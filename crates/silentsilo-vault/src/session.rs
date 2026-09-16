use std::io::Read;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, MAIN_DB};
use silentsilo_crypto::{ContentKek, MasterDek, generate_content_kek, generate_dek, seal, unseal};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::dek_store::{load_dek, save_dek};
use crate::error::VaultError;
use crate::kdf::derive_vault_key;
use crate::kek_store::{load_kek, save_kek};
use crate::vault_file_crypto::{decrypt_vault_bytes, encrypt_vault_bytes};

/// Not `vault.db`, so a release before 1.5.0 never touches it after a
/// downgrade: it would try to open it, then decrypt the snapshot over it
/// with a ciphered WAL still beside it.
const VAULT_DB: &str = "vault.sqlcipher";
/// Where releases before 1.5.0 kept a plaintext working copy.
const LEGACY_VAULT_DB: &str = "vault.db";
/// The working copy's page key, sealed under the DEK.
const VAULT_KEY: &str = "vault.key";
/// The same key sealed under a rotation's new DEK.
const VAULT_KEY_NEXT: &str = "vault.key.next";
const VAULT_DB_ENC: &str = "vault.db.enc";
const VAULT_DB_ENC_BAK: &str = "vault.db.enc.bak";
/// The snapshot re-encrypted under a rotation's new key, written before the
/// keys change hands and moved into place straight after. See
/// [`VaultPaths::db_enc_staged_path`].
const VAULT_DB_ENC_NEXT: &str = "vault.db.enc.next";
const VAULT_SALT: &str = "vault.salt";
const BLOBS_DIR: &str = "blobs";
/// How every plain SQLite file starts. A SQLCipher file starts with its salt.
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
/// The working copy's own bookkeeping. Left out of every snapshot image.
const STATE_TABLE: &str = "working_copy_state";
/// Fingerprint of the last `vault.db.enc` this copy wrote or was built from.
const STATE_SNAPSHOT: &str = "snapshot";
/// Fingerprint of the `vault.db.enc.next` a rotation staged from this copy.
const STATE_STAGED: &str = "staged";
/// Fingerprint of the snapshot a lock wrote, cleared by the next unlock.
const STATE_LOCKED: &str = "locked";

#[derive(Debug, Clone)]
pub struct VaultPaths {
    pub root: PathBuf,
}

impl VaultPaths {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn app_data_dir(&self) -> PathBuf {
        self.root
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.root.clone())
    }

    /// Where the working copy and anything decrypted go while the silo is
    /// open.
    ///
    /// Machine-local, never inside the silo folder: see `workdir` for why
    /// that distinction is the difference between "keep your silo wherever
    /// you like" being an offer and being a trap.
    pub fn work_dir(&self) -> PathBuf {
        crate::workdir::work_dir_for(&self.root)
    }

    /// Creates the scratch directory, since nothing else will: SQLite does
    /// not make parent directories.
    pub fn ensure_work_dir(&self) -> Result<(), VaultError> {
        crate::workdir::create_private_dir(&self.work_dir())?;
        Ok(())
    }

    /// The working copy, ciphered page by page with SQLCipher. Kept across
    /// locks until the snapshot changes or the silo is removed, and only on
    /// this machine.
    pub fn db_path(&self) -> PathBuf {
        self.work_dir().join(VAULT_DB)
    }

    /// The working copy's page key, sealed under the DEK like
    /// `vault.db.enc`. Kept so the next unlock can reuse the copy.
    pub fn db_key_path(&self) -> PathBuf {
        self.work_dir().join(VAULT_KEY)
    }

    /// The page key sealed under a rotation's new DEK, written with
    /// [`Self::db_enc_staged_path`], so a crash after the commit still
    /// adopts the working copy.
    pub fn db_key_staged_path(&self) -> PathBuf {
        self.work_dir().join(VAULT_KEY_NEXT)
    }

    /// The plaintext working copy of releases before 1.5.0, which a crash
    /// may have left. Adopted once on unlock, then removed.
    pub fn legacy_db_path(&self) -> PathBuf {
        self.work_dir().join(LEGACY_VAULT_DB)
    }

    /// Decrypted copies of files the user opened. Wiped when the silo locks.
    pub fn open_scratch_dir(&self) -> PathBuf {
        self.work_dir().join("open")
    }

    /// Durable, encrypted-at-rest artifact. This is what's read on unlock,
    /// backed up locally, and synced to the cloud.
    pub fn db_enc_path(&self) -> PathBuf {
        self.root.join(VAULT_DB_ENC)
    }

    pub fn db_enc_backup_path(&self) -> PathBuf {
        self.root.join(VAULT_DB_ENC_BAK)
    }

    /// Where a rotation writes the snapshot under its new key.
    ///
    /// Rotation commits the keys and then moves this into place. Those are
    /// two filesystem operations, and a machine that dies between them wakes
    /// up with a new key and a snapshot under the old one, which nothing can
    /// read without a working copy, and the shadow backup is under the old
    /// key too. This file is the way back, which is why unlock
    /// knows about it.
    pub fn db_enc_staged_path(&self) -> PathBuf {
        self.root.join(VAULT_DB_ENC_NEXT)
    }

    pub fn salt_path(&self) -> PathBuf {
        self.root.join(VAULT_SALT)
    }

    pub fn blobs_dir(&self) -> PathBuf {
        self.root.join(BLOBS_DIR)
    }

    pub fn blob_path(&self, blob_id: Uuid) -> PathBuf {
        self.blobs_dir().join(format!("{blob_id}.sslo"))
    }

    /// Whether a silo has already been provisioned at this path.
    ///
    /// Asks only about the encrypted snapshot: the working copy lives
    /// elsewhere, so its presence says something about this machine's
    /// session rather than about the folder.
    pub fn exists(&self) -> bool {
        self.db_enc_path().is_file()
    }
}

pub struct VaultSession {
    pub paths: VaultPaths,
    pub conn: Connection,
    pub vault_id: Uuid,
    pub dek: MasterDek,
    /// The key every blob's content key is wrapped under. Shared across the
    /// silo's devices, so a file written on one opens on the others.
    pub kek: ContentKek,
}

impl VaultSession {
    /// First-time setup after POST /devices/register: binds local state to server vault_id.
    pub fn provision(
        root: PathBuf,
        server_vault_id: Uuid,
        device_secret: &str,
    ) -> Result<Self, VaultError> {
        let paths = VaultPaths::new(root.clone());
        if paths.exists() {
            return Err(VaultError::AlreadyExists);
        }

        std::fs::create_dir_all(root.join(BLOBS_DIR))?;

        let salt: [u8; 16] = rand::random();
        crate::workdir::write_private(&paths.salt_path(), &salt)?;

        let vault_key = derive_vault_key(device_secret, &salt)?;
        let dek = generate_dek();
        save_dek(&root, &dek, &vault_key.wrap_key)?;
        let kek = generate_content_kek();
        save_kek(&root, &kek, &dek)?;

        // Nothing a previous silo in this folder left behind is ours. The
        // scratch and cache directories are keyed by path, so without this
        // the open below adopts the old silo's database wholesale: its
        // folders, its files, and password rows sealed with a key this silo
        // does not have.
        crate::workdir::wipe_machine_state(&root);

        let conn = create_working_copy(&paths, &dek)?;

        let session = Self {
            paths,
            conn,
            vault_id: server_vault_id,
            dek,
            kek,
        };
        // Persist an encrypted snapshot immediately, so the silo exists as
        // far as `VaultPaths::exists` is concerned.
        session.backup_locally()?;

        Ok(session)
    }

    /// Sets up local state for a device joining a vault that already
    /// exists. Both the DEK and the `kek` are *given*, never generated
    /// here: minting either would produce a vault nothing in storage
    /// decrypts, or files no other device can open. The database starts
    /// empty and the tree is rebuilt by replay.
    pub fn provision_with_dek(
        root: PathBuf,
        vault_id: Uuid,
        device_secret: &str,
        dek: MasterDek,
        kek: ContentKek,
    ) -> Result<Self, VaultError> {
        let paths = VaultPaths::new(root.clone());
        if paths.exists() {
            return Err(VaultError::AlreadyExists);
        }

        std::fs::create_dir_all(root.join(BLOBS_DIR))?;

        let salt: [u8; 16] = rand::random();
        crate::workdir::write_private(&paths.salt_path(), &salt)?;

        // The device secret is per-device and never leaves it; wrapping the
        // shared DEK under it keeps this device's on-disk envelope in the
        // same shape as one that provisioned locally.
        let vault_key = derive_vault_key(device_secret, &salt)?;
        save_dek(&root, &dek, &vault_key.wrap_key)?;
        save_kek(&root, &kek, &dek)?;

        // Same reason as `provision`: the database has to start empty for
        // the replay to rebuild the tree, and a folder that held a silo
        // before still points at that silo's working copy.
        crate::workdir::wipe_machine_state(&root);

        let conn = create_working_copy(&paths, &dek)?;

        let session = Self {
            paths,
            conn,
            vault_id,
            dek,
            kek,
        };
        session.backup_locally()?;
        Ok(session)
    }

    /// Unlock with the device secret, the bootstrap path that exists only
    /// until a security key is enrolled.
    pub fn open_with_device_secret(root: PathBuf, device_secret: &str) -> Result<Self, VaultError> {
        let paths = VaultPaths::new(root);
        if !paths.exists() {
            return Err(VaultError::NotFound);
        }

        let salt = std::fs::read(paths.salt_path())?;
        if salt.len() != 16 {
            return Err(VaultError::InvalidCredentials);
        }
        let salt: [u8; 16] = salt.try_into().unwrap();

        let vault_key = derive_vault_key(device_secret, &salt)?;
        let dek = load_dek(&paths.root, &vault_key.wrap_key)?;

        let conn = open_database(&paths, &dek)?;

        let vault_id = read_vault_id(&conn).ok_or(VaultError::NotFound)?;
        let kek = load_kek(&paths.root, &dek)?;

        Ok(Self {
            paths,
            conn,
            vault_id,
            dek,
            kek,
        })
    }

    /// Unlock the DEK with a FIDO wrap key and that key's wrapped-DEK blob
    /// (hex), from its row in `keys/fido.json`. An empty blob is refused:
    /// every enrolled key carries its own envelope, and a row without one is
    /// a broken file, not a different format.
    pub fn open_with_fido_wrapped(
        root: PathBuf,
        fido_wrap_key: &[u8; 32],
        wrapped_dek_hex: &str,
    ) -> Result<Self, VaultError> {
        let paths = VaultPaths::new(root);
        if !paths.exists() {
            return Err(VaultError::NotFound);
        }
        if wrapped_dek_hex.is_empty() {
            return Err(VaultError::InvalidCredentials);
        }

        let dek = crate::dek_store::unwrap_dek_hex(wrapped_dek_hex, fido_wrap_key)?;

        let conn = open_database(&paths, &dek)?;

        let vault_id = read_vault_id(&conn).ok_or(VaultError::NotFound)?;
        let kek = load_kek(&paths.root, &dek)?;

        Ok(Self {
            paths,
            conn,
            vault_id,
            dek,
            kek,
        })
    }

    /// Opens an existing vault with a DEK obtained some other way.
    ///
    /// The recovery path uses this: the code produces the DEK directly, with
    /// no credential and no on-disk envelope involved. Everything below the
    /// key is identical either way: the DEK is what decrypts the database,
    /// and where it came from stops mattering once it is in hand.
    pub fn open_with_dek(root: PathBuf, dek: MasterDek) -> Result<Self, VaultError> {
        let paths = VaultPaths::new(root);
        if !paths.exists() {
            return Err(VaultError::NotFound);
        }
        let conn = open_database(&paths, &dek)?;
        let vault_id = read_vault_id(&conn).ok_or(VaultError::NotFound)?;
        let kek = load_kek(&paths.root, &dek)?;
        Ok(Self {
            paths,
            conn,
            vault_id,
            dek,
            kek,
        })
    }

    /// Flush Write-Ahead Log (WAL) to main database file.
    pub fn flush_wal(&self) -> Result<(), VaultError> {
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Rewrites the encrypted copy of the database under a different key,
    /// for rotation: without it the silo opens once more and then never
    /// again once the working copy is gone, because the shadow backup stays
    /// under the old key. Written to one side and moved into place by the
    /// caller, next to the key changeover.
    ///
    /// Also seals the working copy's page key under the new key and records
    /// the staged snapshot's fingerprint, so after the changeover the next
    /// unlock still reuses the working copy.
    pub fn stage_local_backup(&self, dek: &MasterDek, to: &Path) -> Result<(), VaultError> {
        let _ = self.flush_wal();
        if let Some(key) = read_page_key(&self.paths.db_key_path(), &self.dek) {
            save_page_key(&self.paths.db_key_staged_path(), &key, dek)?;
        }
        let image = export_image(&self.conn)?;
        let sealed = encrypt_vault_bytes(&image, to, dek)?;
        record_fingerprint(&self.conn, STATE_STAGED, &sealed)
    }

    /// Seals the current state into `vault.db.enc` and its shadow copy.
    /// Fails inside an open transaction: the export attaches a database.
    pub fn backup_locally(&self) -> Result<(), VaultError> {
        // A rotation committed since this session opened: the snapshot on
        // disk is under the new key, and sealing over it under this one
        // would leave the silo opening under nothing.
        if let Ok(sealed) = std::fs::read(crate::kek_store::kek_path(&self.paths.root))
            && crate::kek_store::unwrap_kek_bytes(&sealed, &self.dek).is_err()
        {
            return Err(VaultError::Crypto(
                "the silo's key changed since this session opened".into(),
            ));
        }
        self.write_snapshot().map(|_| ())
    }

    /// Seals the snapshot, then records its fingerprint in the working copy.
    /// After the image was taken, so the copy holds the snapshot or more.
    fn write_snapshot(&self) -> Result<Fingerprint, VaultError> {
        let _ = self.flush_wal();
        let image = export_image(&self.conn)?;
        let sealed = encrypt_vault_bytes(&image, &self.paths.db_enc_path(), &self.dek)?;
        std::fs::copy(self.paths.db_enc_path(), self.paths.db_enc_backup_path())?;
        record_fingerprint(&self.conn, STATE_SNAPSHOT, &sealed)?;
        Ok(sealed)
    }

    /// Writes the snapshot before lock and marks the working copy as exactly
    /// that snapshot, folded into one file, so the next unlock reuses it as
    /// it stands. The caller drops the `Connection` and then calls
    /// [`wipe_plaintext_working_copy`]. On an error the copy stays unmarked,
    /// and the next unlock treats it as a session that never locked.
    pub fn seal_for_lock(&self) -> Result<(), VaultError> {
        let sealed = self.write_snapshot()?;
        record_fingerprint(&self.conn, STATE_LOCKED, &sealed)?;
        self.flush_wal()
    }
}

/// Removes everything readable this machine wrote for the silo while it was
/// open: opened files and a plaintext copy an earlier release left. The
/// ciphered working copy and its sealed key stay for the next unlock. Call
/// only after the `Connection` is dropped.
///
/// An allowlist rather than a list of what to delete: anything in the
/// scratch directory other than the ciphered copy goes, so a file some later
/// feature writes there cannot survive a lock by being forgotten.
pub fn wipe_plaintext_working_copy(paths: &VaultPaths) {
    crate::workdir::wipe_plaintext(&paths.root);
}

fn verify_integrity(conn: &Connection) -> Result<(), VaultError> {
    let status: Result<String, _> = conn.query_row("PRAGMA quick_check;", [], |row| row.get(0));
    match status {
        Ok(res) if res == "ok" => Ok(()),
        Ok(res) => Err(VaultError::Corrupted(format!(
            "integrity quick_check failed: {res}"
        ))),
        Err(err) => Err(VaultError::Corrupted(format!(
            "integrity check SQL error: {err}"
        ))),
    }
}

/// Reuses the working copy a lock or a crash left, or builds a fresh one from
/// the encrypted snapshot, falling back to the staged snapshot of an
/// interrupted rotation and then to the shadow backup if the primary is
/// missing, tampered, or under a different key.
///
/// Nothing decrypted is written to disk on the way: the snapshot is opened
/// in memory and exported straight into a ciphered working copy.
fn open_database(paths: &VaultPaths, dek: &MasterDek) -> Result<Connection, VaultError> {
    paths.ensure_work_dir()?;

    // A plaintext copy is always the newest: this build removes it before
    // writing a ciphered one, and an older release ignores the ciphered one.
    if is_plain_sqlite(&paths.legacy_db_path())
        && let Some(conn) = adopt_plaintext_working_copy(paths, dek)
    {
        return Ok(conn);
    }
    if !paths.legacy_db_path().exists()
        && paths.db_path().is_file()
        && let Some(conn) = reuse_working_copy(paths, dek)
    {
        return Ok(conn);
    }

    let enc_path = paths.db_enc_path();
    if !enc_path.is_file() {
        return Err(VaultError::NotFound);
    }
    let (image, source) = match decrypt_vault_bytes(&enc_path, dek) {
        Ok(image) => (image, enc_path),
        Err(_) => match adopt_staged_snapshot(paths, dek) {
            Ok(image) => (image, enc_path),
            Err(_) => (read_enc_backup(paths, dek)?, paths.db_enc_backup_path()),
        },
    };

    match write_working_copy(paths, &image, &source, dek) {
        Ok(conn) => Ok(conn),
        Err(err) => {
            if paths.db_enc_backup_path().is_file() {
                let image = read_enc_backup(paths, dek)?;
                write_working_copy(paths, &image, &paths.db_enc_backup_path(), dek)
            } else {
                Err(err)
            }
        }
    }
}

/// Whether a working copy left behind really belongs to the silo now at
/// this path.
///
/// The scratch directory is keyed by path, so a folder that once held
/// another silo can hand this one its predecessor's working copy. Adopting
/// that would re-encrypt the wrong tree over this silo's snapshot before
/// the caller ever gets to compare vault ids. The marker in the folder is
/// the silo's own claim about which vault it is; a folder without one
/// predates nothing that matters here, so it is trusted.
fn working_copy_belongs_here(paths: &VaultPaths, working_copy_vault: Uuid) -> bool {
    match crate::registry::read_marker(&paths.root) {
        Ok(marker) => marker.vault_id == working_copy_vault,
        Err(_) => true,
    }
}

/// Opens the ciphered working copy left on disk, if it still stands for the
/// snapshot beside it.
///
/// It does when a fingerprint it recorded is the fingerprint of
/// `vault.db.enc` as it is now: this copy wrote that snapshot, or was built
/// from it, and has only moved forward since. Anything that replaced the
/// snapshot (a rotation finished elsewhere, a repair, a restored backup, a
/// session of another release, a different folder at this path) changes
/// the fingerprint, and the copy is dropped for a fresh export. So is a copy
/// whose page key this DEK does not open, one another silo left, and one
/// that does not open.
///
/// A copy a lock marked is exactly the snapshot and is used as it stands.
/// One not marked is a session that never locked: it may hold changes the
/// snapshot lacks, so it is checked and the snapshot catches up from it.
fn reuse_working_copy(paths: &VaultPaths, dek: &MasterDek) -> Option<Connection> {
    // A DEK a rotation retired must not write a snapshot over the new one.
    if let Ok(sealed) = std::fs::read(crate::kek_store::kek_path(&paths.root))
        && crate::kek_store::unwrap_kek_bytes(&sealed, dek).is_err()
    {
        return None;
    }
    let key = load_page_key(paths, dek)?;
    let conn = open_ciphered(&paths.db_path(), &key).ok()?;
    // The first read: a wrong key or a damaged page fails here.
    let id = read_vault_id(&conn)?;
    if !working_copy_belongs_here(paths, id) {
        return None;
    }
    let recorded = [
        read_fingerprint(&conn, STATE_SNAPSHOT),
        read_fingerprint(&conn, STATE_STAGED),
    ];
    let stands_for = |fp: Option<Fingerprint>| fp.is_some() && recorded.contains(&fp);
    let current = file_fingerprint(&paths.db_enc_path());
    if !stands_for(current) {
        // A snapshot that no longer opens was damaged rather than replaced,
        // and the shadow copy is what it was.
        if !stands_for(file_fingerprint(&paths.db_enc_backup_path()))
            || decrypt_vault_bytes(&paths.db_enc_path(), dek).is_ok()
        {
            return None;
        }
    }

    if current.is_some() && read_fingerprint(&conn, STATE_LOCKED) == current {
        // Cleared first, so a crash in this session is not taken for a lock.
        // No quick_check: nothing wrote the file since the lock exported
        // every table from it, and SQLCipher checks each page's HMAC on read.
        conn.execute(
            &format!("DELETE FROM {STATE_TABLE} WHERE key = ?1"),
            [STATE_LOCKED],
        )
        .ok()?;
        return Some(conn);
    }

    verify_integrity(&conn).ok()?;
    // Fold the crashed session's WAL into the main file first, so it does
    // not grow across sessions.
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    if let Ok(image) = export_image(&conn) {
        refresh_snapshot(paths, dek, &image, Some(&conn));
    }
    Some(conn)
}

/// The plaintext working copy an earlier release left after a crash.
///
/// Adopted once, as those releases did, then replaced by a ciphered copy:
/// the plaintext files are removed before this returns. `None` leaves the
/// caller to build from the snapshot, which removes them too.
fn adopt_plaintext_working_copy(paths: &VaultPaths, dek: &MasterDek) -> Option<Connection> {
    let image = {
        let conn = Connection::open(paths.legacy_db_path()).ok()?;
        conn.execute_batch("PRAGMA busy_timeout=5000;").ok()?;
        verify_integrity(&conn).ok()?;
        let id = read_vault_id(&conn)?;
        if !working_copy_belongs_here(paths, id) {
            return None;
        }
        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        Zeroizing::new(conn.serialize(MAIN_DB).ok()?.to_vec())
    };
    refresh_snapshot(paths, dek, &image, None);
    // The plaintext copy holds at least the snapshot, refreshed or not.
    write_working_copy(paths, &image, &paths.db_enc_path(), dek).ok()
}

/// Seals a working copy's image as the snapshot and its shadow copy, and
/// records the fingerprint in `conn`, the copy the image came from.
fn refresh_snapshot(paths: &VaultPaths, dek: &MasterDek, image: &[u8], conn: Option<&Connection>) {
    if let Ok(sealed) = encrypt_vault_bytes(image, &paths.db_enc_path(), dek) {
        let _ = std::fs::copy(paths.db_enc_path(), paths.db_enc_backup_path());
        // A snapshot staged by an interrupted rotation is superseded: the
        // working copy postdates it.
        let _ = std::fs::remove_file(paths.db_enc_staged_path());
        if let Some(conn) = conn {
            let _ = record_fingerprint(conn, STATE_SNAPSHOT, &sealed);
        }
    }
}

/// Finishes a rotation that died between the key commit and the rename.
///
/// The symptom is a silo whose snapshot will not open under the key that is
/// now in force. Rotation stages the re-encrypted snapshot next to the old
/// one, commits the keys, then renames; a crash in that gap leaves the
/// staged file holding the only copy anything can read, and the shadow
/// backup is under the old key too, so without this the silo never opens
/// again. Tried before the shadow backup, since the shadow is what a
/// damaged snapshot calls for and this is what a moved key calls for.
///
/// The staged file is promoted rather than merely read: leaving it in place
/// would mean doing this on every unlock, and the shadow copy would stay
/// under a key nothing holds.
fn adopt_staged_snapshot(
    paths: &VaultPaths,
    dek: &MasterDek,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let staged = paths.db_enc_staged_path();
    if !staged.is_file() {
        return Err(VaultError::NotFound);
    }
    let image = decrypt_vault_bytes(&staged, dek)?;
    silentsilo_core::rename_with_retry(&staged, &paths.db_enc_path())?;
    std::fs::copy(paths.db_enc_path(), paths.db_enc_backup_path())?;
    Ok(image)
}

fn read_enc_backup(paths: &VaultPaths, dek: &MasterDek) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let backup = paths.db_enc_backup_path();
    if !backup.is_file() {
        return Err(VaultError::Corrupted("no local backup available".into()));
    }
    decrypt_vault_bytes(&backup, dek)
        .map_err(|_| VaultError::Corrupted("shadow backup failed to decrypt".into()))
}

/// Whether `path` is a plain SQLite file rather than a ciphered one.
fn is_plain_sqlite(path: &Path) -> bool {
    let mut header = [0u8; 16];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut header))
        .is_ok()
        && &header == SQLITE_HEADER
}

/// A working copy page key. Random per working copy, never the DEK.
type PageKey = Zeroizing<[u8; 32]>;

/// The key as SQLCipher takes a raw key: used as is, no passphrase KDF.
fn key_literal(key: &[u8; 32]) -> Zeroizing<String> {
    use std::fmt::Write;
    let mut literal = Zeroizing::new(String::with_capacity(67));
    literal.push_str("x'");
    for byte in key {
        let _ = write!(literal, "{byte:02X}");
    }
    literal.push('\'');
    literal
}

fn save_page_key(path: &Path, key: &[u8; 32], dek: &MasterDek) -> Result<(), VaultError> {
    let sealed = seal(key, dek).map_err(|e| VaultError::Crypto(e.to_string()))?;
    crate::workdir::write_private(path, &sealed)?;
    Ok(())
}

fn read_page_key(path: &Path, dek: &MasterDek) -> Option<PageKey> {
    let data = std::fs::read(path).ok()?;
    let plain = Zeroizing::new(unseal(&data, dek).ok()?);
    if plain.len() != 32 {
        return None;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plain);
    Some(key)
}

/// The page key a surviving working copy was written under, if this DEK
/// opens it. After a committed rotation only the staged one does, and it is
/// moved into place so the next unlock finds it there.
fn load_page_key(paths: &VaultPaths, dek: &MasterDek) -> Option<PageKey> {
    if let Some(key) = read_page_key(&paths.db_key_path(), dek) {
        return Some(key);
    }
    let key = read_page_key(&paths.db_key_staged_path(), dek)?;
    let _ = silentsilo_core::rename_with_retry(&paths.db_key_staged_path(), &paths.db_key_path());
    Some(key)
}

/// Removes the working copy, its journals and its sealed keys.
fn remove_working_copy(paths: &VaultPaths) -> Result<(), VaultError> {
    let mut files = vec![paths.db_key_path(), paths.db_key_staged_path()];
    for db in [paths.db_path(), paths.legacy_db_path()] {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut name = db.as_os_str().to_os_string();
            name.push(suffix);
            files.push(PathBuf::from(name));
        }
    }
    for file in files {
        match std::fs::remove_file(&file) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
    }
    Ok(())
}

/// An empty ciphered working copy under a new page key.
fn create_working_copy(paths: &VaultPaths, dek: &MasterDek) -> Result<Connection, VaultError> {
    paths.ensure_work_dir()?;
    remove_working_copy(paths)?;
    let key: PageKey = Zeroizing::new(rand::random());
    save_page_key(&paths.db_key_path(), &key, dek)?;
    open_ciphered(&paths.db_path(), &key)
}

/// A ciphered working copy holding `image`, a plain SQLite file image,
/// under a new page key, recording the fingerprint of `source`, the sealed
/// file the image came from. The image is exported from memory, so its
/// plaintext never touches the disk.
fn write_working_copy(
    paths: &VaultPaths,
    image: &[u8],
    source: &Path,
    dek: &MasterDek,
) -> Result<Connection, VaultError> {
    paths.ensure_work_dir()?;
    remove_working_copy(paths)?;
    let key: PageKey = Zeroizing::new(rand::random());
    save_page_key(&paths.db_key_path(), &key, dek)?;

    let path = paths.db_path();
    let path_str = path
        .to_str()
        .ok_or_else(|| VaultError::Corrupted("working copy path is not UTF-8".into()))?;
    {
        let mut mem = Connection::open_in_memory()?;
        // A file image in WAL mode says so in bytes 18 and 19, and an
        // in-memory database cannot open a WAL. Legacy mode reads the same.
        let mut header = Zeroizing::new([0u8; 100]);
        let head = image.len().min(100);
        header[..head].copy_from_slice(&image[..head]);
        if head == 100 && header[18] == 2 && header[19] == 2 {
            header[18] = 1;
            header[19] = 1;
        }
        let reader = (&header[..head]).chain(&image[head..]);
        mem.deserialize_read_exact(MAIN_DB, reader, image.len(), false)?;
        mem.execute(
            "ATTACH DATABASE ?1 AS enc KEY ?2",
            rusqlite::params![path_str, key_literal(&key).as_str()],
        )?;
        mem.query_row("SELECT sqlcipher_export('enc')", [], |_| Ok(()))?;
        mem.execute_batch("DETACH DATABASE enc;")?;
    }

    let conn = open_ciphered(&path, &key)?;
    verify_integrity(&conn)?;
    if let Some(fp) = file_fingerprint(source) {
        record_fingerprint(&conn, STATE_SNAPSHOT, &fp)?;
    }
    Ok(conn)
}

/// Opens a ciphered database. The key goes first: nothing may read the file
/// before it is set.
fn open_ciphered(path: &Path, key: &[u8; 32]) -> Result<Connection, VaultError> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "key", key_literal(key).as_str())?;
    // Sorts and temporary tables in memory, never in a plain temp file.
    // A 64 MiB page cache: every page read from disk is decrypted and
    // checked, and at SQLite's 2 MiB default a 10,000-record history took
    // 20 times longer to write.
    conn.execute_batch(
        "PRAGMA temp_store=MEMORY;
         PRAGMA cache_size=-65536;
         PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA busy_timeout=5000;
         PRAGMA foreign_keys=ON;",
    )?;
    Ok(conn)
}

/// The database behind `conn` as a plain SQLite file image, in memory only:
/// the shape `vault.db.enc` has always sealed, so every release reads it.
fn export_image(conn: &Connection) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    conn.execute_batch("ATTACH DATABASE ':memory:' AS plain KEY '';")?;
    let image = conn
        .query_row("SELECT sqlcipher_export('plain')", [], |_| Ok(()))
        .and_then(|()| conn.execute_batch(&format!("DROP TABLE IF EXISTS plain.{STATE_TABLE};")))
        .and_then(|()| conn.serialize(c"plain"))
        .map(|data| Zeroizing::new(data.to_vec()));
    let detached = conn.execute_batch("DETACH DATABASE plain;");
    let image = image?;
    detached?;
    Ok(image)
}

/// BLAKE3 of a sealed snapshot's bytes. It names one snapshot: the
/// envelope's nonce is random, so no other write produces the same bytes.
type Fingerprint = [u8; 32];

fn file_fingerprint(path: &Path) -> Option<Fingerprint> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut file, &mut hasher).ok()?;
    Some(*hasher.finalize().as_bytes())
}

fn record_fingerprint(conn: &Connection, key: &str, fp: &Fingerprint) -> Result<(), VaultError> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {STATE_TABLE} (key TEXT PRIMARY KEY, value BLOB NOT NULL);"
    ))?;
    conn.execute(
        &format!("INSERT OR REPLACE INTO {STATE_TABLE} (key, value) VALUES (?1, ?2)"),
        rusqlite::params![key, &fp[..]],
    )?;
    Ok(())
}

fn read_fingerprint(conn: &Connection, key: &str) -> Option<Fingerprint> {
    conn.query_row(
        &format!("SELECT value FROM {STATE_TABLE} WHERE key = ?1"),
        [key],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .ok()
    .and_then(|v| v.try_into().ok())
}

fn read_vault_id(conn: &Connection) -> Option<Uuid> {
    conn.query_row(
        "SELECT value FROM vault_meta WHERE key = 'vault_id'",
        [],
        |row| {
            let value: String = row.get(0)?;
            Ok(value)
        },
    )
    .ok()
    .and_then(|s| Uuid::parse_str(&s).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// A session opened somewhere throwaway still writes outside it.
    ///
    /// The trial restore builds a whole silo in a temporary directory and
    /// deletes the directory afterwards, which reads as leaving nothing
    /// behind and is not: the working copy lives under the machine's own
    /// scratch base, keyed by path, so the decrypted index survived every
    /// run under a fresh name and nothing ever collected them. Deleting the
    /// folder is not the same act as wiping what this machine wrote for it.
    #[test]
    fn deleting_a_silo_folder_does_not_reach_its_plaintext_copy() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("throwaway");
        let session = VaultSession::provision(root.clone(), Uuid::new_v4(), "secret").unwrap();
        let plaintext = session.paths.db_path();
        drop(session);

        assert!(
            plaintext.is_file(),
            "the test needs a working copy to exist"
        );
        assert!(
            !plaintext.starts_with(&root),
            "the working copy is meant to live outside the silo folder"
        );

        std::fs::remove_dir_all(&root).unwrap();
        assert!(
            plaintext.is_file(),
            "deleting the folder must not be mistaken for cleaning up"
        );

        crate::workdir::wipe_machine_state(&root);
        assert!(!plaintext.exists(), "the plaintext copy outlived the silo");
    }

    /// The gap a rotation cannot close by itself.
    ///
    /// Committing the keys and moving the snapshot under them are two
    /// filesystem operations. A machine that dies between them wakes up with
    /// the new key in force and `vault.db.enc` still under the old one, and
    /// the shadow backup is under the old key too, so both fallbacks fail
    /// and the silo never opens again. The staged file holds the only bytes
    /// anything can read, and unlock has to know that.
    #[test]
    fn a_rotation_that_died_before_the_rename_still_opens() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let vault_id = Uuid::new_v4();
        let secret = "test_device_secret_123";

        // `provision` writes no schema; the vfs crate owns that. The table is
        // made by hand here for the same reason the shadow-backup test makes
        // it: what is being checked is which bytes unlock reads back.
        let session = VaultSession::provision(root.clone(), vault_id, secret).unwrap();
        session
            .conn
            .execute_batch(&format!(
                "CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT);
                 INSERT INTO vault_meta VALUES ('vault_id', '{vault_id}');
                 INSERT INTO vault_meta VALUES ('marker', 'survived');"
            ))
            .unwrap();

        // What rotation does, stopping exactly where the power cut would:
        // stage the key and the snapshot, commit the key, never rename.
        let new_dek = silentsilo_crypto::generate_dek();
        let paths = session.paths.clone();
        crate::rotation::stage_rotation(&root, &new_dek, &session.kek, &session.dek).unwrap();
        session
            .stage_local_backup(&new_dek, &paths.db_enc_staged_path())
            .unwrap();
        crate::rotation::commit_rotation(&root).unwrap();
        drop(session);
        crate::workdir::wipe_work_dir(&root);
        assert!(paths.db_enc_staged_path().is_file());

        let reopened = VaultSession::open_with_dek(root.clone(), new_dek.clone()).unwrap();

        let marker: String = reopened
            .conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'marker'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(marker, "survived");
        assert!(
            !paths.db_enc_staged_path().exists(),
            "the staged snapshot must be promoted, not read again on every unlock"
        );

        // And it stays open afterwards, which is what promoting buys: the
        // primary and the shadow are both under the key now in force.
        drop(reopened);
        crate::workdir::wipe_work_dir(&root);
        assert!(VaultSession::open_with_dek(root, new_dek).is_ok());
    }

    #[test]
    fn test_database_integrity_and_shadow_backup() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let vault_id = Uuid::new_v4();
        let secret = "test_device_secret_123";

        let session = VaultSession::provision(root.clone(), vault_id, secret).unwrap();
        session
            .conn
            .execute_batch("CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT);")
            .unwrap();
        session
            .conn
            .execute_batch(&format!(
                "INSERT INTO vault_meta VALUES ('vault_id', '{vault_id}');"
            ))
            .unwrap();
        session.backup_locally().unwrap();

        assert!(session.paths.db_enc_backup_path().exists());

        drop(session);
        // No copy kept, so the reopen genuinely exercises the snapshot path.
        crate::workdir::wipe_work_dir(&root);

        // Opens: vault.db.enc decrypts into the working copy.
        let session2 = VaultSession::open_with_device_secret(root.clone(), secret).unwrap();
        assert_eq!(session2.vault_id, vault_id);
        drop(session2);
        crate::workdir::wipe_work_dir(&root);

        // Corrupt the encrypted-at-rest snapshot.
        std::fs::write(root.join(VAULT_DB_ENC), b"corrupted ciphertext junk").unwrap();

        // Re-open: should detect the decrypt failure and restore from the
        // encrypted shadow backup instead.
        let session3 = VaultSession::open_with_device_secret(root.clone(), secret).unwrap();
        assert_eq!(session3.vault_id, vault_id);
    }

    #[test]
    fn a_crash_keeps_the_changes_made_since_the_last_snapshot() {
        // The working copy is the only place a session's changes live until
        // something snapshots it. Unlock used to decrypt the older snapshot
        // over it, so a crash cost everything since the last lock even
        // though the bytes were still on disk.
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let vault_id = Uuid::new_v4();
        let secret = "test_device_secret_123";

        let session = VaultSession::provision(root.clone(), vault_id, secret).unwrap();
        session
            .conn
            .execute_batch(&format!(
                "CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT);
                 INSERT INTO vault_meta VALUES ('vault_id', '{vault_id}');
                 INSERT INTO vault_meta VALUES ('marker', 'early');"
            ))
            .unwrap();
        session.backup_locally().unwrap();
        session
            .conn
            .execute(
                "UPDATE vault_meta SET value = 'late' WHERE key = 'marker'",
                [],
            )
            .unwrap();
        // The crash: no lock, no wipe, no fresh snapshot.
        drop(session);

        let reopened = VaultSession::open_with_device_secret(root.clone(), secret).unwrap();
        let marker: String = reopened
            .conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'marker'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(marker, "late", "the crashed session's changes were lost");

        // Adoption also refreshed the snapshot, so even losing the copy right
        // now would carry the late change forward.
        drop(reopened);
        crate::workdir::wipe_work_dir(&root);
        let from_snapshot = VaultSession::open_with_device_secret(root, secret).unwrap();
        let marker: String = from_snapshot
            .conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'marker'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(marker, "late");
    }

    #[test]
    fn a_working_copy_left_by_another_silo_is_not_adopted_over_this_one() {
        // The scratch directory is keyed by path, so a folder that once held
        // another silo can hand this one its predecessor's working copy.
        // Adopting it would re-encrypt the wrong tree over this silo's
        // snapshot before any caller compares vault ids.
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let secret = "test_device_secret_123";
        // One DEK for both, so the stranger's page key opens and only the
        // marker tells the two apart.
        let dek = generate_dek();
        let kek = generate_content_kek();

        // A stranger's working copy, sitting where this path's scratch is.
        let stranger = Uuid::new_v4();
        let stranger_session = VaultSession::provision_with_dek(
            root.clone(),
            stranger,
            secret,
            dek.clone(),
            kek.clone(),
        )
        .unwrap();
        stranger_session
            .conn
            .execute_batch(&format!(
                "CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT);
                 INSERT INTO vault_meta VALUES ('vault_id', '{stranger}');
                 INSERT INTO vault_meta VALUES ('marker', 'the stranger');"
            ))
            .unwrap();
        stranger_session.flush_wal().unwrap();
        drop(stranger_session);

        // This silo takes the folder over, keeping the stranger's scratch in
        // place: what a moved or copied silo folder produces.
        let paths = VaultPaths::new(root.clone());
        let kept = std::fs::read(paths.db_path()).unwrap();
        let kept_key = std::fs::read(paths.db_key_path()).unwrap();
        for name in ["vault.db.enc", "vault.db.enc.bak", "silo.json"] {
            let _ = std::fs::remove_file(root.join(name));
        }
        let ours = Uuid::new_v4();
        let session =
            VaultSession::provision_with_dek(root.clone(), ours, secret, dek, kek).unwrap();
        session
            .conn
            .execute_batch(&format!(
                "CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT);
                 INSERT INTO vault_meta VALUES ('vault_id', '{ours}');
                 INSERT INTO vault_meta VALUES ('marker', 'ours');"
            ))
            .unwrap();
        session.backup_locally().unwrap();
        drop(session);
        crate::registry::write_marker(&root, ours).unwrap();
        let snapshot_before = std::fs::read(paths.db_enc_path()).unwrap();
        // The stranger's copy is put back, as a crash would leave it.
        remove_working_copy(&paths).unwrap();
        std::fs::write(paths.db_path(), kept).unwrap();
        std::fs::write(paths.db_key_path(), kept_key).unwrap();
        assert!(
            read_page_key(&paths.db_key_path(), &load_dek_for(&root, secret)).is_some(),
            "the stranger's copy must open, or the marker is never consulted"
        );

        let reopened = VaultSession::open_with_device_secret(root, secret).unwrap();

        assert_eq!(reopened.vault_id, ours, "the stranger's tree was adopted");
        assert_eq!(
            std::fs::read(paths.db_enc_path()).unwrap(),
            snapshot_before,
            "this silo's snapshot was overwritten from another silo's copy"
        );
    }

    fn load_dek_for(root: &Path, secret: &str) -> MasterDek {
        let salt: [u8; 16] = std::fs::read(root.join(VAULT_SALT))
            .unwrap()
            .try_into()
            .unwrap();
        let key = derive_vault_key(secret, &salt).unwrap();
        load_dek(root, &key.wrap_key).unwrap()
    }

    #[test]
    fn a_corrupt_working_copy_falls_back_to_the_snapshot() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let vault_id = Uuid::new_v4();
        let secret = "test_device_secret_123";

        let session = VaultSession::provision(root.clone(), vault_id, secret).unwrap();
        session
            .conn
            .execute_batch(&format!(
                "CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT);
                 INSERT INTO vault_meta VALUES ('vault_id', '{vault_id}');"
            ))
            .unwrap();
        session.backup_locally().unwrap();
        let plain = session.paths.db_path();
        drop(session);

        std::fs::write(&plain, b"not a database").unwrap();

        let reopened = VaultSession::open_with_device_secret(root, secret).unwrap();
        assert_eq!(reopened.vault_id, vault_id);
    }

    /// A new silo at a path a previous silo used must not inherit its
    /// index: the scratch directory is keyed by path, and after a crash the
    /// old working copy is still there for `provision` to adopt, rows
    /// sealed with a key the new silo does not have.
    #[test]
    fn provisioning_over_a_previous_silos_leftovers_starts_clean() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("Personal");
        std::fs::create_dir_all(&root).unwrap();

        // The first silo, left as an abrupt shutdown would leave it: the
        // working copy still on disk, never wiped by a lock.
        let first = VaultSession::provision(root.clone(), Uuid::new_v4(), "first-secret").unwrap();
        first
            .conn
            .execute_batch(
                "CREATE TABLE passwords (id TEXT PRIMARY KEY, data TEXT NOT NULL);
                 INSERT INTO passwords VALUES ('old', 'sealed-with-the-first-key');",
            )
            .unwrap();
        first.flush_wal().unwrap();
        let working_copy = first.paths.db_path();
        drop(first);
        assert!(working_copy.is_file(), "the crash this test models");

        // The user deletes the silo and makes a new one in the same folder.
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        let second =
            VaultSession::provision(root.clone(), Uuid::new_v4(), "second-secret").unwrap();

        let inherited: i64 = second
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'passwords'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            inherited, 0,
            "the new silo inherited the deleted silo's tables"
        );
    }

    /// The other half of what a path hands to its next tenant: a record of
    /// blobs that belonged to a silo which no longer exists. Left in place,
    /// the new silo believes it already holds content it has never seen, and
    /// that the bucket already has content that was never uploaded.
    #[test]
    fn provisioning_does_not_inherit_a_previous_silos_blob_bookkeeping() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("Personal");
        std::fs::create_dir_all(&root).unwrap();

        let first = VaultSession::provision(root.clone(), Uuid::new_v4(), "first-secret").unwrap();
        crate::cache_store::record_blob_present(&root, Uuid::new_v4(), 4096, true).unwrap();
        assert!(crate::workdir::cache_dir_for(&root).exists());
        drop(first);

        std::fs::remove_dir_all(&root).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        VaultSession::provision(root.clone(), Uuid::new_v4(), "second-secret").unwrap();

        assert!(
            crate::cache_store::list_local_blob_ids(&root).is_empty(),
            "the new silo inherited blobs belonging to the deleted one"
        );
    }

    #[test]
    fn plaintext_working_copy_is_never_left_behind_by_provision() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let session = VaultSession::provision(root.clone(), Uuid::new_v4(), "secret").unwrap();
        assert!(session.paths.db_enc_path().is_file());
    }

    #[test]
    fn a_joining_device_keeps_the_dek_it_was_given() {
        // The whole point of the join path: generating a fresh key here
        // would produce a second, unrelated vault sharing an id, and nothing
        // already in the bucket would decrypt.
        let dir = tempdir().unwrap();
        let vault_id = Uuid::new_v4();
        let shared = generate_dek();

        let session = VaultSession::provision_with_dek(
            dir.path().to_path_buf(),
            vault_id,
            "a-device-secret",
            shared.clone(),
            generate_content_kek(),
        )
        .unwrap();

        assert_eq!(session.dek.as_bytes(), shared.as_bytes());
        assert_eq!(session.vault_id, vault_id);
    }

    #[test]
    fn a_joined_vault_reopens_with_the_same_key() {
        // The on-disk envelope is wrapped under this device's own secret,
        // so re-opening locally has to land on the shared DEK again.
        let dir = tempdir().unwrap();
        let shared = generate_dek();
        let session = VaultSession::provision_with_dek(
            dir.path().to_path_buf(),
            Uuid::new_v4(),
            "a-device-secret",
            shared.clone(),
            generate_content_kek(),
        )
        .unwrap();
        session
            .conn
            .execute_batch("CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT);")
            .unwrap();
        session
            .conn
            .execute(
                "INSERT INTO vault_meta (key, value) VALUES ('vault_id', ?1)",
                [session.vault_id.to_string()],
            )
            .unwrap();
        session.backup_locally().unwrap();
        drop(session);

        let reopened =
            VaultSession::open_with_device_secret(dir.path().to_path_buf(), "a-device-secret")
                .unwrap();
        assert_eq!(reopened.dek.as_bytes(), shared.as_bytes());
    }

    #[test]
    fn joining_refuses_to_overwrite_an_existing_vault() {
        let dir = tempdir().unwrap();
        VaultSession::provision_with_dek(
            dir.path().to_path_buf(),
            Uuid::new_v4(),
            "secret",
            generate_dek(),
            generate_content_kek(),
        )
        .unwrap();

        let second = VaultSession::provision_with_dek(
            dir.path().to_path_buf(),
            Uuid::new_v4(),
            "secret",
            generate_dek(),
            generate_content_kek(),
        );
        assert!(matches!(second, Err(VaultError::AlreadyExists)));
    }

    #[test]
    fn nothing_decrypted_is_written_into_the_silo_folder() {
        // The guarantee that makes "keep your silo wherever you like" safe.
        // If this fails, a silo in a synced folder uploads its index in the
        // clear, the one outcome the whole design exists to prevent.
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let session =
            VaultSession::provision(root.clone(), Uuid::new_v4(), "a-device-secret").unwrap();
        session
            .conn
            .execute_batch("CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT);")
            .unwrap();
        session.backup_locally().unwrap();

        let names: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();

        for name in &names {
            assert!(
                !name.starts_with("vault.db") || name.ends_with(".enc") || name.ends_with(".bak"),
                "{name} is a plaintext database artefact inside the silo folder"
            );
            assert_ne!(
                name, "cache.db",
                "cache.db lists blob sizes and belongs on the machine"
            );
        }
        assert!(
            names.iter().any(|n| n == "vault.db.enc"),
            "the encrypted snapshot must still be in the silo folder, or the silo is not portable"
        );
    }

    /// Every file in the working directory, as bytes.
    fn work_files(paths: &VaultPaths) -> Vec<(PathBuf, Vec<u8>)> {
        std::fs::read_dir(paths.work_dir())
            .unwrap()
            .flatten()
            .filter(|e| e.path().is_file())
            .map(|e| (e.path(), std::fs::read(e.path()).unwrap()))
            .collect()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn marker(conn: &Connection) -> String {
        conn.query_row(
            "SELECT value FROM vault_meta WHERE key = 'marker'",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn silo_with_marker(root: &Path, secret: &str, marker: &str) -> VaultSession {
        let session = VaultSession::provision(root.to_path_buf(), Uuid::new_v4(), secret).unwrap();
        let id = session.vault_id;
        session
            .conn
            .execute_batch(&format!(
                "CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT);
                 INSERT INTO vault_meta VALUES ('vault_id', '{id}');
                 INSERT INTO vault_meta VALUES ('marker', '{marker}');"
            ))
            .unwrap();
        session
    }

    /// The reason for SQLCipher: a crash, a kill or a power cut leaves the
    /// working copy and its WAL on disk, and neither may be readable.
    #[test]
    fn the_working_copy_and_its_wal_hold_no_plaintext() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let name = "Quarterly-Salaries-Marker.xlsx";
        let session = silo_with_marker(&root, "secret", "early");
        session.backup_locally().unwrap();
        // Written after the checkpoint, so it sits in the WAL.
        session
            .conn
            .execute("INSERT INTO vault_meta VALUES ('file', ?1)", [name])
            .unwrap();
        let paths = session.paths.clone();

        let files = work_files(&paths);
        assert!(
            files
                .iter()
                .any(|(p, b)| p.ends_with("vault.sqlcipher-wal") && !b.is_empty()),
            "the test needs a WAL holding the write"
        );
        for (path, bytes) in &files {
            let shown = path.display();
            assert!(!contains(bytes, name.as_bytes()), "{shown} holds the name");
            assert!(!contains(bytes, b"vault_meta"), "{shown} holds the schema");
            assert!(!bytes.starts_with(SQLITE_HEADER), "{shown} is plain SQLite");
        }

        // The snapshot still carries it, sealed.
        session.backup_locally().unwrap();
        drop(session);
        for (path, bytes) in work_files(&paths) {
            let shown = path.display();
            assert!(!contains(&bytes, name.as_bytes()), "{shown} holds the name");
        }
        wipe_plaintext_working_copy(&paths);
        let reopened = VaultSession::open_with_device_secret(root, "secret").unwrap();
        let back: String = reopened
            .conn
            .query_row("SELECT value FROM vault_meta WHERE key = 'file'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(back, name);
    }

    /// A leftover opens only through the DEK. A wrong key must neither read
    /// it nor destroy it, or a failed unlock would cost the crashed
    /// session's changes.
    #[test]
    fn a_leftover_working_copy_needs_the_dek() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let session = silo_with_marker(&root, "secret", "early");
        session.backup_locally().unwrap();
        session
            .conn
            .execute(
                "UPDATE vault_meta SET value = 'late' WHERE key = 'marker'",
                [],
            )
            .unwrap();
        let (paths, dek) = (session.paths.clone(), session.dek.clone());
        drop(session);

        let plain = Connection::open(paths.db_path()).unwrap();
        assert!(
            plain
                .query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r
                    .get::<_, i64>(0))
                .is_err(),
            "opened without a key"
        );
        drop(plain);
        assert!(open_ciphered(&paths.db_path(), &[7u8; 32]).is_err());
        assert!(VaultSession::open_with_dek(root.clone(), generate_dek()).is_err());
        assert!(read_page_key(&paths.db_key_path(), &generate_dek()).is_none());

        let reopened = VaultSession::open_with_dek(root, dek).unwrap();
        assert_eq!(marker(&reopened.conn), "late");
    }

    /// A release before SQLCipher left its working copy in the clear after
    /// a crash. It is adopted once, then replaced by a ciphered copy.
    #[test]
    fn a_plaintext_leftover_from_an_earlier_release_is_adopted_then_ciphered() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let session = silo_with_marker(&root, "secret", "early");
        session.backup_locally().unwrap();
        let (paths, vault_id) = (session.paths.clone(), session.vault_id);
        drop(session);
        remove_working_copy(&paths).unwrap();

        // What 1.4.0 leaves: a plain database with the change in its WAL.
        let legacy = paths.legacy_db_path();
        let wal = PathBuf::from(format!("{}-wal", legacy.display()));
        let old = Connection::open(&legacy).unwrap();
        old.execute_batch(&format!(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT);
             INSERT INTO vault_meta VALUES ('vault_id', '{vault_id}');
             INSERT INTO vault_meta VALUES ('marker', 'written by 1.4.0');"
        ))
        .unwrap();
        // Copied while open: closing would checkpoint and delete the WAL.
        let db_bytes = std::fs::read(&legacy).unwrap();
        let wal_bytes = std::fs::read(&wal).unwrap();
        drop(old);
        assert!(contains(&wal_bytes, b"written by 1.4.0"));
        std::fs::write(&legacy, db_bytes).unwrap();
        std::fs::write(&wal, wal_bytes).unwrap();
        assert!(is_plain_sqlite(&legacy));

        let reopened = VaultSession::open_with_device_secret(root.clone(), "secret").unwrap();
        assert_eq!(marker(&reopened.conn), "written by 1.4.0");
        for (path, bytes) in work_files(&paths) {
            let shown = path.display();
            assert!(!contains(&bytes, b"written by 1.4.0"), "{shown} is plain");
        }
        assert!(
            !legacy.exists() && !wal.exists(),
            "the plaintext files stayed"
        );
        assert!(paths.db_path().is_file());

        // The snapshot caught up, so it holds the change without the copy.
        drop(reopened);
        crate::workdir::wipe_work_dir(&root);
        let again = VaultSession::open_with_device_secret(root, "secret").unwrap();
        assert_eq!(marker(&again.conn), "written by 1.4.0");
    }

    /// A crash after a rotation committed: the page key was sealed under the
    /// old DEK, and only the new one opens the silo now.
    #[test]
    fn a_crash_after_a_rotation_keeps_the_changes() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let session = silo_with_marker(&root, "secret", "before");
        session.backup_locally().unwrap();
        let paths = session.paths.clone();

        // The rotation as the desktop commits it.
        let new_dek = generate_dek();
        crate::rotation::stage_rotation(&root, &new_dek, &session.kek, &session.dek).unwrap();
        session
            .stage_local_backup(&new_dek, &paths.db_enc_staged_path())
            .unwrap();
        crate::rotation::commit_rotation(&root).unwrap();
        silentsilo_core::rename_with_retry(&paths.db_enc_staged_path(), &paths.db_enc_path())
            .unwrap();
        std::fs::copy(paths.db_enc_path(), paths.db_enc_backup_path()).unwrap();

        // Written after the commit, then the crash.
        session
            .conn
            .execute(
                "UPDATE vault_meta SET value = 'after' WHERE key = 'marker'",
                [],
            )
            .unwrap();
        let old_dek = session.dek.clone();
        drop(session);

        let snapshot = std::fs::read(paths.db_enc_path()).unwrap();
        assert!(VaultSession::open_with_dek(root.clone(), old_dek).is_err());
        assert_eq!(
            std::fs::read(paths.db_enc_path()).unwrap(),
            snapshot,
            "a retired key wrote the snapshot"
        );
        let reopened = VaultSession::open_with_dek(root.clone(), new_dek.clone()).unwrap();
        assert_eq!(marker(&reopened.conn), "after");
        assert!(
            !paths.db_key_staged_path().exists(),
            "the staged key is promoted"
        );

        // A second crash finds the key in place.
        drop(reopened);
        let again = VaultSession::open_with_dek(root, new_dek).unwrap();
        assert_eq!(marker(&again.conn), "after");
    }

    /// The desktop locks every silo right after a rotation commits, and the
    /// lock snapshots with the session's DEK, which is the old one. Sealing
    /// under it would put `vault.db.enc` and its shadow copy under a key
    /// nothing opens any more.
    #[test]
    fn a_session_whose_key_was_rotated_away_does_not_overwrite_the_snapshot() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let session = silo_with_marker(&root, "secret", "kept");
        session.backup_locally().unwrap();
        let paths = session.paths.clone();

        let new_dek = generate_dek();
        crate::rotation::stage_rotation(&root, &new_dek, &session.kek, &session.dek).unwrap();
        session
            .stage_local_backup(&new_dek, &paths.db_enc_staged_path())
            .unwrap();
        crate::rotation::commit_rotation(&root).unwrap();
        silentsilo_core::rename_with_retry(&paths.db_enc_staged_path(), &paths.db_enc_path())
            .unwrap();
        std::fs::copy(paths.db_enc_path(), paths.db_enc_backup_path()).unwrap();

        // The lock.
        assert!(session.backup_locally().is_err());
        drop(session);
        wipe_plaintext_working_copy(&paths);

        let reopened = VaultSession::open_with_dek(root, new_dek).unwrap();
        assert_eq!(marker(&reopened.conn), "kept");
    }

    /// Snapshots, drops the connection and clears plaintext, as a lock does.
    fn lock(session: VaultSession) -> VaultPaths {
        session.seal_for_lock().unwrap();
        let paths = session.paths.clone();
        drop(session);
        wipe_plaintext_working_copy(&paths);
        paths
    }

    fn set_marker(session: &VaultSession, value: &str) {
        session
            .conn
            .execute(
                "UPDATE vault_meta SET value = ?1 WHERE key = 'marker'",
                [value],
            )
            .unwrap();
    }

    /// A snapshot image an in-memory database opens: not marked as WAL.
    fn plain_image(image: &[u8]) -> Vec<u8> {
        let mut image = image.to_vec();
        if image.len() >= 100 && image[18] == 2 {
            image[18] = 1;
            image[19] = 1;
        }
        image
    }

    /// The sealed page key changes whenever a working copy is exported fresh.
    fn page_key_bytes(paths: &VaultPaths) -> Vec<u8> {
        std::fs::read(paths.db_key_path()).unwrap()
    }

    /// After a lock only ciphertext is left: the copy in one file, its sealed
    /// key, nothing opened, nothing plain.
    #[test]
    fn a_lock_leaves_only_the_ciphered_copy_and_its_key() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let name = "Locked-Silo-Marker-Payroll.xlsx";
        let session = silo_with_marker(&root, "secret", "early");
        session
            .conn
            .execute("INSERT INTO vault_meta VALUES ('file', ?1)", [name])
            .unwrap();
        let opened = session.paths.open_scratch_dir();
        std::fs::create_dir_all(&opened).unwrap();
        std::fs::write(opened.join(name), name).unwrap();
        crate::workdir::seal_readonly(&opened.join(name));
        std::fs::write(session.paths.legacy_db_path(), name).unwrap();

        let paths = lock(session);

        let mut names: Vec<String> = std::fs::read_dir(paths.work_dir())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        assert_eq!(names, ["vault.key", "vault.sqlcipher"]);
        for (path, bytes) in work_files(&paths) {
            let shown = path.display();
            assert!(!contains(&bytes, name.as_bytes()), "{shown} holds the name");
            assert!(!contains(&bytes, b"vault_meta"), "{shown} holds the schema");
            assert!(!bytes.starts_with(SQLITE_HEADER), "{shown} is plain SQLite");
        }
    }

    /// The point of keeping the copy: an unlock after a lock opens it as it
    /// stands, with no export and no new snapshot.
    #[test]
    fn an_unlock_after_a_lock_reuses_the_copy() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let session = silo_with_marker(&root, "secret", "kept");
        let paths = lock(session);
        let key = page_key_bytes(&paths);
        let snapshot = std::fs::read(paths.db_enc_path()).unwrap();

        let mut snapshot = snapshot;
        for round in 0..3 {
            let session = VaultSession::open_with_device_secret(root.clone(), "secret").unwrap();
            assert_eq!(marker(&session.conn), "kept");
            assert_eq!(page_key_bytes(&paths), key, "round {round} exported afresh");
            assert_eq!(std::fs::read(paths.db_enc_path()).unwrap(), snapshot);
            lock(session);
            assert!(!paths.work_dir().join("vault.sqlcipher-wal").exists());
            // Each lock writes a new snapshot, which the copy then stands for.
            snapshot = std::fs::read(paths.db_enc_path()).unwrap();
        }
        // The copy was never replaced, and neither was its key.
        assert_eq!(page_key_bytes(&paths), key);
        let reopened = VaultSession::open_with_device_secret(root, "secret").unwrap();
        assert_eq!(marker(&reopened.conn), "kept");
        assert_eq!(page_key_bytes(&paths), key);
    }

    /// A snapshot replaced by anything but this copy: an older generation put
    /// back, the same state sealed again (a repair, another release), a
    /// rotation. The unlock shows the snapshot, never the stale copy.
    #[test]
    fn a_snapshot_replaced_elsewhere_is_exported_afresh() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let session = silo_with_marker(&root, "secret", "one");
        let dek = session.dek.clone();
        let paths = lock(session);
        let first = std::fs::read(paths.db_enc_path()).unwrap();

        let session = VaultSession::open_with_dek(root.clone(), dek.clone()).unwrap();
        set_marker(&session, "two");
        lock(session);

        // An older snapshot put back, over the shadow copy too.
        std::fs::write(paths.db_enc_path(), &first).unwrap();
        std::fs::write(paths.db_enc_backup_path(), &first).unwrap();
        let key = page_key_bytes(&paths);
        let session = VaultSession::open_with_dek(root.clone(), dek.clone()).unwrap();
        assert_eq!(marker(&session.conn), "one", "the stale copy was reused");
        assert_ne!(page_key_bytes(&paths), key);
        lock(session);

        // The same state sealed again, as a repair or another release does.
        let image = decrypt_vault_bytes(&paths.db_enc_path(), &dek).unwrap();
        encrypt_vault_bytes(&image, &paths.db_enc_path(), &dek).unwrap();
        let key = page_key_bytes(&paths);
        let session = VaultSession::open_with_dek(root.clone(), dek.clone()).unwrap();
        assert_eq!(marker(&session.conn), "one");
        assert_ne!(
            page_key_bytes(&paths),
            key,
            "a resealed snapshot was not noticed"
        );
        set_marker(&session, "three");
        lock(session);

        // A rotation finished without this copy: the snapshot under the new
        // key holds something else.
        let new_dek = generate_dek();
        let kek = crate::kek_store::load_kek(&root, &dek).unwrap();
        crate::rotation::stage_rotation(&root, &new_dek, &kek, &dek).unwrap();
        crate::rotation::commit_rotation(&root).unwrap();
        let rotated = {
            let mut mem = Connection::open_in_memory().unwrap();
            let image = plain_image(&decrypt_vault_bytes(&paths.db_enc_path(), &dek).unwrap());
            mem.deserialize_read_exact(MAIN_DB, &image[..], image.len(), false)
                .unwrap();
            mem.execute(
                "UPDATE vault_meta SET value = 'rotated' WHERE key = 'marker'",
                [],
            )
            .unwrap();
            Zeroizing::new(mem.serialize(MAIN_DB).unwrap().to_vec())
        };
        encrypt_vault_bytes(&rotated, &paths.db_enc_path(), &new_dek).unwrap();
        std::fs::copy(paths.db_enc_path(), paths.db_enc_backup_path()).unwrap();
        let session = VaultSession::open_with_dek(root, new_dek).unwrap();
        assert_eq!(marker(&session.conn), "rotated");
    }

    /// A damaged snapshot is not a replaced one: the copy still stands for
    /// the shadow copy and keeps its changes. A shadow copy of another
    /// generation does not count.
    #[test]
    fn a_damaged_snapshot_keeps_the_copy_only_if_the_shadow_matches() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let session = silo_with_marker(&root, "secret", "one");
        let dek = session.dek.clone();
        let paths = lock(session);
        let older_shadow = std::fs::read(paths.db_enc_backup_path()).unwrap();

        let session = VaultSession::open_with_dek(root.clone(), dek.clone()).unwrap();
        set_marker(&session, "two");
        session.backup_locally().unwrap();
        set_marker(&session, "unsaved");
        drop(session);
        std::fs::write(paths.db_enc_path(), b"damaged").unwrap();
        let reopened = VaultSession::open_with_dek(root.clone(), dek.clone()).unwrap();
        assert_eq!(marker(&reopened.conn), "unsaved");
        drop(reopened);

        std::fs::write(paths.db_enc_path(), b"damaged").unwrap();
        std::fs::write(paths.db_enc_backup_path(), older_shadow).unwrap();
        let reopened = VaultSession::open_with_dek(root, dek).unwrap();
        assert_eq!(marker(&reopened.conn), "one");
    }

    /// A session opened from a kept copy that then crashes still keeps its
    /// changes: the unlock cleared the lock's mark.
    #[test]
    fn a_crash_after_reusing_the_copy_keeps_the_changes() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let session = silo_with_marker(&root, "secret", "locked");
        let paths = lock(session);

        let session = VaultSession::open_with_device_secret(root.clone(), "secret").unwrap();
        set_marker(&session, "after the unlock");
        drop(session);

        let reopened = VaultSession::open_with_device_secret(root.clone(), "secret").unwrap();
        assert_eq!(marker(&reopened.conn), "after the unlock");
        drop(reopened);
        // Adoption refreshed the snapshot.
        crate::workdir::wipe_work_dir(&paths.root);
        let from_snapshot = VaultSession::open_with_device_secret(root, "secret").unwrap();
        assert_eq!(marker(&from_snapshot.conn), "after the unlock");
    }

    /// A kept copy opens only through the DEK, and a failed unlock leaves it
    /// as it was.
    #[test]
    fn a_kept_copy_needs_the_dek() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let session = silo_with_marker(&root, "secret", "kept");
        let dek = session.dek.clone();
        let paths = lock(session);
        let copy = std::fs::read(paths.db_path()).unwrap();
        let key = page_key_bytes(&paths);

        assert!(VaultSession::open_with_dek(root.clone(), generate_dek()).is_err());
        assert!(VaultSession::open_with_device_secret(root.clone(), "wrong").is_err());
        assert!(read_page_key(&paths.db_key_path(), &generate_dek()).is_none());
        assert_eq!(std::fs::read(paths.db_path()).unwrap(), copy);
        assert_eq!(page_key_bytes(&paths), key);

        let reopened = VaultSession::open_with_dek(root, dek).unwrap();
        assert_eq!(marker(&reopened.conn), "kept");
        assert_eq!(page_key_bytes(&paths), key);
    }

    /// The copy's bookkeeping never reaches a snapshot, which every release
    /// reads.
    #[test]
    fn the_snapshot_image_carries_no_working_copy_state() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let session = silo_with_marker(&root, "secret", "one");
        let dek = session.dek.clone();
        let paths = lock(session);
        let session = VaultSession::open_with_dek(root, dek.clone()).unwrap();
        assert!(read_fingerprint(&session.conn, STATE_SNAPSHOT).is_some());
        lock(session);

        let image = plain_image(&decrypt_vault_bytes(&paths.db_enc_path(), &dek).unwrap());
        let mut mem = Connection::open_in_memory().unwrap();
        mem.deserialize_read_exact(MAIN_DB, &image[..], image.len(), false)
            .unwrap();
        let tables: i64 = mem
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
                [STATE_TABLE],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0);
    }
}
