//! Folders on this computer that the silo keeps a copy of: scanned at
//! unlock, imported one way, never mirrored. Not a live watcher (fights
//! auto-lock and Windows recursive watches), not two-way sync (the app must
//! not write into folders it does not own), and not a mirror (a file
//! deleted from the folder stays in the silo; this is an archive).
//!
//! Each imported file is remembered by size and modified time, so a
//! second scan skips what did not move: the same trade every backup tool
//! makes.
//!
//! Both files here are encrypted, because between them they name every
//! mirrored file by its full local path. That is a list of what someone
//! keeps and where, it survived locking the silo and removing it, and until
//! core 1.6.0 it sat in the clear beside the blob cache.
//!
//! Under the content KEK rather than the DEK, and the difference matters:
//! the KEK never rotates. Sealed under the DEK, a key rotation would leave
//! the ledger unreadable, and a ledger that reads as empty is not a slow
//! scan, it is every protected file imported a second time and the silo
//! holding two copies of each under a "(2)" name. For the same reason a
//! ledger that will not open is an error here, never an empty one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use silentsilo_crypto::{ContentKek, seal_with_key, unseal_with_key};
use zeroize::Zeroizing;

use crate::error::VaultError;

/// The folder list, sealed under the content KEK.
const CONFIG_FILE: &str = "protected.enc";
/// The import ledger, ciphered page by page by SQLCipher.
const LEDGER_FILE: &str = "protected.sqlcipher";
/// The ledger's page key, sealed under the content KEK. Random per ledger,
/// like the working copy's, so the KEK itself is never handed to SQLCipher.
const LEDGER_KEY_FILE: &str = "protected.key";
/// What releases before core 1.6.0 wrote, in the clear. Read once and
/// removed; see `adopt_legacy_config` and `adopt_legacy_ledger`.
const LEGACY_CONFIG_FILE: &str = "protected.json";
const LEGACY_LEDGER_FILE: &str = "protected.db";

/// One folder being copied into the silo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedFolder {
    /// Where it is on this computer.
    pub path: PathBuf,
    /// Where its contents land inside the silo, as a vault path. Kept
    /// explicitly rather than derived from the folder name, so renaming the
    /// folder on disk does not silently start a second copy beside the first.
    pub target: String,
}

/// The list, as stored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedFolders {
    pub folders: Vec<ProtectedFolder>,
}

/// Beside the import ledger, and machine-local for the same reason: these
/// are local paths, and the silo folder is made to be carried around.
fn config_path(vault_root: &Path) -> PathBuf {
    crate::workdir::cache_dir_for(vault_root).join(CONFIG_FILE)
}

fn legacy_config_path(vault_root: &Path) -> PathBuf {
    crate::workdir::cache_dir_for(vault_root).join(LEGACY_CONFIG_FILE)
}

/// Local to this machine, never in the silo folder: see `config_path`.
pub fn save_protected(
    vault_root: &Path,
    kek: &ContentKek,
    folders: &ProtectedFolders,
) -> Result<(), VaultError> {
    let sealed = seal_with_key(&crate::format::encode(folders)?, kek.as_bytes())
        .map_err(|e| VaultError::Crypto(e.to_string()))?;
    crate::workdir::write_private(&config_path(vault_root), &sealed)?;
    let _ = std::fs::remove_file(legacy_config_path(vault_root));
    Ok(())
}

/// An empty list for a silo that has never had one, which is not an error.
/// A list that is there and will not open is one, because answering "no
/// protected folders" would stop copying folders someone asked for.
pub fn load_protected(vault_root: &Path, kek: &ContentKek) -> Result<ProtectedFolders, VaultError> {
    match std::fs::read(config_path(vault_root)) {
        Ok(sealed) => {
            let plain = unseal_with_key(&sealed, kek.as_bytes()).map_err(|e| {
                VaultError::Crypto(format!("the protected folder list is not readable: {e}"))
            })?;
            crate::format::decode("the protected folder list", &plain)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => adopt_legacy_config(vault_root, kek),
        Err(e) => Err(e.into()),
    }
}

/// The plaintext list a release before core 1.6.0 left behind: read once,
/// written back sealed and removed, so the paths stop sitting in the clear
/// without anyone having to set their folders up again.
fn adopt_legacy_config(
    vault_root: &Path,
    kek: &ContentKek,
) -> Result<ProtectedFolders, VaultError> {
    let bytes = match std::fs::read(legacy_config_path(vault_root)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ProtectedFolders::default());
        }
        Err(e) => return Err(e.into()),
    };
    let folders: ProtectedFolders = crate::format::decode("the protected folder list", &bytes)?;
    save_protected(vault_root, kek, &folders)?;
    Ok(folders)
}

/// What a file looked like when it was last imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStat {
    pub size: u64,
    /// Seconds since the epoch. Whole seconds because that is what every
    /// filesystem agrees on, and finer resolution would only make the
    /// comparison fail more often on copies that are actually identical.
    pub modified: i64,
}

/// One file the scan decided to import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingImport {
    pub source: PathBuf,
    /// Folder inside the silo, as a vault path.
    pub target_folder: String,
    pub stat: FileStat,
}

/// Walks a protected folder and lists what has changed since last time. A
/// file whose size and modified time both match `seen` is skipped. Nothing
/// here deletes. Symbolic links are not followed: a link into a parent
/// walks forever, and one pointing outside the folder would copy in
/// something the user never marked.
pub fn plan_scan(
    root: &Path,
    target: &str,
    seen: &HashMap<PathBuf, FileStat>,
) -> Result<Vec<PendingImport>, VaultError> {
    let mut pending = Vec::new();
    let mut stack = vec![(root.to_path_buf(), target.to_string())];

    while let Some((dir, vault_dir)) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            // A folder that has become unreadable (an unplugged drive, a
            // permission change) is skipped rather than failing the scan: the
            // other protected folders still deserve their pass.
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }

            let Some(name) = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_string)
            else {
                continue;
            };

            if meta.is_dir() {
                let child = join_vault_path(&vault_dir, &name);
                stack.push((path, child));
                continue;
            }
            if !meta.is_file() {
                continue;
            }

            let stat = FileStat {
                size: meta.len(),
                modified: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            };
            if seen.get(&path) == Some(&stat) {
                continue;
            }
            pending.push(PendingImport {
                source: path,
                target_folder: vault_dir.clone(),
                stat,
            });
        }
    }

    // Shallowest first, and stable, so a run that is interrupted resumes
    // somewhere predictable rather than in a different order every time.
    pending.sort_by(|a, b| {
        (a.target_folder.matches('/').count(), &a.source)
            .cmp(&(b.target_folder.matches('/').count(), &b.source))
    });
    Ok(pending)
}

fn join_vault_path(parent: &str, name: &str) -> String {
    if parent.ends_with('/') {
        format!("{parent}{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// What this machine has already taken from its protected folders. A fact
/// about this disk, kept beside the blob cache rather than in the vault
/// index, and holding the full local path of every file that was copied.
fn seen_db_path(vault_root: &Path) -> PathBuf {
    crate::workdir::cache_dir_for(vault_root).join(LEDGER_FILE)
}

fn ledger_key_path(vault_root: &Path) -> PathBuf {
    crate::workdir::cache_dir_for(vault_root).join(LEDGER_KEY_FILE)
}

fn legacy_seen_db_path(vault_root: &Path) -> PathBuf {
    crate::workdir::cache_dir_for(vault_root).join(LEGACY_LEDGER_FILE)
}

/// The ledger's page key, drawn the first time and kept sealed beside it.
fn ledger_key(vault_root: &Path, kek: &ContentKek) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let path = ledger_key_path(vault_root);
    match std::fs::read(&path) {
        Ok(sealed) => {
            let plain = Zeroizing::new(unseal_with_key(&sealed, kek.as_bytes()).map_err(|e| {
                VaultError::Crypto(format!(
                    "the protected folder ledger's key is not readable: {e}"
                ))
            })?);
            if plain.len() != 32 {
                return Err(VaultError::Corrupted(
                    "the protected folder ledger's key is not 32 bytes".into(),
                ));
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&plain);
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // A ledger whose key is gone opens under nothing, and reading it
            // as empty would copy every protected file into the silo a
            // second time. Refused instead, which costs the scan and no data.
            if seen_db_path(vault_root).exists() {
                return Err(VaultError::Corrupted(
                    "the protected folder ledger is here but the key that opens it is not".into(),
                ));
            }
            let key: Zeroizing<[u8; 32]> = Zeroizing::new(rand::random());
            let sealed = seal_with_key(&key[..], kek.as_bytes())
                .map_err(|e| VaultError::Crypto(e.to_string()))?;
            crate::workdir::write_private(&path, &sealed)?;
            Ok(key)
        }
        Err(e) => Err(e.into()),
    }
}

fn open_seen_db(vault_root: &Path, kek: &ContentKek) -> Result<Connection, VaultError> {
    crate::workdir::create_private_dir(&crate::workdir::cache_dir_for(vault_root))?;
    let key = ledger_key(vault_root, kek)?;
    crate::init_openssl();
    let conn = Connection::open(seen_db_path(vault_root))?;
    // The key goes first: nothing may read the file before it is set.
    conn.pragma_update(None, "key", key_literal(&key).as_str())?;
    // Parallel imports open this from several threads at once.
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute_batch(
        "PRAGMA temp_store=MEMORY;
         CREATE TABLE IF NOT EXISTS protected_seen (
            path     TEXT PRIMARY KEY,
            size     INTEGER NOT NULL,
            modified INTEGER NOT NULL
        );",
    )?;
    adopt_legacy_ledger(vault_root, &conn)?;
    Ok(conn)
}

/// SQLCipher takes the key as a raw hex literal, with no passphrase KDF.
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

/// Moves the rows a release before core 1.6.0 kept in the clear into the
/// ciphered ledger, then removes the plaintext file.
///
/// The rows are upserted, so a run that stops halfway repeats harmlessly. A
/// plaintext file that cannot be read counts as no rows and goes anyway: its
/// rows were unreadable either way, so the rescan happens regardless, and
/// leaving local paths on disk is the thing being fixed.
fn adopt_legacy_ledger(vault_root: &Path, conn: &Connection) -> Result<(), VaultError> {
    let legacy = legacy_seen_db_path(vault_root);
    if !legacy.is_file() {
        return Ok(());
    }
    if let Ok(old) = Connection::open(&legacy) {
        let rows: Vec<(String, i64, i64)> = old
            .prepare("SELECT path, size, modified FROM protected_seen")
            .and_then(|mut stmt| {
                stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                    .collect()
            })
            .unwrap_or_default();
        for (path, size, modified) in rows {
            conn.execute(
                "INSERT INTO protected_seen(path, size, modified) VALUES (?1, ?2, ?3)
                 ON CONFLICT(path) DO UPDATE SET size = excluded.size, modified = excluded.modified",
                rusqlite::params![path, size, modified],
            )?;
        }
    }
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut name = legacy.as_os_str().to_os_string();
        name.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(name));
    }
    Ok(())
}

pub fn load_seen(
    vault_root: &Path,
    kek: &ContentKek,
) -> Result<HashMap<PathBuf, FileStat>, VaultError> {
    let conn = open_seen_db(vault_root, kek)?;
    let mut stmt = conn.prepare("SELECT path, size, modified FROM protected_seen")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            PathBuf::from(row.get::<_, String>(0)?),
            FileStat {
                size: row.get::<_, i64>(1)? as u64,
                modified: row.get(2)?,
            },
        ))
    })?;
    let mut out = HashMap::new();
    for row in rows {
        let (path, stat) = row?;
        out.insert(path, stat);
    }
    Ok(out)
}

/// Records one file as taken, after it is in the silo and not before.
///
/// Written per file rather than per scan so an interrupted run keeps what it
/// managed. The other order, marking first, would skip a file that never
/// arrived and leave it missing until someone touched it again.
pub fn mark_seen(
    vault_root: &Path,
    kek: &ContentKek,
    path: &Path,
    stat: FileStat,
) -> Result<(), VaultError> {
    let conn = open_seen_db(vault_root, kek)?;
    conn.execute(
        "INSERT INTO protected_seen(path, size, modified) VALUES (?1, ?2, ?3)
         ON CONFLICT(path) DO UPDATE SET size = excluded.size, modified = excluded.modified",
        rusqlite::params![path.to_string_lossy(), stat.size as i64, stat.modified],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use silentsilo_crypto::generate_content_kek;

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, body).unwrap();
        path
    }

    fn stat_of(path: &Path) -> FileStat {
        let meta = std::fs::metadata(path).unwrap();
        FileStat {
            size: meta.len(),
            modified: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        }
    }

    #[test]
    fn the_folder_list_never_lands_in_the_silo() {
        // These are absolute local paths: they open nothing, but they
        // describe what someone keeps and where.
        let dir = tempfile::tempdir().unwrap();
        let silo = dir.path().join("Personal");
        std::fs::create_dir_all(&silo).unwrap();
        let kek = generate_content_kek();

        save_protected(
            &silo,
            &kek,
            &ProtectedFolders {
                folders: vec![ProtectedFolder {
                    path: PathBuf::from(r"C:\Users\alex\Documents\Taxes"),
                    target: "/Taxes".into(),
                }],
            },
        )
        .unwrap();

        assert!(!silo.join("protected.json").exists());
        let inside = std::fs::read_dir(&silo)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(inside.is_empty(), "the silo folder gained {inside:?}");

        // Still readable where it belongs, or the move would have cost the
        // feature rather than relocated it.
        let back = load_protected(&silo, &kek).unwrap();
        assert_eq!(back.folders.len(), 1);
        assert_eq!(back.folders[0].target, "/Taxes");

        let _ = std::fs::remove_dir_all(crate::workdir::cache_dir_for(&silo));
    }

    /// Every byte this machine keeps about protected folders, checked for
    /// the one thing it must not spell out.
    fn cache_holds(silo: &Path, needle: &str) -> bool {
        let Ok(entries) = std::fs::read_dir(crate::workdir::cache_dir_for(silo)) else {
            return false;
        };
        entries.flatten().any(|entry| {
            std::fs::read(entry.path())
                .map(|bytes| {
                    bytes
                        .windows(needle.len())
                        .any(|window| window == needle.as_bytes())
                })
                .unwrap_or(false)
        })
    }

    #[test]
    fn neither_the_list_nor_the_ledger_leaves_a_path_in_the_clear() {
        // The finding: between them these two files named every mirrored
        // file, in full, beside the blob cache, and they outlived locking
        // the silo and removing it.
        let dir = tempfile::tempdir().unwrap();
        let silo = dir.path().join("Personal");
        std::fs::create_dir_all(&silo).unwrap();
        let kek = generate_content_kek();
        let secret = "Divorce papers";
        let folder = dir.path().join(secret);
        let file = write(&folder, "settlement.pdf", "x");

        save_protected(
            &silo,
            &kek,
            &ProtectedFolders {
                folders: vec![ProtectedFolder {
                    path: folder.clone(),
                    target: "/Papers".into(),
                }],
            },
        )
        .unwrap();
        mark_seen(&silo, &kek, &file, stat_of(&file)).unwrap();

        assert!(
            !cache_holds(&silo, secret),
            "a protected folder's path is readable on disk"
        );
        assert!(!cache_holds(&silo, "settlement.pdf"));

        // And it is all still there for the silo that owns it.
        assert_eq!(load_protected(&silo, &kek).unwrap().folders[0].path, folder);
        assert_eq!(load_seen(&silo, &kek).unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(crate::workdir::cache_dir_for(&silo));
    }

    #[test]
    fn a_list_and_ledger_from_an_older_release_are_taken_over_whole() {
        // The upgrade path. What 1.5.0 wrote is read once, written back
        // sealed and removed. Nothing is lost, because an empty ledger is
        // not a slow scan: it is every file imported a second time.
        let dir = tempfile::tempdir().unwrap();
        let silo = dir.path().join("Personal");
        std::fs::create_dir_all(&silo).unwrap();
        let cache = crate::workdir::cache_dir_for(&silo);
        crate::workdir::create_private_dir(&cache).unwrap();
        let kek = generate_content_kek();
        let taken = PathBuf::from(r"C:\Users\alex\Documents\Taxes\2025.pdf");

        // Exactly the bytes a release before 1.6.0 left behind.
        let folders = ProtectedFolders {
            folders: vec![ProtectedFolder {
                path: PathBuf::from(r"C:\Users\alex\Documents\Taxes"),
                target: "/Taxes".into(),
            }],
        };
        std::fs::write(
            cache.join(LEGACY_CONFIG_FILE),
            crate::format::encode(&folders).unwrap(),
        )
        .unwrap();
        let old = Connection::open(cache.join(LEGACY_LEDGER_FILE)).unwrap();
        old.execute_batch(
            "CREATE TABLE protected_seen (
                path TEXT PRIMARY KEY, size INTEGER NOT NULL, modified INTEGER NOT NULL);",
        )
        .unwrap();
        old.execute(
            "INSERT INTO protected_seen(path, size, modified) VALUES (?1, 42, 7)",
            rusqlite::params![taken.to_string_lossy()],
        )
        .unwrap();
        drop(old);

        assert_eq!(load_protected(&silo, &kek).unwrap(), folders);
        let seen = load_seen(&silo, &kek).unwrap();
        assert_eq!(
            seen.get(&taken),
            Some(&FileStat {
                size: 42,
                modified: 7
            }),
            "a file already imported would be imported again"
        );

        assert!(!cache.join(LEGACY_CONFIG_FILE).exists());
        assert!(!cache.join(LEGACY_LEDGER_FILE).exists());
        assert!(!cache_holds(&silo, "Taxes"));

        // And the second open reads the ciphered copies, with nothing left
        // to adopt.
        assert_eq!(load_protected(&silo, &kek).unwrap(), folders);
        assert_eq!(load_seen(&silo, &kek).unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(cache);
    }

    #[test]
    fn a_ledger_that_will_not_open_is_an_error_rather_than_an_empty_one() {
        let dir = tempfile::tempdir().unwrap();
        let silo = dir.path().join("Personal");
        std::fs::create_dir_all(&silo).unwrap();
        let kek = generate_content_kek();
        let file = write(dir.path(), "notes.txt", "one");
        mark_seen(&silo, &kek, &file, stat_of(&file)).unwrap();
        save_protected(&silo, &kek, &ProtectedFolders::default()).unwrap();

        // Another silo's key, and then no key at all.
        assert!(load_seen(&silo, &generate_content_kek()).is_err());
        std::fs::remove_file(ledger_key_path(&silo)).unwrap();
        assert!(
            load_seen(&silo, &kek).is_err(),
            "reading it as empty means importing every file again"
        );
        assert!(load_protected(&silo, &generate_content_kek()).is_err());

        let _ = std::fs::remove_dir_all(crate::workdir::cache_dir_for(&silo));
    }

    #[test]
    fn the_first_scan_takes_everything() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "notes.txt", "one");
        write(dir.path(), "sub/deep.txt", "two");

        let plan = plan_scan(dir.path(), "/Protected", &HashMap::new()).unwrap();

        let targets: Vec<&str> = plan.iter().map(|p| p.target_folder.as_str()).collect();
        assert_eq!(plan.len(), 2);
        assert!(targets.contains(&"/Protected"));
        assert!(targets.contains(&"/Protected/sub"));
    }

    #[test]
    fn a_file_that_has_not_moved_is_skipped() {
        // The whole reason the scan is cheap the second time: encrypting a
        // file to find out whether it changed would mean re-encrypting the
        // tree on every unlock.
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "notes.txt", "one");
        let seen: HashMap<PathBuf, FileStat> =
            [(path.clone(), stat_of(&path))].into_iter().collect();

        assert!(
            plan_scan(dir.path(), "/Protected", &seen)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_file_whose_size_changed_is_taken_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "notes.txt", "one");
        let before = stat_of(&path);
        write(dir.path(), "notes.txt", "one and a bit more");
        let seen: HashMap<PathBuf, FileStat> = [(path.clone(), before)].into_iter().collect();

        let plan = plan_scan(dir.path(), "/Protected", &seen).unwrap();

        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].source, path);
    }

    #[test]
    fn a_file_deleted_from_disk_is_not_removed_from_the_silo() {
        // An archive, not a mirror. The copy surviving what happens to the
        // original is the reason for putting a folder here at all.
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("deleted.txt");
        let seen: HashMap<PathBuf, FileStat> = [(
            gone,
            FileStat {
                size: 3,
                modified: 1,
            },
        )]
        .into_iter()
        .collect();

        let plan = plan_scan(dir.path(), "/Protected", &seen).unwrap();

        // Nothing to import, and nothing in the plan asking for a deletion:
        // there is no way to express one.
        assert!(plan.is_empty());
    }

    #[test]
    fn links_are_not_followed() {
        // A link into a parent walks forever; one pointing outside the folder
        // copies in something nobody marked.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "real.txt", "one");
        let outside = tempfile::tempdir().unwrap();
        write(outside.path(), "secret.txt", "not yours");

        let link = dir.path().join("link");
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(outside.path(), &link);
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_dir(outside.path(), &link);
        if made.is_err() {
            // Windows needs developer mode or elevation for this. Said out
            // loud rather than passing on a link that was never created,
            // which would prove nothing at all.
            eprintln!("skipped: this machine will not create symbolic links");
            return;
        }

        let plan = plan_scan(dir.path(), "/Protected", &HashMap::new()).unwrap();

        assert!(
            plan.iter().all(|p| !p.source.ends_with("secret.txt")),
            "the scan followed a link out of the folder: {plan:?}"
        );
    }

    #[test]
    fn the_list_survives_a_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let kek = generate_content_kek();
        let folders = ProtectedFolders {
            folders: vec![ProtectedFolder {
                path: PathBuf::from("C:/Users/alex/Documents/Taxes"),
                target: "/Protected/Taxes".into(),
            }],
        };

        save_protected(dir.path(), &kek, &folders).unwrap();

        assert_eq!(load_protected(dir.path(), &kek).unwrap(), folders);
        let _ = std::fs::remove_dir_all(crate::workdir::cache_dir_for(dir.path()));
    }

    #[test]
    fn a_silo_with_no_list_reports_an_empty_one() {
        let dir = tempfile::tempdir().unwrap();

        assert_eq!(
            load_protected(dir.path(), &generate_content_kek()).unwrap(),
            ProtectedFolders::default()
        );
    }
}
