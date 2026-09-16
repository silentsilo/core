//! A fleet half updated: one device still on 1.0.0, the others on this
//! build, all syncing against the same storage.
//!
//! 1.0.0's sync pass lived in the desktop app, so the 1.0.0 device runs that
//! pass as desktop 1.0.0 wrote it, over the 1.0.0 crates. The devices on this
//! build run `silentsilo_app::run_sync_pass`. The silo starts on three 1.0.0
//! devices; two of them then update in place, which is the first unlock of
//! a 1.0.0 silo folder by this build, and all three go on working.
//!
//! What must hold, however the passes interleave:
//!
//! - no pass fails, holds records back or finds an unreadable object, on
//!   either version. The one exception is a 1.0.0 replay stopping at a
//!   record 1.0.0 refuses the same way when the change is made on it
//!   (`refused_by_1_0_0.rs`): that is printed with who wrote the record;
//! - the devices on this build agree exactly;
//! - nothing added is gone from them unless it was deleted for good;
//! - every file any device shows opens, with the bytes that were added,
//!   unless that content was deleted for good on purpose. A 1.0.0 sweep
//!   deleting content this build still shows is the failure this exists to
//!   catch.
//!
//! What the 1.0.0 device shows differently is printed, not failed: 1.0.0
//! applied some records differently depending on arrival order, which this
//! build fixed, and it applies purges and names by its own rules.
//!
//! Every pass sweeps storage for unreferenced content, where the apps sweep
//! once a day: the window a sweep could delete something in is the point.
//!
//! `SILENTSILO_MIXED_SEED` replays one seed, `SILENTSILO_MIXED_TRACE` prints
//! what each device does as it goes.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::Connection;
use silentsilo_app::files::{import_file, read_file};
use silentsilo_app::{AppEvent, AppState, Host, SyncReport, run_sync_pass};
use silentsilo_crypto_v1_0_0 as crypto_v1;
use silentsilo_store_v1_0_0 as store_v1;
use silentsilo_sync_v1_0_0 as sync_v1;
use silentsilo_vault::{BackupTarget, SiloEntry, TargetRole, VaultSession};
use silentsilo_vault_v1_0_0 as vault_v1;
use silentsilo_vfs::Vfs;
use silentsilo_vfs_v1_0_0 as vfs_v1;
use uuid::Uuid;

// ── A seeded order ──────────────────────────────────────────────────

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn pick<T: Clone>(&mut self, items: &[T]) -> Option<T> {
        (!items.is_empty()).then(|| items[self.below(items.len())].clone())
    }
}

const FOLDER_NAMES: &[&str] = &["Docs", "docs", "Photos", "x", "X", "x (2)", "Școală"];
const FILE_NAMES: &[&str] = &["a.txt", "A.txt", "a (2).txt", "report.pdf", "notă.md"];
const PASSWORD_IDS: &[u128] = &[1, 2, 3, 4];

// ── Devices ─────────────────────────────────────────────────────────

struct FleetHost {
    targets: Vec<BackupTarget>,
}

impl Host for FleetHost {
    fn emit(&self, _event: AppEvent) {}
    fn warn(&self, _area: &str, _detail: &str) {}
    fn targets(&self, _silo_id: Uuid) -> Vec<BackupTarget> {
        self.targets.clone()
    }
}

/// A device on this build, driven the way `silentsilo-app/tests/fleet.rs`
/// drives one.
struct NewDevice {
    state: AppState,
    silo: SiloEntry,
    host: FleetHost,
}

/// A device on 1.0.0.
struct OldDevice {
    session: Mutex<vault_v1::VaultSession>,
    target: store_v1::StoreConfig,
}

enum Kind {
    Old(OldDevice),
    New(NewDevice),
}

struct Device {
    _dir: tempfile::TempDir,
    root: PathBuf,
    storage: PathBuf,
    kind: Kind,
}

/// What a pass came to, on either version.
#[derive(Debug, Default)]
struct Pass {
    moved: usize,
    unreadable: Vec<String>,
    held_back: usize,
    failed: Vec<String>,
    stuck: bool,
    /// A record 1.0.0 could not apply, which stops its replay at that record
    /// on every pass after.
    refused: Option<Refusal>,
}

/// A record a 1.0.0 replay failed on.
#[derive(Debug, Clone)]
struct Refusal {
    error: String,
    author: Uuid,
    seq: u64,
    op: String,
}

/// The constraint errors 1.0.0 stops a replay with when its own `Vfs` would
/// refuse the same change: a name its ranking gives to an entry already
/// called that, and a purge of a folder that still holds something. See
/// `refused_by_1_0_0.rs`. Any other error fails the test.
fn refused_the_way_1_0_0_refuses_locally(error: &str) -> bool {
    [
        "UNIQUE constraint failed: files.folder_id, files.name",
        "UNIQUE constraint failed: folders.path",
        "FOREIGN KEY constraint failed",
    ]
    .iter()
    .any(|known| error.contains(known))
}

impl Device {
    fn is_old(&self) -> bool {
        matches!(self.kind, Kind::Old(_))
    }

    fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> T) -> T {
        match &self.kind {
            Kind::Old(old) => f(&old.session.lock().unwrap().conn),
            Kind::New(new) => {
                let sessions = new.state.sessions.lock().unwrap();
                f(&sessions[&new.silo.id].conn)
            }
        }
    }

    fn keys(&self) -> ([u8; 32], [u8; 32]) {
        match &self.kind {
            Kind::Old(old) => {
                let session = old.session.lock().unwrap();
                (*session.dek.as_bytes(), *session.kek.as_bytes())
            }
            Kind::New(_) => unreachable!("the silo is created on 1.0.0"),
        }
    }

    /// A 1.0.0 device, creating the silo or joining it with its keys.
    fn old(vault_id: Uuid, keys: Option<([u8; 32], [u8; 32])>, storage: &Path) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("silo");
        let session = match keys {
            Some((dek, kek)) => vault_v1::VaultSession::provision_with_dek(
                root.clone(),
                vault_id,
                "secret",
                crypto_v1::MasterDek::from_bytes(dek),
                crypto_v1::ContentKek::from_bytes(kek),
            ),
            None => vault_v1::VaultSession::provision(root.clone(), vault_id, "secret"),
        }
        .unwrap();
        vfs_v1::Vfs::new(&session).ensure_initialized().unwrap();
        Self {
            _dir: dir,
            root,
            storage: storage.to_path_buf(),
            kind: Kind::Old(OldDevice {
                session: Mutex::new(session),
                target: store_v1::StoreConfig::Folder {
                    path: storage.to_path_buf(),
                },
            }),
        }
    }

    /// The update: the app locks the 1.0.0 silo, and this build unlocks the
    /// same silo folder.
    fn update(&mut self, silo_index: usize) {
        let Kind::Old(old) = &self.kind else {
            return;
        };
        let dek = {
            let session = old.session.lock().unwrap();
            session.seal_for_lock().unwrap();
            *session.dek.as_bytes()
        };
        let placeholder = Kind::New(NewDevice {
            state: AppState::default(),
            silo: silo_entry(&self.root, silo_index),
            host: FleetHost {
                targets: Vec::new(),
            },
        });
        let Kind::Old(old) = std::mem::replace(&mut self.kind, placeholder) else {
            unreachable!()
        };
        let paths = old.session.into_inner().unwrap().paths;
        vault_v1::wipe_plaintext_working_copy(&paths);

        let session = VaultSession::open_with_dek(
            self.root.clone(),
            silentsilo_crypto::MasterDek::from_bytes(dek),
        )
        .expect("this build opens a silo folder 1.0.0 locked");
        let Kind::New(new) = &mut self.kind else {
            unreachable!()
        };
        new.host.targets = vec![BackupTarget {
            config: silentsilo_store::StoreConfig::Folder {
                path: self.storage.clone(),
            },
            label: String::new(),
            role: TargetRole::Working,
        }];
        Vfs::new(&session)
            .ensure_initialized()
            .expect("the first unlock after the update rebuilds");
        let version: String = session
            .conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version, silentsilo_vfs::SCHEMA_VERSION.to_string());
        new.state
            .open_session(&new.host, new.silo.id, session)
            .unwrap();
    }

    /// One pass, sweeping storage every time rather than once a day.
    async fn pass(&self) -> Pass {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM vault_meta WHERE key LIKE 'blob_sweep_at:%'",
                [],
            )
            .unwrap()
        });
        match &self.kind {
            Kind::New(new) => {
                let report: SyncReport = run_sync_pass(&new.state, &new.host, &new.silo)
                    .await
                    .unwrap_or_else(|e| panic!("a pass on this build failed: {e}"));
                Pass {
                    moved: report.ops_pushed + report.ops_applied + report.blobs_uploaded,
                    unreadable: report.unreadable,
                    held_back: report.held_back,
                    failed: report
                        .targets
                        .iter()
                        .filter_map(|t| t.failed.clone())
                        .collect(),
                    stuck: report.needs_rebuild || report.needs_rejoin,
                    refused: None,
                }
            }
            Kind::Old(old) => match old_pass(old, &self.root).await {
                Ok(pass) => pass,
                Err(OldPassError::Refused(refusal))
                    if refused_the_way_1_0_0_refuses_locally(&refusal.error) =>
                {
                    Pass {
                        refused: Some(refusal),
                        ..Pass::default()
                    }
                }
                Err(OldPassError::Refused(refusal)) => {
                    panic!("a pass on 1.0.0 failed: {refusal:?}")
                }
                Err(OldPassError::Other(e)) => panic!("a pass on 1.0.0 failed: {e}"),
            },
        }
    }
}

fn silo_entry(root: &Path, index: usize) -> SiloEntry {
    SiloEntry {
        id: Uuid::from_u128(index as u128 + 1),
        name: "Mixed".into(),
        path: root.to_path_buf(),
        last_opened: 0,
        auto_lock_minutes: None,
    }
}

#[derive(Debug)]
enum OldPassError {
    Refused(Refusal),
    Other(String),
}

impl From<String> for OldPassError {
    fn from(e: String) -> Self {
        Self::Other(e)
    }
}

/// Desktop 1.0.0's `run_sync_pass` (src-tauri/src/commands/sync.rs at
/// v1.0.0) with one folder target, the Tauri state and events taken out.
async fn old_pass(device: &OldDevice, root: &Path) -> Result<Pass, OldPassError> {
    use store_v1::ObjectStore;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let target_id = device.target.target_id();
    let every_target = [target_id];
    let store = device.target.open().map_err(|e| e.to_string())?;

    let (owed, dek, kek, vault_id, applied_through, base, known) = {
        let session = device.session.lock().unwrap();
        let conn = &session.conn;
        (
            vfs_v1::pending_ops_for(conn, target_id).map_err(|e| e.to_string())?,
            session.dek.clone(),
            session.kek.clone(),
            session.vault_id,
            vfs_v1::highest_applied_lamport(conn).map_err(|e| e.to_string())?,
            vfs_v1::snapshot::read_base(conn).map_err(|e| e.to_string())?,
            vfs_v1::all_op_ids(conn).map_err(|e| e.to_string())?,
        )
    };
    let local_horizon = base.as_ref().map(|s| s.horizon).unwrap_or(0);

    let stores: Vec<&dyn ObjectStore> = vec![&*store];
    let horizon = sync_v1::lowest_snapshot_horizon(&stores)
        .await
        .map_err(|e| e.to_string())?;
    if horizon > 0 && applied_through <= horizon {
        return Ok(Pass {
            stuck: true,
            ..Pass::default()
        });
    }
    if let Ok(Some(false)) = sync_v1::key_still_current(&*store, &dek).await {
        return Ok(Pass {
            stuck: true,
            ..Pass::default()
        });
    }

    // Out.
    let kek_envelope = vault_v1::wrap_kek_bytes(&kek, &dek).map_err(|e| e.to_string())?;
    let recovery = vault_v1::load_recovery_envelope(root).ok();
    let keys = vault_v1::load_fido_keys(root).ok();
    let outcome = sync_v1::push_everything_to(
        &sync_v1::TargetPush {
            id: target_id,
            store: &*store,
            allows_delete: true,
            owed: &owed,
        },
        &sync_v1::SiloState {
            vault_id,
            dek: &dek,
            kek_envelope: &kek_envelope,
            recovery: recovery.as_ref(),
            keys: keys.as_ref(),
            base: base.as_ref(),
            vault_root: root,
        },
    )
    .await;
    let mut failed: Vec<String> = outcome.failed.clone().into_iter().collect();

    // In.
    let mut incoming = Vec::new();
    let mut unreadable = Vec::new();
    match sync_v1::fetch_missing_ops(&*store, &dek, &known, local_horizon).await {
        Ok(mut got) => {
            incoming.append(&mut got.records);
            unreadable.append(&mut got.unreadable);
        }
        Err(e) => failed.push(e.to_string()),
    }
    let (incoming, held_back) = sync_v1::usable_prefix(incoming, &unreadable);
    let replayed = {
        let session = device.session.lock().unwrap();
        let report = match vfs_v1::replay(&session.conn, incoming.clone()) {
            Ok(report) => report,
            Err(e) => {
                return Err(match failing_record(&session.conn, incoming) {
                    Some(refusal) => OldPassError::Refused(refusal),
                    None => OldPassError::Other(e.to_string()),
                });
            }
        };
        if failed.is_empty() {
            vfs_v1::mark_delivered(&session.conn, target_id, &owed).map_err(|e| e.to_string())?;
        }
        report
    };
    {
        let mut session = device.session.lock().unwrap();
        vfs_v1::settle_delivery(&mut session.conn, &every_target).map_err(|e| e.to_string())?;
    }
    vault_v1::settle_blob_delivery(root, &every_target).map_err(|e| e.to_string())?;
    {
        let session = device.session.lock().unwrap();
        if failed.is_empty() {
            vfs_v1::record_target_success(&session.conn, target_id, now)
        } else {
            vfs_v1::record_target_failure(&session.conn, target_id, now).map(|_| ())
        }
        .map_err(|e| e.to_string())?;
    }

    // Housekeeping: a full copy is off, as it is by default.
    assert!(!vault_v1::keep_full_copy(root));

    let planned = {
        let session = device.session.lock().unwrap();
        sync_v1::plan_compaction(
            &session.conn,
            vault_id,
            &vfs_v1::CompactionPolicy::default(),
            now,
        )
    };
    if let Ok(Some(snapshot)) = planned
        && sync_v1::publish_compaction(&*store, &dek, &snapshot, true)
            .await
            .is_ok()
    {
        let mut session = device.session.lock().unwrap();
        let _ = sync_v1::finish_compaction(&mut session.conn, &snapshot);
    }

    let plan = {
        let session = device.session.lock().unwrap();
        let due = matches!(
            vfs_v1::snapshot::sweep_due(&session.conn, target_id, now, 24 * 60 * 60),
            Ok(true)
        );
        match (
            due,
            vfs_v1::Vfs::new(&session).referenced_blobs_with_attachments(),
            vfs_v1::snapshot::gc_candidates(&session.conn, target_id),
        ) {
            (true, Ok(referenced), Ok(candidates)) => Some((referenced, candidates)),
            _ => None,
        }
    };
    if let Some((referenced, candidates)) = plan
        && let Ok(swept) = sync_v1::sweep_orphan_blobs(&*store, &referenced, &candidates).await
    {
        let mut session = device.session.lock().unwrap();
        let seen = swept.candidates.into_iter().collect();
        let _ = vfs_v1::snapshot::set_gc_candidates(&mut session.conn, target_id, &seen);
        let _ = vfs_v1::snapshot::record_sweep(&session.conn, target_id, now);
    }

    Ok(Pass {
        moved: outcome.ops_pushed + replayed.applied + outcome.blobs_uploaded,
        unreadable: unreadable
            .iter()
            .map(|u| format!("{}: {}", u.key, u.error))
            .collect(),
        held_back,
        failed,
        stuck: false,
        refused: None,
    })
}

// ── What each device can do ─────────────────────────────────────────

/// Runs the same call against whichever `Vfs` the device has. The body
/// must come out the same type on both versions.
macro_rules! on_vfs {
    ($device:expr, |$vfs:ident| $body:expr) => {
        match &$device.kind {
            Kind::Old(old) => {
                let session = old.session.lock().unwrap();
                let $vfs = vfs_v1::Vfs::new(&session);
                $body
            }
            Kind::New(new) => {
                let sessions = new.state.sessions.lock().unwrap();
                let $vfs = Vfs::new(&sessions[&new.silo.id]);
                $body
            }
        }
    };
}

/// Imports bytes as a file, returning its id and content hash.
fn import(device: &Device, folder: Uuid, name: &str, bytes: &[u8]) -> Option<(Uuid, String)> {
    match &device.kind {
        Kind::New(new) => {
            let file =
                import_file(&new.state, &new.silo, folder, &mut { bytes }, name, None).ok()?;
            Some((file.id, file.content_hash?))
        }
        Kind::Old(old) => {
            // Desktop 1.0.0's `encrypt_import` and `commit_import`.
            let source = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(source.path(), bytes).unwrap();
            let kek = old.session.lock().unwrap().kek.clone();
            let blob_id = Uuid::new_v4();
            let blob_path = vault_v1::VaultPaths::new(device.root.clone()).blob_path(blob_id);
            let content_key = crypto_v1::generate_content_key();
            let blob_key = crypto_v1::wrap_content_key(&content_key, &kek).unwrap();
            let result = crypto_v1::encrypt_file(
                source.path(),
                &blob_path,
                &content_key,
                Uuid::now_v7(),
                blob_id,
            )
            .unwrap();
            let _ = vault_v1::record_blob_present(
                &device.root,
                blob_id,
                result.size_bytes as i64,
                false,
            );
            let hash = hex::encode(result.header.content_hash);
            let session = old.session.lock().unwrap();
            let file = vfs_v1::Vfs::new(&session)
                .add_file(
                    folder,
                    name,
                    blob_id,
                    result.plain_bytes as i64,
                    &hash,
                    vfs_v1::guess_mime(Path::new(name)).as_deref(),
                    &blob_key,
                )
                .ok()?;
            Some((file.id, hash))
        }
    }
}

/// A file's bytes, fetched from storage first when this device lacks them.
async fn read(device: &Device, id: Uuid) -> Result<Vec<u8>, String> {
    match &device.kind {
        Kind::New(new) => read_file(&new.state, &new.host, &new.silo, id, 1 << 20)
            .await
            .map(|file| file.bytes),
        Kind::Old(old) => {
            let (blob, key) = device
                .with_conn(|conn| {
                    conn.query_row(
                        "SELECT blob_id, blob_key FROM files WHERE id = ?1",
                        [id.to_string()],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                    )
                })
                .map_err(|e| e.to_string())?;
            let blob = Uuid::parse_str(&blob).unwrap();
            let path = vault_v1::VaultPaths::new(device.root.clone()).blob_path(blob);
            if !path.is_file() {
                let store = old.target.open().map_err(|e| e.to_string())?;
                sync_v1::fetch_blob_from_any(&[&*store], &device.root, blob)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            let kek = old.session.lock().unwrap().kek.clone();
            let key = crypto_v1::unwrap_content_key(&key, &kek).map_err(|e| e.to_string())?;
            let out = tempfile::NamedTempFile::new().unwrap();
            crypto_v1::decrypt_blob(&path, out.path(), &key, blob).map_err(|e| e.to_string())?;
            std::fs::read(out.path()).map_err(|e| e.to_string())
        }
    }
}

fn uuids(device: &Device, sql: &str) -> Vec<Uuid> {
    device.with_conn(|conn| {
        conn.prepare(sql)
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|id| Uuid::parse_str(&id.unwrap()).unwrap())
            .collect()
    })
}

fn live_folders(device: &Device) -> Vec<Uuid> {
    uuids(
        device,
        "SELECT id FROM folders WHERE deleted_at IS NULL AND path != '/Inbox'
          ORDER BY path COLLATE NOCASE",
    )
}

fn files_with(device: &Device, trashed: bool) -> Vec<(Uuid, Option<String>)> {
    device.with_conn(|conn| {
        conn.prepare(&format!(
            "SELECT id, content_hash FROM files WHERE deleted_at IS {} NULL ORDER BY id",
            if trashed { "NOT" } else { "" }
        ))
        .unwrap()
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get(1)?)))
        .unwrap()
        .map(|row| {
            let (id, hash) = row.unwrap();
            (Uuid::parse_str(&id).unwrap(), hash)
        })
        .collect()
    })
}

/// Ids of the files under a folder, itself included, on one device.
fn files_under(device: &Device, folder_id: Uuid) -> Vec<(Uuid, Option<String>)> {
    device.with_conn(|conn| {
        let Ok(path) = conn.query_row(
            "SELECT path FROM folders WHERE id = ?1",
            [folder_id.to_string()],
            |r| r.get::<_, String>(0),
        ) else {
            return Vec::new();
        };
        let below = format!("{}/*", path.trim_end_matches('/'));
        conn.prepare(
            "SELECT f.id, f.content_hash FROM files f JOIN folders d ON d.id = f.folder_id
              WHERE d.id = ?1 OR d.path GLOB ?2",
        )
        .unwrap()
        .query_map(rusqlite::params![folder_id.to_string(), below], |r| {
            Ok((r.get::<_, String>(0)?, r.get(1)?))
        })
        .unwrap()
        .map(|row| {
            let (id, hash) = row.unwrap();
            (Uuid::parse_str(&id).unwrap(), hash)
        })
        .collect()
    })
}

/// What a device shows, comparable across devices.
fn picture(device: &Device) -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    let (folders, files) = device.with_conn(|conn| {
        let folders = conn
            .prepare("SELECT path, deleted_at IS NOT NULL FROM folders")
            .unwrap()
            .query_map([], |r| {
                Ok(format!(
                    "{} trashed={}",
                    r.get::<_, String>(0)?,
                    r.get::<_, bool>(1)?
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let files = conn
            .prepare(
                "SELECT d.path, f.name, f.blob_id, f.content_hash,
                        f.deleted_at IS NOT NULL, d.deleted_at IS NOT NULL
                   FROM files f JOIN folders d ON d.id = f.folder_id",
            )
            .unwrap()
            .query_map([], |r| {
                Ok(format!(
                    "{}/{} blob={} hash={:?} trashed={} folder_trashed={}",
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, bool>(4)?,
                    r.get::<_, bool>(5)?
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        (folders, files)
    });
    let passwords = on_vfs!(device, |vfs| vfs.list_passwords().unwrap())
        .into_iter()
        .collect();
    (folders, files, passwords)
}

// ── What was done, for judging what may be gone ─────────────────────

#[derive(Default)]
struct Ledger {
    /// Content added, by hash, with its bytes.
    added: HashMap<String, Vec<u8>>,
    /// Which file each content went into.
    hash_file: HashMap<String, Uuid>,
    /// Content a later add over the same name replaced in place.
    replaced: HashSet<String>,
    /// Content in the trash of a device when that device emptied it.
    purged: HashSet<String>,
    /// First step at which some device sent each file to the trash, directly
    /// or with a folder, or moved it.
    file_trashed_at: HashMap<Uuid, usize>,
    /// Steps at which some device emptied its trash.
    emptied: Vec<usize>,
    /// For each updated device, the first position in its chain written by
    /// this build.
    updated_from: HashMap<Uuid, u64>,
    /// Records a 1.0.0 device could not apply, by author and position, with
    /// whether this build wrote them.
    refused: std::collections::BTreeMap<(Uuid, u64), (bool, String, String)>,
}

impl Ledger {
    fn may_be_gone(&self, hash: &str) -> bool {
        if self.replaced.contains(hash) || self.purged.contains(hash) {
            return true;
        }
        self.hash_file
            .get(hash)
            .and_then(|file| self.file_trashed_at.get(file))
            .is_some_and(|since| self.emptied.iter().any(|at| at > since))
    }

    /// What happened, printed as it happens under `SILENTSILO_MIXED_TRACE`.
    fn note(&mut self, line: String) {
        if std::env::var("SILENTSILO_MIXED_TRACE").is_ok() {
            eprintln!("{line}");
        }
    }

    /// Checks a pass, keeping what a 1.0.0 device refused.
    fn check(&mut self, pass: Pass, context: &str) {
        assert!(
            pass.unreadable.is_empty()
                && pass.held_back == 0
                && pass.failed.is_empty()
                && !pass.stuck,
            "{context}: {pass:?}"
        );
        if let Some(refusal) = pass.refused {
            let by_this_build = self
                .updated_from
                .get(&refusal.author)
                .is_some_and(|from| refusal.seq >= *from);
            self.refused
                .entry((refusal.author, refusal.seq))
                .or_insert((by_this_build, refusal.error, refusal.op));
        }
    }

    fn trashing(&mut self, files: Vec<(Uuid, Option<String>)>, step: usize) {
        for (id, _) in files {
            self.file_trashed_at.entry(id).or_insert(step);
        }
    }
}

// ── One run ─────────────────────────────────────────────────────────

async fn act(devices: &[Device], rng: &mut Rng, ledger: &mut Ledger, step: usize) {
    let which = rng.below(devices.len());
    let d = &devices[which];
    let choice = rng.below(20);
    let version = if d.is_old() { "1.0.0" } else { "new" };
    ledger.note(format!(
        "step {step}: device {which} ({version}) action {choice}"
    ));
    match choice {
        0..=3 => {
            let a = &devices[rng.below(devices.len())];
            let b = &devices[rng.below(devices.len())];
            if std::ptr::eq(a, b) {
                ledger.check(a.pass().await, &format!("step {step}"));
            } else {
                let (x, y) = tokio::join!(a.pass(), b.pass());
                ledger.check(x, &format!("step {step}"));
                ledger.check(y, &format!("step {step}"));
            }
        }
        4 => {
            let (x, y, z) = tokio::join!(devices[0].pass(), devices[1].pass(), devices[2].pass());
            for p in [x, y, z] {
                ledger.check(p, &format!("step {step}"));
            }
        }
        5..=6 => {
            if let Some(parent) = rng.pick(&live_folders(d)) {
                let name = rng.pick(FOLDER_NAMES).unwrap();
                let _ = on_vfs!(d, |vfs| vfs
                    .create_folder(parent, name)
                    .map(|_| ())
                    .map_err(|e| e.to_string()));
            }
        }
        7..=10 => {
            let Some(folder) = rng.pick(&live_folders(d)) else {
                return;
            };
            let name = rng.pick(FILE_NAMES).unwrap();
            // Over a name already in the folder the content is replaced.
            let replaced: Vec<String> = files_under(d, folder)
                .into_iter()
                .filter_map(|(id, hash)| {
                    let same = d.with_conn(|conn| {
                        conn.query_row(
                            "SELECT folder_id = ?2 AND lower(name) = lower(?3) AND deleted_at IS NULL
                               FROM files WHERE id = ?1",
                            [id.to_string(), folder.to_string(), name.to_string()],
                            |r| r.get::<_, bool>(0),
                        )
                        .unwrap_or(false)
                    });
                    same.then_some(hash).flatten()
                })
                .collect();
            ledger.replaced.extend(replaced);
            let len = 64 + rng.below(3000);
            let bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            if let Some((id, hash)) = import(d, folder, name, &bytes) {
                ledger.note(format!("  added {hash} as {name} id {id}"));
                ledger.hash_file.insert(hash.clone(), id);
                ledger.added.insert(hash, bytes);
            }
        }
        11 => {
            if let Some((id, _)) = rng.pick(&files_with(d, false)) {
                let name = rng.pick(FILE_NAMES).unwrap();
                let _ = on_vfs!(d, |vfs| vfs
                    .rename_file(id, name)
                    .map(|_| ())
                    .map_err(|e| e.to_string()));
            } else if let Some(id) = rng.pick(&live_folders(d)) {
                let name = rng.pick(FOLDER_NAMES).unwrap();
                let _ = on_vfs!(d, |vfs| vfs
                    .rename_folder(id, name)
                    .map(|_| ())
                    .map_err(|e| e.to_string()));
            }
        }
        // Moves exist on this build only; 1.0.0 restores a folder instead.
        12 => match &d.kind {
            Kind::New(new) => {
                let folders = live_folders(d);
                if let (Some((id, hash)), Some(to)) =
                    (rng.pick(&files_with(d, false)), rng.pick(&folders))
                {
                    ledger.trashing(vec![(id, hash)], step);
                    let sessions = new.state.sessions.lock().unwrap();
                    let r = Vfs::new(&sessions[&new.silo.id])
                        .move_file(id, to)
                        .map(|f| f.id);
                    ledger.note(format!("  move file {id} to {to}: {r:?}"));
                }
            }
            Kind::Old(_) => {
                if let Some(id) = rng.pick(&uuids(
                    d,
                    "SELECT id FROM folders WHERE deleted_at IS NOT NULL ORDER BY id",
                )) {
                    let r = on_vfs!(d, |vfs| vfs
                        .restore_folder(id)
                        .map(|_| ())
                        .map_err(|e| e.to_string()));
                    ledger.note(format!("  restore folder {id}: {r:?}"));
                }
            }
        },
        13 => {
            let folders = live_folders(d);
            let (Some(id), Some(to)) = (rng.pick(&folders), rng.pick(&folders)) else {
                return;
            };
            if let Kind::New(new) = &d.kind {
                ledger.trashing(files_under(d, id), step);
                let sessions = new.state.sessions.lock().unwrap();
                let r = Vfs::new(&sessions[&new.silo.id])
                    .move_folder(id, to)
                    .map(|f| f.id);
                ledger.note(format!("  move folder {id} to {to}: {r:?}"));
            }
        }
        14 => {
            if let Some((id, hash)) = rng.pick(&files_with(d, false)) {
                ledger.trashing(vec![(id, hash)], step);
                let r = on_vfs!(d, |vfs| vfs.trash_file(id).map_err(|e| e.to_string()));
                ledger.note(format!("  trash file {id}: {r:?}"));
            }
        }
        15 => {
            if let Some(id) = rng.pick(&live_folders(d)) {
                ledger.trashing(files_under(d, id), step);
                let r = on_vfs!(d, |vfs| vfs.trash_folder(id).map_err(|e| e.to_string()));
                ledger.note(format!("  trash folder {id}: {r:?}"));
            }
        }
        16 => {
            if let Some((id, _)) = rng.pick(&files_with(d, true)) {
                let r = on_vfs!(d, |vfs| vfs
                    .restore_file(id)
                    .map(|_| ())
                    .map_err(|e| e.to_string()));
                ledger.note(format!("  restore file {id}: {r:?}"));
            }
        }
        17 => {
            if rng.below(3) == 0 {
                ledger.emptied.push(step);
                let in_trash: Vec<String> = d.with_conn(|conn| {
                    conn.prepare(
                        "SELECT f.content_hash FROM files f JOIN folders d ON d.id = f.folder_id
                          WHERE (f.deleted_at IS NOT NULL OR d.deleted_at IS NOT NULL)
                            AND f.content_hash IS NOT NULL",
                    )
                    .unwrap()
                    .query_map([], |r| r.get::<_, String>(0))
                    .unwrap()
                    .map(Result::unwrap)
                    .collect()
                });
                ledger.purged.extend(in_trash);
                let orphaned = on_vfs!(d, |vfs| vfs
                    .empty_trash()
                    .map(|(_, blobs)| blobs)
                    .map_err(|e| e.to_string()));
                ledger.note(format!("  emptied trash: {orphaned:?}"));
                // As both apps do: the local copy goes, storage keeps its
                // own until the sweep.
                for blob in orphaned.unwrap_or_default() {
                    if d.is_old() {
                        let _ = vault_v1::remove_blob_from_cache(&d.root, blob);
                    } else {
                        let _ = silentsilo_vault::remove_blob_from_cache(&d.root, blob);
                    }
                }
            }
        }
        _ => {
            let id = Uuid::from_u128(rng.pick(PASSWORD_IDS).unwrap());
            if rng.below(4) == 0 {
                let _ = on_vfs!(d, |vfs| vfs.delete_password(id).map_err(|e| e.to_string()));
            } else {
                let entry = serde_json::json!({
                    "id": id.to_string(),
                    "service": format!("site-{}", rng.below(3)),
                    "username": "alex",
                    "password": format!("pw-{}", rng.next()),
                    "url": "", "notes": "", "category": "General",
                    "created_at": 0, "updated_at": step, "type": "login",
                });
                let data = entry.to_string();
                let _ = on_vfs!(d, |vfs| vfs
                    .upsert_password(id, &data)
                    .map_err(|e| e.to_string()));
            }
        }
    }
}

/// Syncs until a whole round moves nothing.
async fn settle(devices: &[Device], seed: u64, ledger: &mut Ledger) {
    for _ in 0..12 {
        let mut moved = 0;
        for d in devices {
            let pass = d.pass().await;
            moved += pass.moved;
            ledger.check(pass, &format!("seed {seed}"));
        }
        if moved == 0 {
            return;
        }
    }
    panic!("seed {seed}: the devices never stopped exchanging changes");
}

/// What the 1.0.0 device shows differently, and what it could not apply.
struct OldDivergence {
    /// Lines of the tree, trash and passwords that differ from this build.
    rows: usize,
    /// Content this build keeps that the 1.0.0 device does not show.
    content_missing: usize,
    /// Records 1.0.0 could not apply: (written by this build, error, op).
    refused: Vec<(bool, String, String)>,
}

async fn run(seed: u64, before: usize, after: usize) -> OldDivergence {
    let storage = tempfile::tempdir().unwrap();
    let mut rng = Rng::new(seed);
    let vault_id = Uuid::new_v4();

    let first = Device::old(vault_id, None, storage.path());
    let keys = first.keys();
    let mut devices = vec![first];
    for _ in 0..2 {
        devices.push(Device::old(vault_id, Some(keys), storage.path()));
    }
    let mut ledger = Ledger::default();
    settle(&devices, seed, &mut ledger).await;
    for (i, d) in devices.iter().enumerate() {
        let id = d.with_conn(|conn| vfs_v1::device_id(conn).unwrap());
        ledger.note(format!("device {i} is {id}"));
    }

    // Everyone on 1.0.0, then two devices update in place.
    for step in 0..before {
        act(&devices, &mut rng, &mut ledger, step).await;
    }
    settle(&devices, seed, &mut ledger).await;
    for (i, d) in devices.iter_mut().enumerate().skip(1) {
        let (author, from) = d.with_conn(|conn| {
            let id = vfs_v1::device_id(conn).unwrap();
            (id, vfs_v1::chain_tip(conn, id).unwrap().0)
        });
        ledger.updated_from.insert(author, from);
        d.update(i);
    }
    ledger.note("devices 1 and 2 updated".into());

    for step in before..before + after {
        act(&devices, &mut rng, &mut ledger, step).await;
    }
    settle(&devices, seed, &mut ledger).await;

    // The devices on this build agree exactly.
    let reference = picture(&devices[1]);
    let other = picture(&devices[2]);
    for (what, a, b) in [
        ("folders", &reference.0, &other.0),
        ("files", &reference.1, &other.1),
        ("passwords", &reference.2, &other.2),
    ] {
        assert!(
            a == b,
            "seed {seed}: {what} differ between the updated devices\n  only on 1: {:#?}\n  only on 2: {:#?}",
            a.difference(b).collect::<Vec<_>>(),
            b.difference(a).collect::<Vec<_>>(),
        );
    }
    let clashes: Vec<String> = devices[1].with_conn(|conn| {
        conn.prepare(
            "SELECT lower(name) FROM files WHERE deleted_at IS NULL
              GROUP BY folder_id, lower(name) HAVING COUNT(*) > 1
             UNION ALL
             SELECT lower(name) FROM folders WHERE deleted_at IS NULL AND parent_id IS NOT NULL
              GROUP BY parent_id, lower(name) HAVING COUNT(*) > 1",
        )
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
    });
    assert!(clashes.is_empty(), "seed {seed}: names clash: {clashes:?}");

    // Every file shown opens with its bytes, on every device, unless its
    // content was deleted for good on purpose somewhere.
    for (i, d) in devices.iter().enumerate() {
        for (id, hash) in files_with(d, false) {
            let expected = hash.as_ref().and_then(|h| ledger.added.get(h));
            let excused = hash.as_ref().is_some_and(|h| ledger.may_be_gone(h));
            match read(d, id).await {
                Ok(bytes) => {
                    if let Some(expected) = expected {
                        assert_eq!(
                            &bytes, expected,
                            "seed {seed}: file {id} changed on device {i}"
                        );
                    }
                }
                Err(e) if excused && d.is_old() => {
                    println!("seed {seed}: 1.0.0 shows file {id}, deleted for good elsewhere: {e}");
                }
                Err(e) => panic!(
                    "seed {seed}: file {id} does not open on device {i} ({}): {e}",
                    if d.is_old() { "1.0.0" } else { "this build" },
                ),
            }
        }
    }

    // Nothing added is gone from this build unless deleted for good.
    let present = |d: &Device| -> HashSet<String> {
        files_with(d, false)
            .into_iter()
            .chain(files_with(d, true))
            .filter_map(|(_, hash)| hash)
            .collect()
    };
    let kept = present(&devices[1]);
    let lost: Vec<&String> = ledger
        .added
        .keys()
        .filter(|hash| !kept.contains(*hash) && !ledger.may_be_gone(hash))
        .collect();
    assert!(lost.is_empty(), "seed {seed}: content lost: {lost:?}");

    let old = picture(&devices[0]);
    let differ = |a: &BTreeSet<String>, b: &BTreeSet<String>| a.symmetric_difference(b).count();
    let on_old = present(&devices[0]);
    OldDivergence {
        rows: differ(&old.0, &reference.0)
            + differ(&old.1, &reference.1)
            + differ(&old.2, &reference.2),
        content_missing: kept.difference(&on_old).count(),
        refused: ledger.refused.into_values().collect(),
    }
}

fn seeds(default: std::ops::Range<u64>) -> Vec<u64> {
    match std::env::var("SILENTSILO_MIXED_SEED") {
        Ok(seed) => vec![seed.parse().expect("a number")],
        Err(_) => default.collect(),
    }
}

#[tokio::test]
async fn a_1_0_0_device_beside_updated_ones_loses_nothing_and_breaks_nothing() {
    work_dirs_for_this_test();
    for seed in seeds(1..5) {
        let old = run(seed, 60, 180).await;
        println!(
            "seed {seed}: the 1.0.0 device differs in {} rows and lacks {} contents this build keeps",
            old.rows, old.content_missing
        );
        for (by_this_build, error, op) in &old.refused {
            let author = if *by_this_build {
                "this build"
            } else {
                "1.0.0"
            };
            println!("seed {seed}: 1.0.0 refused a record {author} wrote: {error}\n  {op}");
        }
    }
}

/// Where both versions keep working copies and blob bookkeeping. 1.0.0 has
/// no switch for tests and writes under the user's local app data, so that
/// is pointed into `target/` as well, at the same place this build uses:
/// updating in place needs both versions to find the same cache.
fn work_dirs_for_this_test() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-work-mixed")
        .canonicalize()
        .unwrap_or_else(|_| {
            let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-work-mixed");
            std::fs::create_dir_all(&dir).unwrap();
            dir.canonicalize().unwrap()
        });
    let work = if cfg!(windows) {
        base.join("SilentSilo").join("work")
    } else {
        base.join("silentsilo").join("work")
    };
    // SAFETY: this binary holds one test, which sets these before it starts
    // anything that reads the environment on another thread.
    unsafe {
        std::env::set_var("LOCALAPPDATA", &base);
        std::env::set_var("XDG_CACHE_HOME", &base);
        std::env::set_var("SILENTSILO_TEST_WORK_BASE", &work);
    }
}

/// Which record a failed 1.0.0 replay stopped on. The failed replay kept
/// what it applied before that record, so this applies the batch again one
/// record at a time.
fn failing_record(conn: &Connection, mut records: Vec<vfs_v1::OpRecord>) -> Option<Refusal> {
    records.sort_by_key(|r| r.sort_key());
    records.iter().find_map(|record| {
        vfs_v1::apply_op(conn, record).err().map(|e| Refusal {
            error: e.to_string(),
            author: record.device_id,
            seq: record.seq,
            op: format!("{:?}", record.op),
        })
    })
}
