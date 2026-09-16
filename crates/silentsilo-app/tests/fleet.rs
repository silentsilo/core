//! Several devices on one silo, writing and syncing against the same storage
//! at once, in an order chosen by a seed. What must hold at the end, however
//! the passes interleaved:
//!
//! - every device shows the same tree, the same trash and the same passwords;
//! - no folder holds two entries whose names differ only in case;
//! - every file on every device opens, with the bytes that were added;
//! - nothing added is gone unless someone moved it to the trash, or trashed
//!   or moved a folder it was in, and the trash was emptied after that;
//! - no pass failed, held records back or found an unreadable object.
//!
//! Against folder storage always, and against MinIO, WebDAV and SFTP when
//! `scripts/test-local.ps1` (or CI) provides them. A failure prints its seed;
//! `SILENTSILO_FLEET_SEED` replays that one run.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Mutex;

use silentsilo_app::files::{import_file, read_file};
use silentsilo_app::{AppEvent, AppState, Host, SyncReport, run_sync_pass};
use silentsilo_store::StoreConfig;
use silentsilo_vault::{BackupTarget, SiloEntry, TargetRole, VaultSession};
use silentsilo_vfs::Vfs;
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

    fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        (!items.is_empty()).then(|| &items[self.below(items.len())])
    }
}

/// Names chosen to collide: by case, with a suffix the ranking produces,
/// and with letters outside ASCII.
const FOLDER_NAMES: &[&str] = &["Docs", "docs", "Photos", "x", "X", "x (2)", "Școală"];
const FILE_NAMES: &[&str] = &["a.txt", "A.txt", "a (2).txt", "report.pdf", "notă.md"];
const PASSWORD_IDS: &[u128] = &[1, 2, 3, 4];

// ── Devices ─────────────────────────────────────────────────────────

struct FleetHost {
    targets: Vec<BackupTarget>,
    warnings: Mutex<Vec<String>>,
}

impl Host for FleetHost {
    fn emit(&self, _event: AppEvent) {}
    fn warn(&self, area: &str, detail: &str) {
        self.warnings
            .lock()
            .unwrap()
            .push(format!("{area}: {detail}"));
    }
    fn targets(&self, _silo_id: Uuid) -> Vec<BackupTarget> {
        self.targets.clone()
    }
}

thread_local! {
    /// The step the run on this thread is at, read as the day.
    static DAY: Cell<usize> = const { Cell::new(0) };
}

struct Device {
    _dir: tempfile::TempDir,
    state: AppState,
    silo: SiloEntry,
    host: FleetHost,
    /// The day of this device's last pass.
    swept_on: Cell<usize>,
}

impl Device {
    fn new(
        vault_id: Uuid,
        keys: Option<(silentsilo_crypto::MasterDek, silentsilo_crypto::ContentKek)>,
        targets: Vec<BackupTarget>,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("silo");
        let session = match keys {
            Some((dek, kek)) => {
                VaultSession::provision_with_dek(root.clone(), vault_id, "secret", dek, kek)
                    .unwrap()
            }
            None => VaultSession::provision(root.clone(), vault_id, "secret").unwrap(),
        };
        let silo = SiloEntry {
            id: Uuid::new_v4(),
            name: "Fleet".into(),
            path: root,
            last_opened: 0,
            auto_lock_minutes: None,
        };
        let state = AppState::default();
        let host = FleetHost {
            targets,
            warnings: Mutex::new(Vec::new()),
        };
        state.open_session(&host, silo.id, session).unwrap();
        Self {
            _dir: dir,
            state,
            silo,
            host,
            swept_on: Cell::new(DAY.get()),
        }
    }

    fn keys(&self) -> (silentsilo_crypto::MasterDek, silentsilo_crypto::ContentKek) {
        let sessions = self.state.sessions.lock().unwrap();
        let s = &sessions[&self.silo.id];
        (s.dek.clone(), s.kek.clone())
    }

    fn vault_id(&self) -> Uuid {
        self.state.sessions.lock().unwrap()[&self.silo.id].vault_id
    }

    fn with<T>(&self, f: impl FnOnce(&Vfs<'_>, &rusqlite::Connection) -> T) -> T {
        let sessions = self.state.sessions.lock().unwrap();
        let session = &sessions[&self.silo.id];
        f(&Vfs::new(session), &session.conn)
    }

    /// A pass that sweeps, where the apps sweep once a day. A step of the
    /// run stands for a day, so the sweep's grace runs out for content
    /// unreferenced for that many steps, and a device that has not synced
    /// for fewer can still point at it.
    async fn pass(&self) -> SyncReport {
        let today = DAY.get();
        let days = today.saturating_sub(self.swept_on.replace(today));
        self.with(|_, conn| {
            conn.execute(
                "DELETE FROM vault_meta WHERE key LIKE 'blob_sweep_at:%'",
                [],
            )
            .unwrap();
            conn.execute(
                "UPDATE blob_gc_seen SET first_seen = first_seen - ?1",
                [days as i64 * 24 * 60 * 60],
            )
            .unwrap();
        });
        run_sync_pass(&self.state, &self.host, &self.silo)
            .await
            .unwrap_or_else(|e| panic!("a pass failed: {e}"))
    }
}

/// One row of what a device shows, comparable across devices.
fn picture(device: &Device) -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    device.with(|vfs, conn| {
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
        let passwords = vfs.list_passwords().unwrap().into_iter().collect();
        (folders, files, passwords)
    })
}

// ── What was done, for judging what may be gone ─────────────────────

#[derive(Default)]
struct Ledger {
    /// Content added, by hash, with its bytes.
    added: HashMap<String, Vec<u8>>,
    /// Step at which each hash first became something the trash could take.
    trashable_since: HashMap<String, usize>,
    /// Steps at which some device emptied its trash.
    emptied: Vec<usize>,
    /// Every folder each hash was put under, with that folder's ancestors
    /// on the device that put it there.
    lived_under: HashMap<String, HashSet<Uuid>>,
    /// First step at which each folder was trashed, by any device.
    folder_trashed: HashMap<Uuid, usize>,
    /// What each device did, for a failure to be read.
    trace: Vec<String>,
    /// Content a later add over the same name replaced in place: gone by
    /// design, not through the trash.
    replaced: HashSet<String>,
    /// Content that sat in the trash of a device when that device emptied
    /// it: the one way content may be gone for good.
    purged: HashSet<String>,
    /// Which file each content went into.
    hash_file: HashMap<String, Uuid>,
    /// First step at which a device sent each file to the trash, directly,
    /// by trashing or moving a folder it was in, or by moving the file. An
    /// edit another device makes to such a file lands on the trashed row,
    /// and goes when that trash is emptied: by design, and known.
    file_trashed_at: HashMap<Uuid, usize>,
}

impl Ledger {
    fn trashable(&mut self, hash: String, step: usize) {
        self.trashable_since.entry(hash).or_insert(step);
    }

    fn lives_under(&mut self, hash: &str, chain: Vec<Uuid>) {
        self.lived_under
            .entry(hash.to_string())
            .or_default()
            .extend(chain);
    }

    /// Gone is allowed once the trash could hold it and was emptied after.
    fn may_be_gone(&self, hash: &str) -> bool {
        if self.replaced.contains(hash) || self.purged.contains(hash) {
            return true;
        }
        self.hash_file
            .get(hash)
            .and_then(|file| self.file_trashed_at.get(file))
            .is_some_and(|since| self.emptied.iter().any(|at| at > since))
    }
}

/// A folder and its ancestors on one device.
fn chain(device: &Device, folder_id: Uuid) -> Vec<Uuid> {
    device.with(|_vfs, conn| {
        let mut out = Vec::new();
        let mut at = Some(folder_id.to_string());
        while let Some(id) = at {
            out.push(Uuid::parse_str(&id).unwrap());
            at = conn
                .query_row("SELECT parent_id FROM folders WHERE id = ?1", [&id], |r| {
                    r.get::<_, Option<String>>(0)
                })
                .ok()
                .flatten();
        }
        out
    })
}

/// Hashes of the files under a folder (itself included) on one device.
/// Ids of the files under a folder (itself included) on one device.
fn files_under(device: &Device, folder_id: Uuid) -> Vec<Uuid> {
    device.with(|_vfs, conn| {
        let Ok(path) = conn.query_row(
            "SELECT path FROM folders WHERE id = ?1",
            [folder_id.to_string()],
            |r| r.get::<_, String>(0),
        ) else {
            return Vec::new();
        };
        let below = format!("{}/*", path.trim_end_matches('/'));
        conn.prepare(
            "SELECT f.id FROM files f JOIN folders d ON d.id = f.folder_id
              WHERE d.id = ?1 OR d.path GLOB ?2",
        )
        .unwrap()
        .query_map(rusqlite::params![folder_id.to_string(), below], |r| {
            r.get::<_, String>(0)
        })
        .unwrap()
        .map(|id| Uuid::parse_str(&id.unwrap()).unwrap())
        .collect()
    })
}

fn hashes_under(device: &Device, folder_id: Uuid) -> Vec<String> {
    device.with(|_vfs, conn| {
        let Ok(path) = conn.query_row(
            "SELECT path FROM folders WHERE id = ?1",
            [folder_id.to_string()],
            |r| r.get::<_, String>(0),
        ) else {
            return Vec::new();
        };
        let below = format!("{}/*", path.trim_end_matches('/'));
        conn.prepare(
            "SELECT f.content_hash FROM files f JOIN folders d ON d.id = f.folder_id
              WHERE (d.id = ?1 OR d.path GLOB ?2) AND f.content_hash IS NOT NULL",
        )
        .unwrap()
        .query_map(rusqlite::params![folder_id.to_string(), below], |r| {
            r.get::<_, String>(0)
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
    })
}

fn live_folders(device: &Device) -> Vec<Uuid> {
    device.with(|vfs, _| {
        vfs.list_all_folders()
            .unwrap()
            .into_iter()
            .filter(|f| f.path != "/Inbox")
            .map(|f| f.id)
            .collect()
    })
}

fn files_with(device: &Device, trashed: bool) -> Vec<(Uuid, Option<String>)> {
    device.with(|_vfs, conn| {
        conn.prepare(&format!(
            "SELECT id, content_hash FROM files WHERE deleted_at IS {} NULL",
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

// ── One run ─────────────────────────────────────────────────────────

async fn act(devices: &[Device], rng: &mut Rng, ledger: &mut Ledger, step: usize) {
    let which = rng.below(devices.len());
    let d = &devices[which];
    DAY.set(step);
    let choice = rng.below(20);
    ledger
        .trace
        .push(format!("step {step}: device {which} action {choice}"));
    match choice {
        // Several devices syncing at the same moment.
        0..=3 => {
            let a = &devices[rng.below(devices.len())];
            let b = &devices[rng.below(devices.len())];
            if std::ptr::eq(a, b) {
                a.pass().await;
            } else {
                tokio::join!(a.pass(), b.pass());
            }
        }
        4 => {
            let all: Vec<_> = devices.iter().map(|d| d.pass()).collect();
            futures_join_all(all).await;
        }
        5..=6 => {
            if let Some(parent) = rng.pick(&live_folders(d)).copied() {
                let name = rng.pick(FOLDER_NAMES).unwrap();
                let _ = d.with(|vfs, _| vfs.create_folder(parent, name));
            }
        }
        7..=10 => {
            let Some(folder) = rng.pick(&live_folders(d)).copied() else {
                return;
            };
            let name = rng.pick(FILE_NAMES).unwrap().to_string();
            // Over a name already in the folder, the file is replaced where
            // it is: what it held before may go, which is not a loss.
            let replaced: Vec<String> = d.with(|vfs, _| {
                vfs.list_folder(folder)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|e| match e {
                        silentsilo_core::VaultEntry::File(f)
                            if f.name.to_lowercase() == name.to_lowercase() =>
                        {
                            f.content_hash
                        }
                        _ => None,
                    })
                    .collect()
            });
            ledger.replaced.extend(replaced);
            let len = 64 + rng.below(3000);
            let bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            if let Ok(file) = import_file(
                &d.state,
                &d.silo,
                folder,
                &mut bytes.as_slice(),
                &name,
                None,
            ) && let Some(hash) = file.content_hash
            {
                ledger.hash_file.insert(hash.clone(), file.id);
                ledger.lives_under(&hash, chain(d, folder));
                ledger.trace.push(format!(
                    "  added {hash} as {} id {} in {folder}",
                    file.name, file.id
                ));
                ledger.added.insert(hash, bytes);
            }
        }
        11 => {
            if let Some((id, _)) = rng.pick(&files_with(d, false)).cloned() {
                let name = rng.pick(FILE_NAMES).unwrap();
                let _ = d.with(|vfs, _| vfs.rename_file(id, name));
            } else if let Some(id) = rng.pick(&live_folders(d)).copied() {
                let name = rng.pick(FOLDER_NAMES).unwrap();
                let _ = d.with(|vfs, _| vfs.rename_folder(id, name));
            }
        }
        12 => {
            let folders = live_folders(d);
            if let (Some((id, hash)), Some(to)) = (
                rng.pick(&files_with(d, false)).cloned(),
                rng.pick(&folders).copied(),
            ) {
                ledger.file_trashed_at.entry(id).or_insert(step);
                if let Some(hash) = hash {
                    ledger.lives_under(&hash, chain(d, to));
                    ledger.trashable(hash, step);
                }
                let r = d.with(|vfs, _| vfs.move_file(id, to).map(|f| f.id));
                ledger
                    .trace
                    .push(format!("  move file {id} to {to}: {r:?}"));
            }
        }
        13 => {
            let folders = live_folders(d);
            if let (Some(id), Some(to)) = (rng.pick(&folders).copied(), rng.pick(&folders).copied())
            {
                ledger.folder_trashed.entry(id).or_insert(step);
                for file in files_under(d, id) {
                    ledger.file_trashed_at.entry(file).or_insert(step);
                }
                let to_chain = chain(d, to);
                for hash in hashes_under(d, id) {
                    ledger.lives_under(&hash, to_chain.clone());
                    ledger.trashable(hash, step);
                }
                let r = d.with(|vfs, _| vfs.move_folder(id, to).map(|f| f.id));
                ledger
                    .trace
                    .push(format!("  move folder {id} to {to}: {r:?}"));
            }
        }
        14 => {
            if let Some((id, hash)) = rng.pick(&files_with(d, false)).cloned() {
                ledger.file_trashed_at.entry(id).or_insert(step);
                if let Some(hash) = hash {
                    ledger.trashable(hash, step);
                }
                let r = d.with(|vfs, _| vfs.trash_file(id));
                ledger.trace.push(format!("  trash file {id}: {r:?}"));
            }
        }
        15 => {
            if let Some(id) = rng.pick(&live_folders(d)).copied() {
                ledger.folder_trashed.entry(id).or_insert(step);
                for file in files_under(d, id) {
                    ledger.file_trashed_at.entry(file).or_insert(step);
                }
                for hash in hashes_under(d, id) {
                    ledger.trashable(hash, step);
                }
                let r = d.with(|vfs, _| vfs.trash_folder(id));
                ledger.trace.push(format!("  trash folder {id}: {r:?}"));
            }
        }
        16 => {
            if let Some((id, _)) = rng.pick(&files_with(d, true)).cloned() {
                let r = d.with(|vfs, _| vfs.restore_file(id).map(|_| ()));
                ledger.trace.push(format!("  restore file {id}: {r:?}"));
            }
        }
        17 => {
            if rng.below(3) == 0 {
                ledger.emptied.push(step);
                // Whatever that device shows in the trash, directly or inside
                // a trashed folder, is what emptying it removes.
                let in_trash: Vec<String> = d.with(|_vfs, conn| {
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
                let orphaned = d.with(|vfs, _| vfs.empty_trash().map(|(_, blobs)| blobs));
                ledger.trace.push(format!("  emptied trash: {orphaned:?}"));
                // As the apps do: the local copies go, storage keeps its own
                // until the sweep.
                for blob in orphaned.unwrap_or_default() {
                    let _ = silentsilo_vault::remove_blob_from_cache(&d.silo.path, blob);
                }
            }
        }
        _ => {
            let id = Uuid::from_u128(*rng.pick(PASSWORD_IDS).unwrap());
            if rng.below(4) == 0 {
                let _ = d.with(|vfs, _| vfs.delete_password(id));
            } else {
                let entry = serde_json::json!({
                    "id": id.to_string(),
                    "service": format!("site-{}", rng.below(3)),
                    "username": "alex",
                    "password": format!("pw-{}", rng.next()),
                    "url": "", "notes": "", "category": "General",
                    "created_at": 0, "updated_at": step, "type": "login",
                });
                let _ = d.with(|vfs, _| vfs.upsert_password(id, &entry.to_string()));
            }
        }
    }
}

async fn futures_join_all(passes: Vec<impl std::future::Future<Output = SyncReport>>) {
    let mut set = Vec::new();
    for pass in passes {
        set.push(Box::pin(pass));
    }
    // Polled together on this task: the passes interleave at every await.
    let mut pending: Vec<_> = set.into_iter().map(Some).collect();
    std::future::poll_fn(|cx| {
        let mut all_done = true;
        for slot in pending.iter_mut() {
            if let Some(fut) = slot {
                if fut.as_mut().poll(cx).is_ready() {
                    *slot = None;
                } else {
                    all_done = false;
                }
            }
        }
        if all_done {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
}

/// Sync until a whole round moves nothing, checking every report on the way.
async fn settle(devices: &[Device], seed: u64) {
    for _ in 0..12 {
        let mut moved = 0;
        for d in devices {
            let report = d.pass().await;
            assert!(
                report.unreadable.is_empty() && report.held_back == 0,
                "seed {seed}: {report:?}"
            );
            assert!(
                !report.needs_rebuild && !report.needs_rejoin,
                "seed {seed}: {report:?}"
            );
            assert!(
                report.targets.iter().all(|t| t.failed.is_none()),
                "seed {seed}: {report:?}"
            );
            moved += report.ops_pushed + report.ops_applied + report.blobs_uploaded;
        }
        if moved == 0 {
            return;
        }
    }
    panic!("seed {seed}: the devices never stopped exchanging changes");
}

async fn run(seed: u64, steps: usize, targets: impl Fn() -> Vec<BackupTarget>) {
    let mut rng = Rng::new(seed);
    DAY.set(0);
    let first = Device::new(Uuid::new_v4(), None, targets());
    let keys = first.keys();
    let vault_id = first.vault_id();
    let mut devices = vec![first];
    for _ in 0..2 {
        devices.push(Device::new(vault_id, Some(keys.clone()), targets()));
    }
    for d in &devices {
        d.with(|vfs, _| vfs.ensure_initialized()).unwrap();
    }
    // The first device publishes the silo; the others arrive on top of it.
    settle(&devices, seed).await;

    let mut ledger = Ledger::default();
    for step in 0..steps {
        act(&devices, &mut rng, &mut ledger, step).await;
    }
    settle(&devices, seed).await;

    // One picture everywhere.
    let reference = picture(&devices[0]);
    for (i, d) in devices.iter().enumerate().skip(1) {
        let other = picture(d);
        let differ = |what: &str, a: &BTreeSet<String>, b: &BTreeSet<String>| {
            let only_first: Vec<_> = a.difference(b).collect();
            let only_other: Vec<_> = b.difference(a).collect();
            assert!(
                only_first.is_empty() && only_other.is_empty(),
                "seed {seed}: {what} differ on device {i}\n  only on device 0: {only_first:#?}\n  only on device {i}: {only_other:#?}\n{}",
                if std::env::var("SILENTSILO_FLEET_TRACE").is_ok() {
                    ledger.trace.join("\n")
                } else {
                    String::new()
                }
            );
        };
        differ("folders", &reference.0, &other.0);
        differ("files", &reference.1, &other.1);
        differ("passwords", &reference.2, &other.2);
    }

    for d in &devices {
        // No two live entries in one folder whose names fold to the same.
        let clashes: Vec<String> = d.with(|_vfs, conn| {
            conn.prepare(
                "SELECT folder_id, lower(name), COUNT(*) FROM files
                  WHERE deleted_at IS NULL GROUP BY 1, 2 HAVING COUNT(*) > 1
                 UNION ALL
                 SELECT parent_id, lower(name), COUNT(*) FROM folders
                  WHERE deleted_at IS NULL AND parent_id IS NOT NULL
                  GROUP BY 1, 2 HAVING COUNT(*) > 1",
            )
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .collect()
        });
        assert!(clashes.is_empty(), "seed {seed}: names clash: {clashes:?}");

        // Every file opens, with the bytes that went in.
        for (id, hash) in files_with(d, false) {
            let shown = read_file(&d.state, &d.host, &d.silo, id, 1 << 20)
                .await
                .unwrap_or_else(|e| panic!("seed {seed}: file {id} does not open: {e}"));
            if let Some(expected) = hash.as_ref().and_then(|h| ledger.added.get(h)) {
                assert_eq!(&shown.bytes, expected, "seed {seed}: file {id} changed");
            }
        }
    }

    // Nothing added is gone unless the trash was emptied after it could
    // have gone there.
    let present: HashSet<String> = files_with(&devices[0], false)
        .into_iter()
        .chain(files_with(&devices[0], true))
        .filter_map(|(_, hash)| hash)
        .collect();
    let lost: BTreeMap<&String, usize> = ledger
        .added
        .keys()
        .filter(|hash| !present.contains(*hash) && !ledger.may_be_gone(hash))
        .map(|hash| (hash, 0))
        .collect();
    assert!(
        lost.is_empty(),
        "seed {seed}: content lost: {lost:?}\n{}",
        ledger.trace.join("\n")
    );
}

fn folder_target(dir: &std::path::Path) -> BackupTarget {
    BackupTarget {
        config: StoreConfig::Folder {
            path: dir.to_path_buf(),
        },
        label: String::new(),
        role: TargetRole::Working,
    }
}

fn seeds(default: std::ops::Range<u64>) -> Vec<u64> {
    match std::env::var("SILENTSILO_FLEET_SEED") {
        Ok(seed) => vec![seed.parse().expect("a number")],
        Err(_) => default.collect(),
    }
}

#[tokio::test]
async fn three_devices_on_one_folder_agree_and_lose_nothing() {
    for seed in seeds(1..9) {
        let storage = tempfile::tempdir().unwrap();
        let path = storage.path().to_path_buf();
        run(seed, 220, || vec![folder_target(&path)]).await;
    }
}

#[tokio::test]
async fn three_devices_on_two_copies_agree_and_lose_nothing() {
    for seed in seeds(100..104) {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let (a, b) = (first.path().to_path_buf(), second.path().to_path_buf());
        run(seed, 160, || vec![folder_target(&a), folder_target(&b)]).await;
    }
}

#[tokio::test]
async fn three_devices_on_minio_agree_and_lose_nothing() {
    let Ok(endpoint) = std::env::var("SILENTSILO_TEST_S3_ENDPOINT") else {
        silentsilo_testkit::skip_or_fail("SILENTSILO_TEST_S3_ENDPOINT is not set");
        return;
    };
    for seed in seeds(200..202) {
        let prefix = format!("fleet-{}", Uuid::new_v4());
        let config = silentsilo_core::S3Config {
            endpoint: endpoint.clone(),
            region: "us-east-1".into(),
            bucket: std::env::var("SILENTSILO_TEST_S3_BUCKET")
                .unwrap_or_else(|_| "vault-test".into()),
            prefix,
            access_key_id: std::env::var("SILENTSILO_TEST_S3_KEY")
                .unwrap_or_else(|_| "silentsilo".into()),
            secret_access_key: std::env::var("SILENTSILO_TEST_S3_SECRET")
                .unwrap_or_else(|_| "silentsilo123".into()),
            path_style: true,
        };
        run(seed, 120, || {
            vec![BackupTarget {
                config: StoreConfig::S3(config.clone()),
                label: String::new(),
                role: TargetRole::Working,
            }]
        })
        .await;
    }
}

#[tokio::test]
async fn three_devices_on_webdav_agree_and_lose_nothing() {
    let Ok(base) = std::env::var("SILENTSILO_TEST_WEBDAV_URL") else {
        silentsilo_testkit::skip_or_fail("SILENTSILO_TEST_WEBDAV_URL is not set");
        return;
    };
    for seed in seeds(300..302) {
        let config = silentsilo_store::WebDavConfig {
            url: format!("{}/fleet-{}", base.trim_end_matches('/'), Uuid::new_v4()),
            username: std::env::var("SILENTSILO_TEST_WEBDAV_USER")
                .unwrap_or_else(|_| "silentsilo".into()),
            password: std::env::var("SILENTSILO_TEST_WEBDAV_PASSWORD")
                .unwrap_or_else(|_| "silentsilo123".into()),
        };
        run(seed, 120, || {
            vec![BackupTarget {
                config: StoreConfig::WebDav(config.clone()),
                label: String::new(),
                role: TargetRole::Working,
            }]
        })
        .await;
    }
}

#[tokio::test]
async fn three_devices_on_sftp_agree_and_lose_nothing() {
    let Ok(host) = std::env::var("SILENTSILO_TEST_SFTP_HOST") else {
        silentsilo_testkit::skip_or_fail("SILENTSILO_TEST_SFTP_HOST is not set");
        return;
    };
    let port: u16 = std::env::var("SILENTSILO_TEST_SFTP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(2222);
    let fingerprint = silentsilo_store::probe_host_key(&host, port)
        .await
        .expect("the SFTP server's key");
    for seed in seeds(400..402) {
        let config = silentsilo_store::SftpConfig {
            host: host.clone(),
            port,
            username: std::env::var("SILENTSILO_TEST_SFTP_USER")
                .unwrap_or_else(|_| "silentsilo".into()),
            auth: silentsilo_store::SftpAuth::Password {
                password: std::env::var("SILENTSILO_TEST_SFTP_PASSWORD")
                    .unwrap_or_else(|_| "silentsilo123".into()),
            },
            path: format!("silo/fleet-{}", Uuid::new_v4()),
            host_fingerprint: Some(fingerprint.clone()),
        };
        run(seed, 100, || {
            vec![BackupTarget {
                config: StoreConfig::Sftp(config.clone()),
                label: String::new(),
                role: TargetRole::Working,
            }]
        })
        .await;
    }
}
