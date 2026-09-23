//! What a sync pass does, pinned against folder targets before any client
//! depends on this crate. Each test states a behaviour the desktop already
//! had when the pass moved here.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use silentsilo_app::{AppEvent, AppState, Host, SyncReport, run_sync_pass, sync_now};
use silentsilo_store::StoreConfig;
use silentsilo_vault::{BackupTarget, SiloEntry, TargetRole, VaultSession};
use silentsilo_vfs::Vfs;
use uuid::Uuid;

/// A client that records what it was told and serves a fixed target list.
#[derive(Default)]
struct FakeHost {
    events: Mutex<Vec<AppEvent>>,
    warnings: Mutex<Vec<String>>,
    targets: Mutex<Vec<BackupTarget>>,
}

impl Host for FakeHost {
    fn emit(&self, event: AppEvent) {
        self.events.lock().unwrap().push(event);
    }
    fn warn(&self, area: &str, detail: &str) {
        self.warnings
            .lock()
            .unwrap()
            .push(format!("[{area}] {detail}"));
    }
    fn targets(&self, _silo_id: Uuid) -> Vec<BackupTarget> {
        self.targets.lock().unwrap().clone()
    }
}

impl FakeHost {
    fn reports(&self) -> Vec<SyncReport> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                AppEvent::SyncReport(r) => Some(r.clone()),
                _ => None,
            })
            .collect()
    }

    fn vault_changed(&self) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, AppEvent::VaultChanged))
            .count()
    }
}

fn folder_target(path: PathBuf, role: TargetRole) -> BackupTarget {
    BackupTarget {
        config: StoreConfig::Folder { path },
        label: String::new(),
        role,
    }
}

/// One device: its silo folder, an app state holding it open, and a host.
struct Device {
    _dir: tempfile::TempDir,
    state: AppState,
    host: FakeHost,
    silo: SiloEntry,
}

impl Device {
    fn new(
        vault_id: Uuid,
        keys: Option<(silentsilo_crypto::MasterDek, silentsilo_crypto::ContentKek)>,
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
        Vfs::new(&session).ensure_initialized().unwrap();
        let silo = SiloEntry {
            id: Uuid::new_v4(),
            name: "Test".into(),
            path: root,
            last_opened: 0,
            auto_lock_minutes: None,
        };
        let state = AppState::default();
        let host = FakeHost::default();
        state.open_session(&host, silo.id, session).unwrap();
        Self {
            _dir: dir,
            state,
            host,
            silo,
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

    fn make_folder(&self, name: &str) {
        let sessions = self.state.sessions.lock().unwrap();
        let vfs = Vfs::new(&sessions[&self.silo.id]);
        let root = vfs.root_folder_id().unwrap();
        vfs.create_folder(root, name).unwrap();
    }

    fn folder_names(&self) -> Vec<String> {
        let sessions = self.state.sessions.lock().unwrap();
        let vfs = Vfs::new(&sessions[&self.silo.id]);
        let root = vfs.root_folder_id().unwrap();
        vfs.list_folder(root)
            .unwrap()
            .into_iter()
            .filter_map(|e| match e {
                silentsilo_core::VaultEntry::Folder(f) => Some(f.name),
                _ => None,
            })
            .collect()
    }

    fn pending(&self) -> usize {
        silentsilo_vfs::pending_count(&self.state.sessions.lock().unwrap()[&self.silo.id].conn)
            .unwrap()
    }

    async fn pass(&self) -> SyncReport {
        run_sync_pass(&self.state, &self.host, &self.silo)
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn a_silo_with_no_storage_reports_unconfigured_and_says_nothing() {
    let device = Device::new(Uuid::new_v4(), None);
    let report = device.pass().await;
    assert!(!report.configured);
    assert!(device.host.events.lock().unwrap().is_empty(), "no event");
}

#[tokio::test]
async fn a_pass_already_running_is_stood_down_without_an_event() {
    let storage = tempfile::tempdir().unwrap();
    let device = Device::new(Uuid::new_v4(), None);
    *device.host.targets.lock().unwrap() = vec![folder_target(
        storage.path().to_path_buf(),
        TargetRole::Working,
    )];
    device.state.sync_in_flight.store(true, Ordering::SeqCst);

    let report = device.pass().await;
    assert!(report.configured && report.skipped);
    assert!(device.host.events.lock().unwrap().is_empty());
    assert!(
        device.state.sync_in_flight.load(Ordering::SeqCst),
        "the running pass still holds the flag"
    );
}

#[tokio::test]
async fn a_pass_pushes_local_changes_reports_every_target_and_releases_the_flag() {
    let storage = tempfile::tempdir().unwrap();
    let device = Device::new(Uuid::new_v4(), None);
    *device.host.targets.lock().unwrap() = vec![folder_target(
        storage.path().to_path_buf(),
        TargetRole::Working,
    )];
    device.make_folder("Documents");
    assert!(device.pending() > 0);

    let report = device.pass().await;
    assert!(report.configured);
    assert!(report.ops_pushed > 0, "{report:?}");
    assert_eq!(report.silo_id, device.silo.id.to_string());
    assert_eq!(report.targets.len(), 1);
    assert!(report.targets[0].failed.is_none());
    assert_eq!(report.targets[0].ops_behind, 0);
    assert_eq!(device.pending(), 0, "delivered to every target");
    assert!(!device.state.sync_in_flight.load(Ordering::SeqCst));
    assert_eq!(device.host.reports().len(), 1, "one sync-report per pass");
    assert_eq!(device.host.vault_changed(), 0, "nothing arrived");
}

#[tokio::test]
async fn another_devices_changes_arrive_and_the_listing_is_told() {
    let storage = tempfile::tempdir().unwrap();
    let target = folder_target(storage.path().to_path_buf(), TargetRole::Working);

    let a = Device::new(Uuid::new_v4(), None);
    *a.host.targets.lock().unwrap() = vec![target.clone()];
    a.make_folder("From A");
    a.pass().await;

    let b = Device::new(a.vault_id(), Some(a.keys()));
    *b.host.targets.lock().unwrap() = vec![target];
    let report = b.pass().await;

    assert!(report.ops_applied > 0, "{report:?}");
    assert!(b.folder_names().contains(&"From A".to_string()));
    assert_eq!(b.host.vault_changed(), 1);
}

#[tokio::test]
async fn a_target_that_will_not_open_backs_off_and_waits_next_time() {
    // A folder path that is a file: the store opens, the writes fail. The
    // failure is recorded, so the next pass leaves the target alone instead
    // of retrying on every tick.
    let dir = tempfile::tempdir().unwrap();
    let not_a_folder = dir.path().join("file");
    std::fs::write(&not_a_folder, b"x").unwrap();

    let device = Device::new(Uuid::new_v4(), None);
    *device.host.targets.lock().unwrap() = vec![folder_target(not_a_folder, TargetRole::Working)];
    device.make_folder("Documents");

    let first = device.pass().await;
    assert!(first.targets[0].failed.is_some(), "{first:?}");
    assert!(device.pending() > 0, "nothing counts as delivered");

    let second = device.pass().await;
    assert!(second.targets[0].waiting, "{second:?}");
    assert!(second.targets[0].retry_in > 0);
}

#[tokio::test]
async fn pressing_sync_clears_the_backoff() {
    let dir = tempfile::tempdir().unwrap();
    let not_a_folder = dir.path().join("file");
    std::fs::write(&not_a_folder, b"x").unwrap();

    let device = Device::new(Uuid::new_v4(), None);
    *device.host.targets.lock().unwrap() = vec![folder_target(not_a_folder, TargetRole::Working)];
    device.make_folder("Documents");
    device.pass().await;

    let pressed = sync_now(&device.state, &device.host, &device.silo)
        .await
        .unwrap();
    assert!(!pressed.targets[0].waiting, "tried again: {pressed:?}");
}

#[tokio::test]
async fn a_never_delete_copy_on_the_old_key_does_not_send_the_device_to_rejoin() {
    // A key replacement leaves never-delete copies alone, so to a device on
    // the new key they look rotated. Listed first, it used to decide.
    let archive = tempfile::tempdir().unwrap();
    let working = tempfile::tempdir().unwrap();
    let device = Device::new(Uuid::new_v4(), None);
    *device.host.targets.lock().unwrap() = vec![
        folder_target(archive.path().to_path_buf(), TargetRole::Archive),
        folder_target(working.path().to_path_buf(), TargetRole::Working),
    ];
    device.make_folder("Documents");
    let first = device.pass().await;
    assert!(!first.needs_rejoin, "{first:?}");

    // What the old key left on the archive: its own envelope, and a record
    // newer than anything this device can read.
    let old = silentsilo_crypto::generate_dek();
    let store = silentsilo_store::FolderStore::new(archive.path().to_path_buf());
    std::fs::write(
        archive.path().join(silentsilo_sync::CONTENT_KEK_KEY),
        silentsilo_crypto::seal(b"old envelope", &old).unwrap(),
    )
    .unwrap();
    let record = silentsilo_vfs::OpRecord::authored(
        Uuid::new_v4(),
        9_999_999,
        Uuid::new_v4(),
        1_700_000_000,
        9_999_999,
        None,
        silentsilo_vfs::VaultOp::CreateFolder {
            id: Uuid::new_v4(),
            parent_id: Uuid::new_v4(),
            name: "old".into(),
        },
    );
    silentsilo_sync::push_ops(&store, &old, &[record])
        .await
        .unwrap();

    let second = device.pass().await;
    assert!(!second.needs_rejoin, "{second:?}");
    assert!(!second.key_material_replaced, "{second:?}");
}

#[tokio::test]
async fn one_target_failing_does_not_mark_the_other_as_behind() {
    let good = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("file");
    std::fs::write(&bad, b"x").unwrap();

    let device = Device::new(Uuid::new_v4(), None);
    *device.host.targets.lock().unwrap() = vec![
        folder_target(good.path().to_path_buf(), TargetRole::Working),
        folder_target(bad, TargetRole::Archive),
    ];
    device.make_folder("Documents");

    let report = device.pass().await;
    let ok = report.targets.iter().filter(|t| t.failed.is_none()).count();
    assert_eq!(ok, 1, "{report:?}");
    assert!(
        device.pending() > 0,
        "a record one target lacks is not delivered everywhere yet"
    );
}

#[tokio::test]
async fn a_pass_that_could_not_read_every_record_neither_sweeps_nor_compacts() {
    // A record nobody can read holds back everything after it, so this
    // device's picture of what is referenced is short. Content others
    // added would look orphaned to the sweep.
    let storage = tempfile::tempdir().unwrap();
    let device = Device::new(Uuid::new_v4(), None);
    let target = folder_target(storage.path().to_path_buf(), TargetRole::Working);
    let target_id = target.config.target_id();
    *device.host.targets.lock().unwrap() = vec![target];
    device.make_folder("Documents");

    let orphan = Uuid::new_v4();
    std::fs::create_dir_all(storage.path().join("blobs")).unwrap();
    std::fs::write(storage.path().join(format!("blobs/{orphan}.sslo")), b"x").unwrap();
    std::fs::create_dir_all(storage.path().join("ops")).unwrap();
    let junk = storage.path().join(format!(
        "ops/00000000000000000001-{}-{}.op",
        Uuid::new_v4(),
        Uuid::new_v4()
    ));
    std::fs::write(&junk, b"not a record").unwrap();

    let candidates = |device: &Device| {
        silentsilo_vfs::snapshot::gc_candidates(
            &device.state.sessions.lock().unwrap()[&device.silo.id].conn,
            target_id,
        )
        .unwrap()
    };

    let report = device.pass().await;
    assert_eq!(report.unreadable.len(), 1, "{report:?}");
    assert!(candidates(&device).is_empty());

    std::fs::remove_file(&junk).unwrap();
    let report = device.pass().await;
    assert!(report.unreadable.is_empty(), "{report:?}");
    assert!(candidates(&device).contains(&orphan));
}

#[tokio::test]
async fn records_sent_late_and_compacted_at_once_send_the_others_to_rebuild() {
    // C wrote a folder offline, under a Lamport value A and B had long
    // passed. Back online, it pushed and compacted in the same pass, before
    // B fetched the record. B's received mark was above the horizon, so it
    // never saw the folder and never knew it was missing anything.
    let storage = tempfile::tempdir().unwrap();
    let target = || folder_target(storage.path().to_path_buf(), TargetRole::Working);
    let a = Device::new(Uuid::new_v4(), None);
    let b = Device::new(a.vault_id(), Some(a.keys()));
    let c = Device::new(a.vault_id(), Some(a.keys()));
    for d in [&a, &b, &c] {
        *d.host.targets.lock().unwrap() = vec![target()];
    }
    a.make_folder("Shared");
    a.pass().await;
    b.pass().await;
    c.pass().await;

    c.make_folder("Offline");
    for i in 0..20 {
        a.make_folder(&format!("A{i}"));
    }
    a.pass().await;
    b.pass().await;

    c.pass().await;
    let dek = c.keys().0;
    let snapshot = {
        let sessions = c.state.sessions.lock().unwrap();
        let session = &sessions[&c.silo.id];
        let policy = silentsilo_vfs::CompactionPolicy {
            retain_seconds: 0,
            keep_recent: 1,
            min_records: 0,
        };
        silentsilo_sync::plan_compaction(&session.conn, session.vault_id, &policy, i64::MAX / 4)
            .unwrap()
            .expect("a horizon")
    };
    let store = silentsilo_store::FolderStore::new(storage.path().to_path_buf());
    silentsilo_sync::publish_compaction(&store, &dek, &snapshot, true)
        .await
        .unwrap();

    let report = b.pass().await;
    assert!(report.needs_rebuild, "{report:?}");
    assert!(a.pass().await.needs_rebuild, "A missed it too");
    assert!(
        !c.pass().await.needs_rebuild,
        "C agrees with its own snapshot"
    );

    let (snapshot, incoming) = silentsilo_sync::fetch_rebuild(&store, &dek)
        .await
        .unwrap()
        .unwrap();
    {
        let mut sessions = b.state.sessions.lock().unwrap();
        let session = sessions.get_mut(&b.silo.id).unwrap();
        silentsilo_sync::apply_rebuild(&mut session.conn, &snapshot, incoming).unwrap();
    }
    assert!(b.folder_names().contains(&"Offline".to_string()));
    assert!(!b.pass().await.needs_rebuild);
}

#[tokio::test]
async fn a_device_that_wrote_a_lot_offline_still_sees_it_fell_behind_a_snapshot() {
    // B last synced early. A moved on and compacted. B then wrote more
    // records offline than A has, so its own highest record is above A's
    // horizon, yet it never received what A folded into the snapshot.
    let storage = tempfile::tempdir().unwrap();
    let target = || folder_target(storage.path().to_path_buf(), TargetRole::Working);
    let a = Device::new(Uuid::new_v4(), None);
    let b = Device::new(a.vault_id(), Some(a.keys()));
    *a.host.targets.lock().unwrap() = vec![target()];
    *b.host.targets.lock().unwrap() = vec![target()];

    a.make_folder("Shared");
    a.pass().await;
    assert!(!b.pass().await.needs_rebuild);

    for i in 0..5 {
        a.make_folder(&format!("A{i}"));
    }
    a.pass().await;
    let dek = a.keys().0;
    let snapshot = {
        let sessions = a.state.sessions.lock().unwrap();
        let session = &sessions[&a.silo.id];
        let policy = silentsilo_vfs::CompactionPolicy {
            retain_seconds: 0,
            keep_recent: 1,
            min_records: 0,
        };
        silentsilo_sync::plan_compaction(&session.conn, session.vault_id, &policy, i64::MAX / 4)
            .unwrap()
            .expect("a horizon")
    };
    let store = silentsilo_store::FolderStore::new(storage.path().to_path_buf());
    silentsilo_sync::publish_compaction(&store, &dek, &snapshot, true)
        .await
        .unwrap();

    for i in 0..3 * snapshot.horizon {
        b.make_folder(&format!("B{i}"));
    }
    let report = b.pass().await;
    assert!(report.needs_rebuild, "{report:?}");
}

#[tokio::test]
async fn a_device_that_missed_a_new_recovery_code_does_not_put_the_old_one_back() {
    let storage = tempfile::tempdir().unwrap();
    let target = || folder_target(storage.path().to_path_buf(), TargetRole::Working);
    let a = Device::new(Uuid::new_v4(), None);
    let b = Device::new(a.vault_id(), Some(a.keys()));
    *a.host.targets.lock().unwrap() = vec![target()];
    *b.host.targets.lock().unwrap() = vec![target()];
    let dek = a.keys().0;
    let kek = a.state.sessions.lock().unwrap()[&a.silo.id].kek.clone();

    let (_, mut old) = silentsilo_vault::create_recovery_envelope(&dek, &kek).unwrap();
    old.created_at = 100;
    // The date is covered by the tag, so a test that moves it has to stamp
    // the envelope again or it is asking about a rejected one.
    old.authenticate(&kek);
    silentsilo_vault::save_recovery_envelope(&a.silo.path, &old).unwrap();
    silentsilo_vault::save_recovery_envelope(&b.silo.path, &old).unwrap();
    a.pass().await;
    b.pass().await;

    let (_, mut new) = silentsilo_vault::create_recovery_envelope(&dek, &kek).unwrap();
    new.created_at = 200;
    new.authenticate(&kek);
    silentsilo_vault::save_recovery_envelope(&a.silo.path, &new).unwrap();
    a.pass().await;
    b.pass().await;

    let store = silentsilo_store::FolderStore::new(storage.path().to_path_buf());
    let held = silentsilo_sync::fetch_recovery_envelope(&store)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.salt, new.salt);
    assert_eq!(
        silentsilo_vault::load_recovery_envelope(&b.silo.path)
            .unwrap()
            .salt,
        new.salt
    );
}

#[tokio::test]
async fn a_recovery_code_turned_off_stays_off_on_a_device_that_had_not_heard() {
    let storage = tempfile::tempdir().unwrap();
    let target = || folder_target(storage.path().to_path_buf(), TargetRole::Working);
    let a = Device::new(Uuid::new_v4(), None);
    let b = Device::new(a.vault_id(), Some(a.keys()));
    *a.host.targets.lock().unwrap() = vec![target()];
    *b.host.targets.lock().unwrap() = vec![target()];
    let dek = a.keys().0;
    let kek = a.state.sessions.lock().unwrap()[&a.silo.id].kek.clone();
    let store = silentsilo_store::FolderStore::new(storage.path().to_path_buf());

    let (_, mut old) = silentsilo_vault::create_recovery_envelope(&dek, &kek).unwrap();
    old.created_at = 100;
    old.authenticate(&kek);
    silentsilo_vault::save_recovery_envelope(&a.silo.path, &old).unwrap();
    silentsilo_vault::save_recovery_envelope(&b.silo.path, &old).unwrap();
    a.pass().await;
    b.pass().await;

    // A turns it off, as the desktop command does; B still holds the code.
    silentsilo_sync::mark_recovery_disabled(&store, &kek, 150)
        .await
        .unwrap();
    silentsilo_sync::revoke_recovery_envelope(&store)
        .await
        .unwrap();
    silentsilo_vault::clear_recovery_envelope(&a.silo.path);
    b.pass().await;
    a.pass().await;

    assert!(
        silentsilo_sync::fetch_recovery_envelope(&store)
            .await
            .unwrap()
            .is_none()
    );
    assert!(silentsilo_vault::load_recovery_envelope(&b.silo.path).is_err());

    // A code made after that is the silo's code again, everywhere.
    let (_, mut new) = silentsilo_vault::create_recovery_envelope(&dek, &kek).unwrap();
    new.created_at = 200;
    new.authenticate(&kek);
    silentsilo_vault::save_recovery_envelope(&b.silo.path, &new).unwrap();
    b.pass().await;
    a.pass().await;
    let held = silentsilo_sync::fetch_recovery_envelope(&store)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.salt, new.salt);
    assert_eq!(
        silentsilo_vault::load_recovery_envelope(&b.silo.path)
            .unwrap()
            .salt,
        new.salt
    );
}

impl Device {
    /// Imports a file, trashes it and purges it before any push, the way a
    /// file edited and then deleted between two passes goes. Returns the
    /// content it was the last reference to.
    fn import_and_purge(&self) -> Uuid {
        let root = {
            let sessions = self.state.sessions.lock().unwrap();
            Vfs::new(&sessions[&self.silo.id]).root_folder_id().unwrap()
        };
        let file = silentsilo_app::files::import_file(
            &self.state,
            &self.silo,
            root,
            &mut &b"edited, then deleted"[..],
            "note.md",
            None,
        )
        .unwrap();
        let blobs = {
            let sessions = self.state.sessions.lock().unwrap();
            let vfs = Vfs::new(&sessions[&self.silo.id]);
            vfs.trash_file(file.id).unwrap();
            vfs.empty_trash().unwrap().1
        };
        assert_eq!(blobs, vec![file.blob_id]);
        silentsilo_app::files::release_purged_blobs(
            &self.host,
            self.silo.id,
            &self.silo.path,
            &blobs,
        );
        file.blob_id
    }

    fn holds_blob(&self, blob: Uuid) -> bool {
        silentsilo_vault::VaultPaths::new(self.silo.path.clone())
            .blob_path(blob)
            .is_file()
    }
}

fn storage_holds_blob(storage: &std::path::Path, blob: Uuid) -> bool {
    let name = format!("{blob}.sslo");
    walk(storage)
        .iter()
        .any(|p| p.file_name().is_some_and(|n| n == name.as_str()))
}

fn walk(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// A device that has not seen this purge can still keep a file pointing at
/// this content (an edit the purge's author had not seen), so it has to
/// reach storage before it leaves the device. Removed at once, it was in
/// none of the copies and the file could never be opened again.
#[tokio::test]
async fn content_purged_before_it_was_pushed_still_reaches_storage_first() {
    let storage = tempfile::tempdir().unwrap();
    let device = Device::new(Uuid::new_v4(), None);
    *device.host.targets.lock().unwrap() = vec![folder_target(
        storage.path().to_path_buf(),
        TargetRole::Working,
    )];

    let blob = device.import_and_purge();
    assert!(device.holds_blob(blob), "kept until a copy has it");

    device.pass().await;
    assert!(storage_holds_blob(storage.path(), blob), "pushed");
    assert!(!device.holds_blob(blob), "and gone from here once it was");
}

#[tokio::test]
async fn content_purged_on_a_silo_with_no_storage_goes_at_once() {
    let device = Device::new(Uuid::new_v4(), None);
    let blob = device.import_and_purge();
    assert!(!device.holds_blob(blob), "no other device can want it");
}
