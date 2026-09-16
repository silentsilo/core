//! What the sweep leaves in storage and what a pass puts back.
//!
//! A move is a new record over the same content id. Made on a device that
//! had not yet received an edit or a purge of that file, it points at content
//! every other device has stopped referencing, and a sweep there deleted it
//! after two sightings: the moved file then opened nowhere. Content an older
//! version's sweep deleted while a file here still points at it is put back
//! by any device that holds the bytes.

use std::path::{Path, PathBuf};

use silentsilo_app::files::{import_file, read_file};
use silentsilo_app::{AppEvent, AppState, Host, SyncReport, run_sync_pass};
use silentsilo_store::StoreConfig;
use silentsilo_vault::{BackupTarget, SiloEntry, TargetRole, VaultSession};
use silentsilo_vfs::Vfs;
use uuid::Uuid;

struct Targets(Vec<BackupTarget>);

impl Host for Targets {
    fn emit(&self, _event: AppEvent) {}
    fn warn(&self, _area: &str, _detail: &str) {}
    fn targets(&self, _silo_id: Uuid) -> Vec<BackupTarget> {
        self.0.clone()
    }
}

fn target(path: &Path) -> BackupTarget {
    BackupTarget {
        config: StoreConfig::Folder {
            path: path.to_path_buf(),
        },
        label: String::new(),
        role: TargetRole::Working,
    }
}

struct Device {
    _dir: tempfile::TempDir,
    state: AppState,
    silo: SiloEntry,
    host: Targets,
}

impl Device {
    fn new(vault_id: Uuid, keys: Option<&Device>, storage: &[&Path]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("silo");
        let session = match keys {
            Some(other) => {
                let sessions = other.state.sessions.lock().unwrap();
                let s = &sessions[&other.silo.id];
                VaultSession::provision_with_dek(
                    root.clone(),
                    vault_id,
                    "s",
                    s.dek.clone(),
                    s.kek.clone(),
                )
                .unwrap()
            }
            None => VaultSession::provision(root.clone(), vault_id, "s").unwrap(),
        };
        Vfs::new(&session).ensure_initialized().unwrap();
        let silo = SiloEntry {
            id: Uuid::new_v4(),
            name: "Sweep".into(),
            path: root,
            last_opened: 0,
            auto_lock_minutes: None,
        };
        let host = Targets(storage.iter().map(|p| target(p)).collect());
        let state = AppState::default();
        state.open_session(&host, silo.id, session).unwrap();
        Self {
            _dir: dir,
            state,
            silo,
            host,
        }
    }

    fn with<T>(&self, f: impl FnOnce(&Vfs<'_>, &rusqlite::Connection) -> T) -> T {
        let sessions = self.state.sessions.lock().unwrap();
        let session = &sessions[&self.silo.id];
        f(&Vfs::new(session), &session.conn)
    }

    /// A pass with the sweep due, as it is once a day.
    async fn pass(&self) -> SyncReport {
        self.with(|_, conn| {
            conn.execute(
                "DELETE FROM vault_meta WHERE key LIKE 'blob_sweep_at:%'",
                [],
            )
            .unwrap()
        });
        let report = run_sync_pass(&self.state, &self.host, &self.silo)
            .await
            .unwrap();
        assert!(
            report.targets.iter().all(|t| t.failed.is_none()),
            "{report:?}"
        );
        report
    }

    /// Moves this device's clock for the sweep past the grace period.
    fn age_candidates(&self) {
        self.with(|_, conn| {
            conn.execute(
                "UPDATE blob_gc_seen SET first_seen = first_seen - 31 * 24 * 60 * 60",
                [],
            )
            .unwrap()
        });
    }

    fn folder(&self, name: &str) -> Uuid {
        self.with(|vfs, _| {
            let root = vfs.root_folder_id().unwrap();
            vfs.create_folder(root, name).unwrap().id
        })
    }

    fn import(&self, folder: Uuid, name: &str, bytes: &[u8]) -> (Uuid, Uuid) {
        let file =
            import_file(&self.state, &self.silo, folder, &mut { bytes }, name, None).unwrap();
        (file.id, file.blob_id)
    }

    fn root(&self) -> PathBuf {
        self.silo.path.clone()
    }

    async fn read(&self, id: Uuid) -> Result<Vec<u8>, String> {
        read_file(&self.state, &self.host, &self.silo, id, 1 << 20)
            .await
            .map(|f| f.bytes)
    }
}

fn in_storage(storage: &Path, blob: Uuid) -> bool {
    storage.join(format!("blobs/{blob}.sslo")).is_file()
}

/// Three devices on one storage, with a folder every one of them knows.
async fn fleet(storage: &Path) -> (Device, Device, Device, Uuid) {
    let a = Device::new(Uuid::new_v4(), None, &[storage]);
    let vault_id = a.state.sessions.lock().unwrap()[&a.silo.id].vault_id;
    let b = Device::new(vault_id, Some(&a), &[storage]);
    let c = Device::new(vault_id, Some(&a), &[storage]);
    let docs = a.folder("Docs");
    for d in [&a, &b, &c] {
        d.pass().await;
    }
    (a, b, c, docs)
}

#[tokio::test]
async fn a_move_made_before_an_edit_arrived_still_opens() {
    let storage = tempfile::tempdir().unwrap();
    let (a, b, c, docs) = fleet(storage.path()).await;
    let moved = c.folder("Moved");
    let (file, old) = a.import(docs, "report.txt", b"first");
    for d in [&a, &b, &c] {
        d.pass().await;
    }

    // A replaces the content and its cache lets the old bytes go.
    let (same, new) = a.import(docs, "report.txt", b"second");
    assert_eq!(same, file);
    assert_ne!(new, old);
    silentsilo_vault::remove_blob_from_cache(&a.root(), old).unwrap();
    for _ in 0..3 {
        a.pass().await;
        b.pass().await;
    }
    assert!(
        in_storage(storage.path(), old),
        "swept while a device that had not synced could still point at it"
    );

    // C had not heard of the edit and moves the file it knows.
    let copy = c.with(|vfs, _| vfs.move_file(file, moved).unwrap().id);
    for _ in 0..2 {
        for d in [&c, &a, &b] {
            d.pass().await;
        }
    }
    assert_eq!(b.read(copy).await.unwrap(), b"first");
    // The edit stays on the row the move trashed, where it can be restored.
    let kept: String = a.with(|_, conn| {
        conn.query_row(
            "SELECT blob_id FROM files WHERE id = ?1 AND deleted_at IS NOT NULL",
            [file.to_string()],
            |r| r.get(0),
        )
        .unwrap()
    });
    assert_eq!(kept, new.to_string());
}

#[tokio::test]
async fn a_move_made_before_a_purge_arrived_still_opens() {
    let storage = tempfile::tempdir().unwrap();
    let (a, b, c, docs) = fleet(storage.path()).await;
    let moved = c.folder("Moved");
    let (file, blob) = a.import(docs, "report.txt", b"kept");
    for d in [&a, &b, &c] {
        d.pass().await;
    }

    a.with(|vfs, _| vfs.trash_file(file).unwrap());
    let (_, gone) = a.with(|vfs, _| vfs.empty_trash().unwrap());
    for blob in gone {
        silentsilo_vault::remove_blob_from_cache(&a.root(), blob).unwrap();
    }
    for _ in 0..3 {
        a.pass().await;
        b.pass().await;
    }
    assert!(in_storage(storage.path(), blob));

    // C moved the file before the purge reached it: the purge did not name
    // the copy, so the copy stays, and it has to open.
    let copy = c.with(|vfs, _| vfs.move_file(file, moved).unwrap().id);
    for _ in 0..2 {
        for d in [&c, &a, &b] {
            d.pass().await;
        }
    }
    assert_eq!(b.read(copy).await.unwrap(), b"kept");
}

#[tokio::test]
async fn content_purged_everywhere_goes_after_the_grace_and_is_never_put_back() {
    let storage = tempfile::tempdir().unwrap();
    let (a, b, _c, docs) = fleet(storage.path()).await;
    let (file, blob) = a.import(docs, "report.txt", b"gone");
    a.pass().await;
    b.pass().await;
    // B opened it, so B's cache holds the bytes.
    assert_eq!(b.read(file).await.unwrap(), b"gone");

    a.with(|vfs, _| vfs.trash_file(file).unwrap());
    let (_, gone) = a.with(|vfs, _| vfs.empty_trash().unwrap());
    for blob in gone {
        silentsilo_vault::remove_blob_from_cache(&a.root(), blob).unwrap();
    }
    a.pass().await;
    b.pass().await;
    a.pass().await;
    assert!(in_storage(storage.path(), blob), "deleted inside the grace");

    a.age_candidates();
    a.pass().await;
    assert!(!in_storage(storage.path(), blob), "never reclaimed");
    let report = b.pass().await;
    assert_eq!(report.blobs_restored, 0);
    assert!(
        !in_storage(storage.path(), blob),
        "a device still holding purged bytes put them back"
    );
}

#[tokio::test]
async fn content_another_version_swept_is_put_back_by_a_device_that_holds_it() {
    let storage = tempfile::tempdir().unwrap();
    let (a, b, _c, docs) = fleet(storage.path()).await;
    let (file, blob) = a.import(docs, "report.txt", b"still here");
    a.pass().await;
    b.pass().await;

    // What a 1.0.0 sweep does to content it has no row for.
    std::fs::remove_file(storage.path().join(format!("blobs/{blob}.sslo"))).unwrap();
    assert!(b.read(file).await.is_err());

    let report = a.pass().await;
    assert_eq!(report.blobs_restored, 1, "{report:?}");
    assert_eq!(b.read(file).await.unwrap(), b"still here");
}

#[tokio::test]
async fn content_one_copy_lost_comes_back_from_the_other() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let a = Device::new(Uuid::new_v4(), None, &[first.path(), second.path()]);
    let docs = a.folder("Docs");
    let (_, blob) = a.import(docs, "report.txt", b"twice");
    a.pass().await;
    assert!(in_storage(first.path(), blob) && in_storage(second.path(), blob));

    // Neither the first copy nor this device's cache has it any more.
    std::fs::remove_file(first.path().join(format!("blobs/{blob}.sslo"))).unwrap();
    silentsilo_vault::remove_blob_from_cache(&a.root(), blob).unwrap();

    let report = a.pass().await;
    assert_eq!(report.blobs_restored, 1, "{report:?}");
    assert!(in_storage(first.path(), blob));
}
