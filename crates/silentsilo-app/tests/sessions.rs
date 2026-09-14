//! The session lifecycle's promises: a lock leaves no plaintext behind, and
//! the fourth silo closes the one used longest ago.

use std::sync::Mutex;

use silentsilo_app::{AppEvent, AppState, Host, MAX_OPEN_SILOS, open_scratch_dir};
use silentsilo_vault::{BackupTarget, VaultSession};
use silentsilo_vfs::Vfs;
use uuid::Uuid;

#[derive(Default)]
struct QuietHost(Mutex<Vec<String>>);

impl Host for QuietHost {
    fn emit(&self, _event: AppEvent) {}
    fn warn(&self, area: &str, detail: &str) {
        self.0.lock().unwrap().push(format!("[{area}] {detail}"));
    }
    fn targets(&self, _silo_id: Uuid) -> Vec<BackupTarget> {
        Vec::new()
    }
}

fn open(dir: &tempfile::TempDir, name: &str) -> VaultSession {
    let session = VaultSession::provision(dir.path().join(name), Uuid::new_v4(), "secret").unwrap();
    Vfs::new(&session).ensure_initialized().unwrap();
    session
}

#[test]
fn locking_leaves_no_working_copy_and_no_opened_file() {
    let dir = tempfile::tempdir().unwrap();
    let session = open(&dir, "silo");
    let root = session.paths.root.clone();
    let work = silentsilo_vault::work_dir_for(&root);

    // A file the user opened for viewing, written read-only as the app does.
    let scratch = open_scratch_dir(&root);
    std::fs::create_dir_all(&scratch).unwrap();
    let viewed = scratch.join("photo.jpg");
    std::fs::write(&viewed, b"plaintext").unwrap();
    let mut perms = std::fs::metadata(&viewed).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&viewed, perms).unwrap();
    assert!(work.exists(), "an open silo has a working copy");

    let state = AppState::default();
    let host = QuietHost::default();
    let id = Uuid::new_v4();
    state.open_session(&host, id, session).unwrap();
    state.close_session(&host, id).unwrap();

    assert!(!viewed.exists(), "the opened file is gone");
    assert!(!work.exists(), "the working copy is gone");
    assert!(
        root.join("vault.db.enc").is_file(),
        "the snapshot was written"
    );
    assert!(!state.session_is_open(id));
    let warnings = host.0.lock().unwrap().clone();
    assert!(warnings.is_empty(), "{warnings:?}");
}

#[test]
fn the_silo_after_the_limit_closes_the_one_used_longest_ago() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::default();
    let host = QuietHost::default();

    let ids: Vec<Uuid> = (0..MAX_OPEN_SILOS).map(|_| Uuid::new_v4()).collect();
    let mut roots = Vec::new();
    for (n, id) in ids.iter().enumerate() {
        let session = open(&dir, &format!("silo{n}"));
        roots.push(session.paths.root.clone());
        assert_eq!(state.open_session(&host, *id, session).unwrap(), None);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    // The first one is used again, so the second is now the stalest.
    state.touch(ids[0]);

    let extra = Uuid::new_v4();
    let evicted = state
        .open_session(&host, extra, open(&dir, "extra"))
        .unwrap();
    assert_eq!(evicted, Some(ids[1]));
    assert!(!state.session_is_open(ids[1]));
    assert!(
        !silentsilo_vault::work_dir_for(&roots[1]).exists(),
        "the closed one left no plaintext"
    );
    assert_eq!(state.open_silo_ids().len(), MAX_OPEN_SILOS);
}
