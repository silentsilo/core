//! Working copies an earlier SQLCipher wrote still open with this one, and
//! are used, not rebuilt: a rebuild after a crash would lose what only the
//! WAL holds. See `src/working_copies.rs` for what each case is.

use std::path::{Path, PathBuf};

use silentsilo_fixture::FIXTURE_DEVICE_SECRET;
use silentsilo_fixture::working_copies::{ONLY_IN_THE_WAL, SNAPSHOTTED, working_copies_dir};
use silentsilo_vault::{VaultPaths, VaultSession};

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let path = entry.unwrap().path();
        let target = to.join(path.file_name().unwrap());
        if path.is_dir() {
            copy_dir(&path, &target);
        } else {
            std::fs::copy(&path, &target).unwrap();
        }
    }
}

fn live_names(conn: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT name FROM files WHERE deleted_at IS NULL ORDER BY name")
        .unwrap();
    stmt.query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn eras() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(working_copies_dir())
        .expect("the working-copies directory must exist")
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    assert!(!dirs.is_empty(), "no working copies found");
    dirs
}

/// The case's silo in a fresh folder, its work files where this build
/// looks for them.
fn placed(case: &Path, scratch: &Path) -> VaultPaths {
    let root = scratch.join("silo");
    copy_dir(&case.join("silo"), &root);
    let paths = VaultPaths::new(root);
    silentsilo_vault::wipe_work_dir(&paths.root);
    copy_dir(&case.join("work"), &paths.work_dir());
    paths
}

#[test]
fn a_crashed_copy_is_adopted_with_its_wal() {
    for era in eras() {
        let name = era.file_name().unwrap().to_string_lossy().to_string();
        let scratch = tempfile::tempdir().unwrap();
        let paths = placed(&era.join("crashed"), scratch.path());

        let session =
            VaultSession::open_with_device_secret(paths.root.clone(), FIXTURE_DEVICE_SECRET)
                .unwrap_or_else(|e| panic!("{name}: the crashed silo does not open: {e}"));
        assert_eq!(
            live_names(&session.conn),
            [ONLY_IN_THE_WAL, SNAPSHOTTED],
            "{name}: the copy was rebuilt from the snapshot, losing what only its WAL held"
        );
        drop(session);
        silentsilo_vault::wipe_work_dir(&paths.root);
    }
}

#[test]
fn a_locked_copy_is_reused_as_it_stands() {
    for era in eras() {
        let name = era.file_name().unwrap().to_string_lossy().to_string();
        let scratch = tempfile::tempdir().unwrap();
        let paths = placed(&era.join("locked"), scratch.path());
        let key = std::fs::read(paths.db_key_path()).unwrap();

        let session =
            VaultSession::open_with_device_secret(paths.root.clone(), FIXTURE_DEVICE_SECRET)
                .unwrap_or_else(|e| panic!("{name}: the locked silo does not open: {e}"));
        assert_eq!(live_names(&session.conn), [SNAPSHOTTED], "{name}");
        // A copy that did not open would have been exported again, under a
        // new page key.
        assert_eq!(
            std::fs::read(paths.db_key_path()).unwrap(),
            key,
            "{name}: the kept copy was not reused"
        );
        drop(session);
        silentsilo_vault::wipe_work_dir(&paths.root);
    }
}
