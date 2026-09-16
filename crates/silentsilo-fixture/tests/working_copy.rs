//! The working copy on this machine: what an installed 1.0.0 makes of what
//! this build leaves, and what an unlock and a snapshot cost.
//!
//! The benchmark is ignored by default: `cargo test -p silentsilo-fixture
//! --release --test working_copy -- --ignored --nocapture`, sized by
//! `SILENTSILO_BENCH_RECORDS`.

use std::path::{Path, PathBuf};
use std::time::Instant;

use silentsilo_vault::{VaultSession, wipe_plaintext_working_copy};
use silentsilo_vault_v1_0_0 as vault_v1;
use silentsilo_vfs::Vfs;
use uuid::Uuid;

fn add(vfs: &Vfs, name: &str) {
    let root = vfs.root_folder_id().unwrap();
    vfs.add_file(root, name, Uuid::new_v4(), 1, "hash", None, "key")
        .unwrap();
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

/// A silo this build crashed on, with a change made after the last
/// snapshot, and its working copy placed where 1.0.0 looks for one.
fn crashed_silo(dir: &Path, name_in_old_work_dir: &str) -> PathBuf {
    let root = dir.join("silo");
    let session = VaultSession::provision(root.clone(), Uuid::new_v4(), "secret").unwrap();
    let vfs = Vfs::new(&session);
    vfs.ensure_initialized().unwrap();
    add(&vfs, "snapshotted.pdf");
    session.backup_locally().unwrap();
    add(&vfs, "after the snapshot.pdf");
    let paths = session.paths.clone();

    // 1.0.0 reads the machine's real work base, not the test one. Copied
    // while the session is open, since closing checkpoints the WAL away.
    let old_work = vault_v1::work_dir_for(&root);
    std::fs::create_dir_all(&old_work).unwrap();
    let copy = |from: PathBuf, to: String| {
        if from.is_file() {
            std::fs::copy(from, old_work.join(to)).unwrap();
        }
    };
    let db = paths.db_path();
    for suffix in ["", "-wal", "-shm"] {
        copy(
            PathBuf::from(format!("{}{suffix}", db.display())),
            format!("{name_in_old_work_dir}{suffix}"),
        );
    }
    copy(paths.db_key_path(), "vault.key".into());
    assert!(
        old_work
            .join(format!("{name_in_old_work_dir}-wal"))
            .is_file()
    );
    drop(session);
    wipe_plaintext_working_copy(&paths);
    root
}

/// Downgrading after a crash: 1.0.0 never looks at the ciphered working
/// copy, opens the snapshot this build wrote, and loses only what was not
/// yet in it.
#[test]
fn after_a_crash_1_0_0_opens_the_silo_from_the_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let root = crashed_silo(dir.path(), "vault.sqlcipher");

    let old = vault_v1::VaultSession::open_with_device_secret(root.clone(), "secret").unwrap();
    let names = live_names(&old.conn);
    let paths = old.paths.clone();
    drop(old);
    vault_v1::wipe_plaintext_working_copy(&paths);

    assert_eq!(names, vec!["snapshotted.pdf".to_string()]);
}

#[test]
#[ignore = "benchmark: run with --release --ignored --nocapture"]
fn unlock_and_snapshot_benchmark() {
    let records: usize = std::env::var("SILENTSILO_BENCH_RECORDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50_000);
    let dir = tempfile::tempdir().unwrap();
    // Release builds ignore the test work base, so point it here.
    silentsilo_vault::set_work_base(dir.path().join("work"));
    let root = dir.path().join("silo");

    let session = VaultSession::provision(root.clone(), Uuid::new_v4(), "bench").unwrap();
    let dek = session.dek.clone();
    {
        let vfs = Vfs::new(&session);
        vfs.ensure_initialized().unwrap();
        let top = vfs.root_folder_id().unwrap();
        let mut folder = top;
        for i in 0..records {
            if i % 1000 == 0 {
                if i > 0 {
                    session.conn.execute_batch("COMMIT").unwrap();
                }
                session.conn.execute_batch("BEGIN").unwrap();
                if i % 500 == 0 {
                    folder = vfs.create_folder(top, &format!("folder {i}")).unwrap().id;
                }
            }
            vfs.add_file(
                folder,
                &format!("document number {i}.pdf"),
                Uuid::new_v4(),
                4096,
                "0123456789abcdef0123456789abcdef",
                Some("application/pdf"),
                "wrapped-key-placeholder-wrapped-key-placeholder",
            )
            .unwrap();
        }
        session.conn.execute_batch("COMMIT").unwrap();
    }

    let started = Instant::now();
    session.backup_locally().unwrap();
    let snapshot = started.elapsed();
    let snapshot_size = std::fs::metadata(session.paths.db_enc_path())
        .unwrap()
        .len();
    let paths = session.paths.clone();
    drop(session);
    wipe_plaintext_working_copy(&paths);

    let started = Instant::now();
    let reopened = VaultSession::open_with_dek(root.clone(), dek.clone()).unwrap();
    let unlock = started.elapsed();
    drop(reopened);

    // A crash: the working copy is left, the next unlock adopts it.
    let started = Instant::now();
    let adopted = VaultSession::open_with_dek(root, dek).unwrap();
    let adopt = started.elapsed();
    drop(adopted);
    wipe_plaintext_working_copy(&paths);

    println!(
        "{records} records, snapshot {snapshot_size} bytes: snapshot {snapshot:?}, unlock {unlock:?}, unlock adopting a crashed copy {adopt:?}"
    );
}
