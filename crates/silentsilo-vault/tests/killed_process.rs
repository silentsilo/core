//! A real kill, not a dropped session: after a lock, a child process
//! unlocks the kept working copy, writes and is killed with its database
//! open, as a crash or a power cut would leave it. What it leaves must hold
//! nothing readable, and the next unlock must still have the change.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use silentsilo_vault::{VaultPaths, VaultSession, wipe_plaintext_working_copy};
use uuid::Uuid;

const ROOT_VAR: &str = "SILENTSILO_KILLED_CHILD_ROOT";
const SECRET: &str = "killed-process-secret";
const NAME: &str = "Killed-Process-Marker-Contract.pdf";

/// The child's half. Does nothing unless the parent started it.
#[test]
fn child_writes_then_waits_to_be_killed() {
    let Some(root) = std::env::var_os(ROOT_VAR) else {
        return;
    };
    let session = VaultSession::open_with_device_secret(PathBuf::from(root), SECRET).unwrap();
    session
        .conn
        .execute("INSERT INTO names VALUES (?1)", [NAME])
        .unwrap();
    // libtest prints the test name on the same line first.
    println!("READY");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn names(session: &VaultSession) -> Vec<String> {
    let mut stmt = session.conn.prepare("SELECT name FROM names").unwrap();
    stmt.query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn work_files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| (e.path(), std::fs::read(e.path()).unwrap()))
        .collect()
}

#[test]
fn a_killed_session_leaves_nothing_readable_and_loses_nothing() {
    if std::env::var_os(ROOT_VAR).is_some() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("silo");
    let vault_id = Uuid::new_v4();
    let session = VaultSession::provision(root.clone(), vault_id, SECRET).unwrap();
    session
        .conn
        .execute_batch(&format!(
            "CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT);
             INSERT INTO vault_meta VALUES ('vault_id', '{vault_id}');
             CREATE TABLE names (name TEXT);"
        ))
        .unwrap();
    session.seal_for_lock().unwrap();
    let paths = VaultPaths::new(root.clone());
    drop(session);
    wipe_plaintext_working_copy(&paths);
    let locked_key = std::fs::read(paths.db_key_path()).unwrap();

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "child_writes_then_waits_to_be_killed",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ROOT_VAR, &root)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let ready = BufReader::new(stdout)
        .lines()
        .map_while(Result::ok)
        .any(|line| line.trim_end().ends_with("READY"));
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(ready, "the child never wrote");

    let files = work_files(&paths.work_dir());
    assert!(
        files.iter().any(|(p, _)| p.ends_with("vault.sqlcipher")),
        "the kill must leave a working copy behind"
    );
    for (path, bytes) in &files {
        let shown = path.display();
        assert!(!contains(bytes, NAME.as_bytes()), "{shown} holds the name");
        assert!(
            !bytes.starts_with(b"SQLite format 3\0"),
            "{shown} is plain SQLite"
        );
    }

    assert_eq!(
        std::fs::read(paths.db_key_path()).unwrap(),
        locked_key,
        "the child did not reuse the kept copy"
    );
    let reopened = VaultSession::open_with_device_secret(root, SECRET).unwrap();
    assert_eq!(names(&reopened), vec![NAME.to_string()]);
    drop(reopened);
    silentsilo_vault::wipe_work_dir(&paths.root);
}
