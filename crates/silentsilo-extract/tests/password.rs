//! The extraction tool with the unlock password, for a silo that has one:
//! the promise of getting your files out holds for a silo with only a
//! password and the recovery code too.

use std::io::Write;
use std::process::{Command, Stdio};

use silentsilo_extract::{ExtractError, Secret, open_with};
use silentsilo_fixture::{FIXTURE_CODE, FIXTURE_PASSWORD, store_dir};

#[tokio::test]
async fn the_password_opens_what_the_code_opens() {
    let dir = tempfile::tempdir().unwrap();
    silentsilo_fixture::create_rich(dir.path()).await.unwrap();
    let store = silentsilo_extract::folder_store(&store_dir(dir.path()));

    let by_code = open_with(&*store, Secret::RecoveryCode(FIXTURE_CODE))
        .await
        .unwrap();
    let by_password = open_with(&*store, Secret::Password(FIXTURE_PASSWORD))
        .await
        .unwrap();
    assert_eq!(by_code.vault_id, by_password.vault_id);
    assert_eq!(
        silentsilo_extract::describe(&by_code),
        silentsilo_extract::describe(&by_password)
    );
    assert!(by_password.file_count() > 0);

    assert!(matches!(
        open_with(&*store, Secret::Password("wrong-horse-battery-staple")).await,
        Err(ExtractError::WrongPassword)
    ));
}

#[tokio::test]
async fn a_silo_without_a_password_says_to_use_the_code() {
    let dir = tempfile::tempdir().unwrap();
    silentsilo_fixture::create(dir.path()).await.unwrap();
    let store = silentsilo_extract::folder_store(&store_dir(dir.path()));
    assert!(matches!(
        open_with(&*store, Secret::Password(FIXTURE_PASSWORD)).await,
        Err(ExtractError::NoPassword)
    ));
}

fn run(args: &[&str], stdin: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_silentsilo-extract"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[tokio::test]
async fn the_binary_takes_the_password_on_standard_input() {
    let dir = tempfile::tempdir().unwrap();
    silentsilo_fixture::create_rich(dir.path()).await.unwrap();
    let from = store_dir(dir.path());
    let from = from.to_str().unwrap();

    let out = run(
        &["list", "--from", from, "--password"],
        &format!("{FIXTURE_PASSWORD}\n"),
    );
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(said.contains("password entries"), "{said}");

    let out = run(
        &["list", "--from", from, "--password"],
        "wrong-horse-battery-staple\n",
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("that password does not open this backup"),
        "{err}"
    );

    let out = run(
        &["list", "--from", from, "--password", "--code", "AAAA"],
        "",
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not both"));
}
