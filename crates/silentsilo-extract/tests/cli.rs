//! How the binary takes the recovery code: from standard input, or from
//! `--code` with a warning.

use std::io::Write;
use std::process::{Command, Stdio};

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

#[test]
fn the_code_is_read_from_standard_input() {
    let empty = tempfile::tempdir().unwrap();
    let from = empty.path().to_str().unwrap();

    let out = run(&["list", "--from", from], "AAAA-BBBB\n");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    // Past the code, on to the folder, which holds no silo.
    assert!(!err.contains("No recovery code"), "{err}");
    assert!(!err.contains("--code"), "{err}");

    let out = run(&["list", "--from", from], "");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("No recovery code was given"), "{err}");
}

#[test]
fn a_code_on_the_command_line_still_works_and_warns() {
    let empty = tempfile::tempdir().unwrap();
    let from = empty.path().to_str().unwrap();
    let out = run(&["list", "--from", from, "--code", "AAAA-BBBB"], "");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("shell history"), "{err}");
    assert!(!err.contains("No recovery code"), "{err}");
}
