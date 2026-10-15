//! Every byte of every committed fixture, pinned by `fixtures/SHA256SUMS`.
//!
//! `compatibility.rs` proves this build reads what a fixture holds. That
//! proof is worth nothing once the fixture is regenerated to match the
//! build, which is the easiest way to make a red test green. A fixture is
//! a release's format: it is never regenerated, edited or removed. A new
//! format era gets a new directory, and its lines are appended to the
//! manifest in the commit that adds it.
//!
//! The manifest is `sha256sum` output, so `sha256sum -c SHA256SUMS` in
//! `fixtures/` checks it too. Bytes are hashed as stored, and the crate's
//! `.gitattributes` marks the fixtures binary, so a Windows checkout with
//! `core.autocrlf` cannot turn an LF into CRLF and fail this on its own.

use std::collections::BTreeMap;

use silentsilo_fixture::{SUMS_FILE, fixtures_dir, sums};

#[test]
fn no_committed_fixture_has_changed_by_a_byte() {
    let fixtures = fixtures_dir();
    let manifest = std::fs::read_to_string(fixtures.join(SUMS_FILE))
        .unwrap_or_else(|e| panic!("cannot read fixtures/{SUMS_FILE}: {e}"));
    let mut pinned: BTreeMap<String, String> = BTreeMap::new();
    for line in manifest.lines().filter(|l| !l.trim().is_empty()) {
        let (hash, path) = line
            .split_once("  ")
            .unwrap_or_else(|| panic!("not a sha256sum line in {SUMS_FILE}: {line:?}"));
        assert!(
            pinned.insert(path.to_string(), hash.to_string()).is_none(),
            "{path} is listed twice in {SUMS_FILE}"
        );
    }

    let mut dirs: Vec<_> = std::fs::read_dir(&fixtures)
        .expect("the fixtures directory must exist")
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    assert!(!dirs.is_empty(), "no fixtures found");

    let mut problems = Vec::new();
    for dir in &dirs {
        for line in sums(&fixtures, dir).expect("cannot hash a fixture") {
            let (hash, path) = line.split_once("  ").unwrap();
            match pinned.remove(path) {
                Some(expected) if expected == hash => {}
                Some(_) => problems.push(format!("changed: {path}")),
                None => problems.push(format!("not in {SUMS_FILE}: {path}")),
            }
        }
    }
    problems.extend(pinned.keys().map(|path| format!("missing: {path}")));

    assert!(
        problems.is_empty(),
        "{}\n\nOld fixtures are never changed: each one is the format a release \
         shipped, and regenerating or editing it hides the break from the people \
         who will hit it. Fix the code, not the fixture. A new format era gets a \
         new fixture directory; append its lines to fixtures/{SUMS_FILE} with\n\
         cargo run -p silentsilo-fixture -- sums crates/silentsilo-fixture/fixtures/v<version>",
        problems.join("\n")
    );
}
