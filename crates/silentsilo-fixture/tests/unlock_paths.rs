//! Every other way into a fixture besides the recovery code, and the
//! content behind it.
//!
//! `compatibility.rs` opens each silo with its recovery code. An installed
//! app mostly does not: it opens with the device secret until a key is
//! enrolled, then with a key. The fixtures written from `v1.10.1` on hold
//! keys and real content, so those paths have golden bytes too.

use std::path::{Path, PathBuf};

use silentsilo_fixture::{FIXTURE_CODE, FIXTURE_DEVICE_SECRET, fixture_wrap_key, silo_dir};
use silentsilo_vault::VaultSession;

fn fixture_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(silentsilo_fixture::fixtures_dir())
        .expect("the fixtures directory must exist")
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

/// The fixtures with real content and keys: those with an
/// `expected-content.txt`.
fn rich_dirs() -> Vec<PathBuf> {
    let dirs: Vec<PathBuf> = fixture_dirs()
        .into_iter()
        .filter(|dir| dir.join("expected-content.txt").is_file())
        .collect();
    assert!(
        !dirs.is_empty(),
        "no fixture with content: the suite is passing by having nothing to check"
    );
    dirs
}

fn name(dir: &Path) -> String {
    dir.file_name().unwrap().to_string_lossy().to_string()
}

/// `expected.txt` without what the silo folder does not answer for: the
/// op count (compaction prunes the store, not the local log) and the
/// activity log, which lives in storage.
fn expected_tree(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("expected.txt"))
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with("ops count=") && !l.starts_with("activity "))
        .map(str::to_string)
        .collect()
}

fn tree(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .filter(|l| !l.starts_with("ops count="))
        .collect()
}

/// A copy of the fixture's silo folder: opening one writes a working copy
/// for its path, and the committed silo stays as the release wrote it.
fn copied_silo(dir: &Path) -> (tempfile::TempDir, PathBuf) {
    let scratch = tempfile::tempdir().unwrap();
    let silo = scratch.path().join("silo");
    copy_dir(&silo_dir(dir), &silo).unwrap();
    (scratch, silo)
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let dest = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &dest)?;
        } else {
            std::fs::copy(entry.path(), &dest)?;
        }
    }
    Ok(())
}

fn dek_from_code(silo: &Path) -> silentsilo_crypto::MasterDek {
    let envelope = silentsilo_vault::load_recovery_envelope(silo).unwrap();
    silentsilo_vault::unwrap_with_code(&envelope, FIXTURE_CODE).unwrap()
}

#[test]
fn the_device_secret_opens_every_silo_no_key_was_enrolled_on() {
    for dir in fixture_dirs() {
        let name = name(&dir);
        let (_scratch, silo) = copied_silo(&dir);
        let opened = VaultSession::open_with_device_secret(silo.clone(), FIXTURE_DEVICE_SECRET);

        if silentsilo_vault::is_fido_enrolled(&silo) {
            // Enrolment moved `master.dek.enc` under the first key, so the
            // secret opens nothing, and that key opens it instead.
            assert!(
                opened.is_err(),
                "{name}: the device secret still opens a silo with keys"
            );
            let keys = silentsilo_vault::load_fido_keys(&silo).unwrap();
            let marker = silentsilo_vault::read_marker(&silo).unwrap();
            let first = fixture_wrap_key(marker.vault_id, &keys.keys[0]).unwrap();
            let dek = silentsilo_vault::load_dek(&silo, &first)
                .unwrap_or_else(|e| panic!("{name}: the first key no longer opens it: {e}"));
            assert_eq!(dek.as_bytes(), dek_from_code(&silo).as_bytes(), "{name}");
            continue;
        }

        let session =
            opened.unwrap_or_else(|e| panic!("{name}: the device secret no longer opens it: {e}"));
        let actual = silentsilo_fixture::digest_and_close(session).unwrap();
        assert_eq!(
            expected_tree(&dir),
            tree(actual),
            "{name}: the silo opened with its device secret reads differently.\n\
             The fixture is the released format. Fix the code, not the fixture."
        );
        assert!(
            VaultSession::open_with_device_secret(silo, "another-secret").is_err(),
            "{name}: opened with the wrong secret"
        );
    }
}

#[test]
fn every_enrolled_key_opens_the_silo_with_its_fixed_wrap_key() {
    for dir in rich_dirs() {
        let name = name(&dir);
        let (_scratch, silo) = copied_silo(&dir);

        let marker = silentsilo_vault::read_marker(&silo)
            .unwrap_or_else(|e| panic!("{name}: silo.json no longer reads: {e}"));
        let keys = silentsilo_vault::load_fido_keys(&silo)
            .unwrap_or_else(|e| panic!("{name}: keys/fido.json no longer loads: {e}"));
        let kinds: Vec<&str> = keys.active().map(|k| k.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                silentsilo_vault::KIND_FIDO2,
                silentsilo_vault::KIND_SECURE_ENCLAVE,
                silentsilo_vault::KIND_ANDROID_KEYSTORE
            ],
            "{name}"
        );
        let unconfirmed: Vec<&str> = keys
            .keys
            .iter()
            .filter(|k| k.unconfirmed)
            .map(|k| k.kind.as_str())
            .collect();
        assert_eq!(
            unconfirmed,
            [silentsilo_vault::KIND_ANDROID_KEYSTORE],
            "{name}"
        );

        for key in keys.active() {
            let wrap = fixture_wrap_key(marker.vault_id, key).unwrap();
            // The unwrap `open_with_fido_wrapped` does, without the call
            // after it that retires a device secret in the OS credential
            // store: a test has no business there.
            let dek = silentsilo_vault::unwrap_dek_hex(&key.wrapped_dek, &wrap)
                .unwrap_or_else(|e| panic!("{name}: the {} key no longer opens: {e}", key.kind));
            let session = VaultSession::open_with_dek(silo.clone(), dek).unwrap();
            assert_eq!(session.vault_id, marker.vault_id, "{name}");
            let actual = silentsilo_fixture::digest_and_close(session).unwrap();
            assert_eq!(
                expected_tree(&dir),
                tree(actual),
                "{name}: the silo opened with its {} key reads differently",
                key.kind
            );
            assert!(
                silentsilo_vault::unwrap_dek_hex(&key.wrapped_dek, &[0x42; 32]).is_err(),
                "{name}: the {} key opened under the wrong wrap key",
                key.kind
            );
        }
    }
}

#[tokio::test]
async fn the_published_keys_are_the_enrolled_ones_without_local_state() {
    for dir in rich_dirs() {
        let name = name(&dir);
        let store = silentsilo_store::StoreConfig::Folder {
            path: silentsilo_fixture::store_dir(&dir),
        }
        .open()
        .unwrap();
        let manifest = silentsilo_sync::read_manifest(&*store)
            .await
            .unwrap()
            .unwrap();
        let (_scratch, silo) = copied_silo(&dir);
        assert_eq!(
            silentsilo_vault::read_marker(&silo).unwrap().vault_id,
            manifest.vault_id,
            "{name}: silo.json names another silo than storage does"
        );

        let local = silentsilo_vault::load_fido_keys(&silo).unwrap();
        let published = silentsilo_sync::fetch_key_envelopes(&*store).await.unwrap();
        assert_eq!(published.len(), local.keys.len(), "{name}");
        for key in &local.keys {
            let envelope = published
                .iter()
                .find(|p| p.credential_id == key.credential_id)
                .unwrap_or_else(|| panic!("{name}: the {} key is not published", key.kind));
            assert!(!envelope.unconfirmed, "{name}: local state was published");
            assert_eq!(envelope.wrapped_dek, key.wrapped_dek, "{name}");
        }
        for object in store.list("keys/").await.unwrap() {
            let bytes = store.get(&object.key).await.unwrap();
            assert!(
                !String::from_utf8_lossy(&bytes).contains("unconfirmed"),
                "{name}: {} carries a local-only field",
                object.key
            );
        }
    }
}

#[test]
fn the_silo_folder_holds_the_same_content_as_storage() {
    for dir in rich_dirs() {
        let name = name(&dir);
        let local = silo_dir(&dir).join("blobs");
        let stored = silentsilo_fixture::store_dir(&dir).join("blobs");
        let mut names: Vec<_> = std::fs::read_dir(&local)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        let mut stored_names: Vec<_> = std::fs::read_dir(&stored)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        stored_names.sort();
        assert_eq!(names, stored_names, "{name}");
        assert!(!names.is_empty(), "{name}: no content");
        for file in names {
            assert_eq!(
                std::fs::read(local.join(&file)).unwrap(),
                std::fs::read(stored.join(&file)).unwrap(),
                "{name}: {file:?} differs between the silo and storage"
            );
        }
    }
}

#[tokio::test]
async fn every_blob_entry_and_inbox_item_decrypts_to_what_was_written() {
    for dir in rich_dirs() {
        let name = name(&dir);
        let expected = std::fs::read_to_string(dir.join("expected-content.txt")).unwrap();
        let expected: Vec<&str> = expected.lines().filter(|l| !l.is_empty()).collect();
        let actual = silentsilo_fixture::content_from_store(&dir, FIXTURE_CODE)
            .await
            .unwrap_or_else(|e| panic!("{name}: the content no longer opens: {e}"));
        assert_eq!(
            expected, actual,
            "{name}: this build reads the content of a silo written by {name} differently.\n\
             The fixture is the released format. Fix the code, not the fixture."
        );
        for kind in ["file", "password", "attachment", "inbox", "key"] {
            assert!(
                actual
                    .iter()
                    .any(|l| l.starts_with(&format!("content {kind} "))),
                "{name}: no {kind} in the content"
            );
        }
        assert!(
            actual.iter().all(|l| !l.contains("opens=false")),
            "{name}: a key envelope no longer opens"
        );
        assert!(
            actual
                .iter()
                .all(|l| !l.starts_with("content inbox refused")),
            "{name}: the inbox item is refused"
        );
    }
}
