//! What core 1.10.0, the release desktop 1.5.0 and the phone apps beside it
//! ship, makes of what this build writes. Its own code answers, pulled in
//! by tag, not a description of it.
//!
//! Read twice: the committed fixtures with keys and content, frozen when
//! they were written, and a silo this build writes now, so a change made
//! after them is caught too. Both must read on 1.10.0 exactly as on this
//! build: the manifest, the recovery envelope and both its tags, the sealed
//! records (and the snapshot, in the compacted twin), the key envelopes,
//! `keys/fido.json` with its local-only `unconfirmed`, every blob, every
//! password entry and the inbox. None of these changed since 1.10.0, so
//! there is nothing 1.10.0 may refuse; when one does change, a test here
//! has to say it refuses by name.

use std::path::{Path, PathBuf};

use silentsilo_crypto_v1_10_0 as crypto_old;
use silentsilo_fixture::{FIXTURE_CODE, fixture_wrap_key, silo_dir, store_dir};
use silentsilo_store_v1_10_0 as store_old;
use silentsilo_sync_v1_10_0 as sync_old;
use silentsilo_vault_v1_10_0 as vault_old;
use silentsilo_vfs_v1_10_0 as vfs_old;

/// The committed rich fixtures, and one written now.
async fn sources() -> (Vec<(String, PathBuf)>, tempfile::TempDir) {
    let mut out: Vec<(String, PathBuf)> = std::fs::read_dir(silentsilo_fixture::fixtures_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.join("expected-content.txt").is_file())
        .map(|path| {
            (
                path.file_name().unwrap().to_string_lossy().to_string(),
                path,
            )
        })
        .collect();
    out.sort();
    assert!(!out.is_empty(), "no fixture with content");

    let fresh = tempfile::tempdir().unwrap();
    let now = fresh.path().join("now");
    silentsilo_fixture::create_rich(&now)
        .await
        .expect("this build writes a rich silo");
    out.push(("written now".into(), now));
    (out, fresh)
}

fn old_store(root: &Path) -> Box<dyn store_old::ObjectStore> {
    store_old::StoreConfig::Folder {
        path: store_dir(root),
    }
    .open()
    .unwrap()
}

fn without_activity(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .filter(|l| !l.starts_with("activity "))
        .collect()
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

/// A key as 1.10.0 parsed it, as this build's type, for the fixture's
/// wrap key.
fn as_current(key: &vault_old::StoredFidoCredential) -> silentsilo_vault::StoredFidoCredential {
    serde_json::from_value(serde_json::to_value(key).unwrap()).unwrap()
}

#[tokio::test]
async fn a_1_10_0_device_restores_from_storage_written_today() {
    let (sources, _fresh) = sources().await;
    for (name, root) in sources {
        let store = old_store(&root);
        let manifest = sync_old::read_manifest(&*store)
            .await
            .unwrap_or_else(|e| panic!("{name}: 1.10.0 cannot read the manifest: {e}"))
            .unwrap();
        let envelope = sync_old::fetch_recovery_envelope(&*store)
            .await
            .unwrap()
            .unwrap();
        let dek = vault_old::unwrap_with_code(&envelope, FIXTURE_CODE)
            .unwrap_or_else(|e| panic!("{name}: 1.10.0 cannot open the recovery envelope: {e}"));
        let kek = vault_old::unwrap_kek_bytes(
            &sync_old::fetch_content_kek(&*store).await.unwrap().unwrap(),
            &dek,
        )
        .unwrap_or_else(|e| panic!("{name}: 1.10.0 cannot open the content KEK: {e}"));
        assert!(
            envelope.is_authentic(&kek) && envelope.is_authentic_now(&kek, &dek),
            "{name}: 1.10.0 does not trust the recovery envelope's tags"
        );

        // A joining 1.10.0 device: its own replay, its own digest.
        let scratch = tempfile::tempdir().unwrap();
        let session = vault_old::VaultSession::provision_with_dek(
            scratch.path().join("silo"),
            manifest.vault_id,
            "a-1-10-0-device",
            dek.clone(),
            kek.clone(),
        )
        .unwrap();
        vfs_old::Vfs::new(&session).ensure_initialized().unwrap();
        let snapshot = sync_old::latest_snapshot(&*store, &dek)
            .await
            .unwrap_or_else(|e| panic!("{name}: 1.10.0 cannot read the snapshot: {e}"));
        let horizon = snapshot.as_ref().map(|s| s.horizon).unwrap_or(0);
        if let Some(snapshot) = snapshot {
            vfs_old::snapshot::restore(&session.conn, &snapshot).unwrap();
        }
        let ops = sync_old::fetch_all_ops_above(&*store, &dek, horizon)
            .await
            .unwrap_or_else(|e| panic!("{name}: 1.10.0 cannot open the records: {e}"));
        vfs_old::replay(&session.conn, ops)
            .unwrap_or_else(|e| panic!("{name}: 1.10.0 refuses a record: {e}"));

        let ours = silentsilo_fixture::digest_from_store(&root, FIXTURE_CODE)
            .await
            .unwrap();
        assert_eq!(
            vfs_old::digest(&session.conn).unwrap(),
            without_activity(ours),
            "{name}: 1.10.0 rebuilds another silo from the same storage"
        );

        // Every file and entry opens on 1.10.0 with the bytes this build reads.
        let content = silentsilo_fixture::content_from_store(&root, FIXTURE_CODE)
            .await
            .unwrap();
        let staging = tempfile::tempdir().unwrap();
        let mut stmt = session
            .conn
            .prepare(
                "SELECT fo.path || '::' || f.name, f.blob_id, f.blob_key, f.content_hash
                   FROM files f JOIN folders fo ON fo.id = f.folder_id",
            )
            .unwrap();
        let rows: Vec<(String, String, String, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        drop(stmt);
        assert!(!rows.is_empty(), "{name}: no files");
        for (path, blob_id, blob_key, hash) in rows {
            let blob_id = uuid::Uuid::parse_str(&blob_id).unwrap();
            let sealed = staging.path().join(format!("{blob_id}.sslo"));
            let plain = staging.path().join(format!("{blob_id}.plain"));
            sync_old::fetch_blob_to_file(&*store, blob_id, &sealed)
                .await
                .unwrap();
            let key = crypto_old::unwrap_content_key(&blob_key, &kek)
                .unwrap_or_else(|e| panic!("{name}: 1.10.0 cannot unwrap the key of {path}: {e}"));
            crypto_old::decrypt_file(&sealed, &plain, &key, blob_id, &hash)
                .unwrap_or_else(|e| panic!("{name}: 1.10.0 cannot open {path}: {e}"));
            let hash = blake3::hash(&std::fs::read(&plain).unwrap()).to_hex();
            assert!(
                content.iter().any(|l| l
                    .strip_prefix("content file ")
                    .is_some_and(|l| l.starts_with(&format!("{path} ")))
                    && l.ends_with(&format!("blake3={hash}"))),
                "{name}: {path} opens on 1.10.0 with other bytes"
            );
        }
        for json in vfs_old::Vfs::new(&session).list_passwords().unwrap() {
            let id = serde_json::from_str::<serde_json::Value>(&json).unwrap()["id"]
                .as_str()
                .unwrap()
                .to_string();
            let line = format!(
                "content password {id} blake3={}",
                blake3::hash(json.as_bytes()).to_hex()
            );
            assert!(
                content.contains(&line),
                "{name}: 1.10.0 reads entry {id} otherwise"
            );
        }

        // Each key envelope gives 1.10.0 the same vault key.
        let envelopes = sync_old::fetch_key_envelopes(&*store).await.unwrap();
        assert_eq!(envelopes.len(), 3, "{name}: 1.10.0 skipped an envelope");
        for key in &envelopes {
            let wrap = fixture_wrap_key(manifest.vault_id, &as_current(key)).unwrap();
            let opened = vault_old::unwrap_dek_hex(&key.wrapped_dek, &wrap)
                .unwrap_or_else(|e| panic!("{name}: 1.10.0 cannot open the {} key: {e}", key.kind));
            assert_eq!(opened.as_bytes(), dek.as_bytes(), "{name}: {}", key.kind);
        }

        // And it imports the photo waiting in the inbox.
        let scan = sync_old::inbox::scan_inbox(&*store, manifest.vault_id, &kek)
            .await
            .unwrap();
        assert!(scan.refused.is_empty(), "{name}: {:?}", scan.refused);
        assert_eq!(
            scan.ready
                .iter()
                .map(|i| i.name.as_str())
                .collect::<Vec<_>>(),
            ["IMG_0001.jpg"],
            "{name}"
        );

        drop(session);
    }
}

#[tokio::test]
async fn a_1_10_0_device_opens_the_silo_folder_written_today_and_keeps_its_keys() {
    let (sources, _fresh) = sources().await;
    for (name, root) in sources {
        let scratch = tempfile::tempdir().unwrap();
        let silo = scratch.path().join("silo");
        copy_dir(&silo_dir(&root), &silo).unwrap();
        let before = std::fs::read(silo.join("keys/fido.json")).unwrap();
        let ours = silentsilo_vault::load_fido_keys(&silo).unwrap();

        let marker = vault_old::read_marker(&silo)
            .unwrap_or_else(|e| panic!("{name}: 1.10.0 cannot read silo.json: {e}"));
        let keys = vault_old::load_fido_keys(&silo)
            .unwrap_or_else(|e| panic!("{name}: 1.10.0 cannot load keys/fido.json: {e}"));
        assert_eq!(keys.active().count(), 3, "{name}");
        assert_eq!(
            keys.keys.iter().filter(|k| k.unconfirmed).count(),
            1,
            "{name}: 1.10.0 lost the unconfirmed mark"
        );

        // Every key opens the folder on 1.10.0, through its own database code.
        let expected = without_activity(
            silentsilo_fixture::digest_from_store(&root, FIXTURE_CODE)
                .await
                .unwrap(),
        );
        for key in keys.active() {
            let wrap = fixture_wrap_key(marker.vault_id, &as_current(key)).unwrap();
            let dek = vault_old::unwrap_dek_hex(&key.wrapped_dek, &wrap).unwrap();
            let session = vault_old::VaultSession::open_with_dek(silo.clone(), dek)
                .unwrap_or_else(|e| panic!("{name}: 1.10.0 cannot open the silo: {e}"));
            assert_eq!(session.vault_id, marker.vault_id, "{name}");
            let tree: Vec<String> = vfs_old::digest(&session.conn)
                .unwrap()
                .into_iter()
                .filter(|l| !l.starts_with("ops count="))
                .collect();
            let root_dir = session.paths.root.clone();
            drop(session);
            vault_old::wipe_work_dir(&root_dir);
            let expected: Vec<&String> = expected
                .iter()
                .filter(|l| !l.starts_with("ops count="))
                .collect();
            assert_eq!(
                tree.iter().collect::<Vec<_>>(),
                expected,
                "{name}: 1.10.0 reads the silo opened with the {} key otherwise",
                key.kind
            );
        }

        // The recovery envelope in the folder, both tags kept on a save.
        let envelope = vault_old::load_recovery_envelope(&silo).unwrap();
        assert!(
            envelope.auth.is_some() && envelope.auth_dek.is_some(),
            "{name}"
        );
        vault_old::save_recovery_envelope(&silo, &envelope).unwrap();
        let back = silentsilo_vault::load_recovery_envelope(&silo).unwrap();
        assert_eq!(back.auth, envelope.auth, "{name}");
        assert_eq!(back.auth_dek, envelope.auth_dek, "{name}");
        assert!(
            silentsilo_vault::unwrap_with_code(&back, FIXTURE_CODE).is_ok(),
            "{name}"
        );

        // A save by 1.10.0 hands every key back to this build unchanged.
        vault_old::save_fido_keys(&silo, &keys, vault_old::Authority::Machine)
            .unwrap_or_else(|e| panic!("{name}: 1.10.0 cannot save the keys back: {e}"));
        let back = silentsilo_vault::load_fido_keys(&silo).unwrap();
        assert_eq!(
            serde_json::to_value(&back.keys).unwrap(),
            serde_json::to_value(&ours.keys).unwrap(),
            "{name}: 1.10.0 changed a key on its way through"
        );
        assert_eq!(
            std::fs::read(silo.join("keys/fido.json")).unwrap(),
            before,
            "{name}: 1.10.0 writes the keys file in other bytes"
        );
    }
}
