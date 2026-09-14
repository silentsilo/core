//! Showing a file inside the app: from the local cache, from storage when
//! this device never held it, and never above the size limit.

use silentsilo_app::files::read_file;
use silentsilo_app::{AppEvent, AppState, Host, open_scratch_dir, run_sync_pass};
use silentsilo_store::StoreConfig;
use silentsilo_vault::{BackupTarget, SiloEntry, TargetRole, VaultSession};
use silentsilo_vfs::Vfs;
use uuid::Uuid;

struct OneTarget(BackupTarget);

impl Host for OneTarget {
    fn emit(&self, _event: AppEvent) {}
    fn warn(&self, _area: &str, _detail: &str) {}
    fn targets(&self, _silo_id: Uuid) -> Vec<BackupTarget> {
        vec![self.0.clone()]
    }
}

struct Device {
    _dir: tempfile::TempDir,
    state: AppState,
    silo: SiloEntry,
}

fn device(
    vault_id: Uuid,
    keys: Option<(silentsilo_crypto::MasterDek, silentsilo_crypto::ContentKek)>,
    host: &OneTarget,
) -> Device {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("silo");
    let session = match keys {
        Some((dek, kek)) => {
            VaultSession::provision_with_dek(root.clone(), vault_id, "s", dek, kek).unwrap()
        }
        None => VaultSession::provision(root.clone(), vault_id, "s").unwrap(),
    };
    Vfs::new(&session).ensure_initialized().unwrap();
    let silo = SiloEntry {
        id: vault_id,
        name: "T".into(),
        path: root,
        last_opened: 0,
        auto_lock_minutes: None,
    };
    let state = AppState::default();
    state.open_session(host, vault_id, session).unwrap();
    Device {
        _dir: dir,
        state,
        silo,
    }
}

/// Imports `bytes` the way the desktop does and returns the file id.
fn import(device: &Device, name: &str, bytes: &[u8]) -> Uuid {
    let sessions = device.state.sessions.lock().unwrap();
    let session = &sessions[&device.silo.id];
    let source = device._dir.path().join("source");
    std::fs::write(&source, bytes).unwrap();
    let blob_id = Uuid::new_v4();
    let key = silentsilo_crypto::generate_content_key();
    let blob_path = session.paths.blob_path(blob_id);
    std::fs::create_dir_all(blob_path.parent().unwrap()).unwrap();
    let result =
        silentsilo_crypto::encrypt_file(&source, &blob_path, &key, Uuid::now_v7(), blob_id)
            .unwrap();
    silentsilo_vault::record_blob_present(
        &session.paths.root,
        blob_id,
        result.size_bytes as i64,
        false,
    )
    .unwrap();
    let vfs = Vfs::new(session);
    let file = vfs
        .add_file(
            vfs.root_folder_id().unwrap(),
            name,
            blob_id,
            result.plain_bytes as i64,
            &hex::encode(result.header.content_hash),
            Some("image/png"),
            &silentsilo_crypto::wrap_content_key(&key, &session.kek).unwrap(),
        )
        .unwrap();
    file.id
}

#[tokio::test]
async fn a_file_on_this_device_or_only_in_storage_reads_back_whole() {
    let storage = tempfile::tempdir().unwrap();
    let host = OneTarget(BackupTarget {
        config: StoreConfig::Folder {
            path: storage.path().to_path_buf(),
        },
        label: String::new(),
        role: TargetRole::Working,
    });
    let bytes: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();

    let a = device(Uuid::new_v4(), None, &host);
    let file_id = import(&a, "photo.png", &bytes);
    let local = read_file(&a.state, &host, &a.silo, file_id, 1 << 20)
        .await
        .unwrap();
    assert_eq!(local.bytes, bytes);
    assert_eq!(local.name, "photo.png");
    assert_eq!(local.mime_type.as_deref(), Some("image/png"));
    run_sync_pass(&a.state, &host, &a.silo).await.unwrap();

    // Device B has the record but not the content, which comes down.
    let keys = {
        let s = a.state.sessions.lock().unwrap();
        (s[&a.silo.id].dek.clone(), s[&a.silo.id].kek.clone())
    };
    let b = device(a.silo.id, Some(keys), &host);
    run_sync_pass(&b.state, &host, &b.silo).await.unwrap();
    let remote = read_file(&b.state, &host, &b.silo, file_id, 1 << 20)
        .await
        .unwrap();
    assert_eq!(remote.bytes, bytes);

    // Nothing decrypted is left behind.
    let scratch = open_scratch_dir(&b.silo.path);
    let left = std::fs::read_dir(&scratch).map(|d| d.count()).unwrap_or(0);
    assert_eq!(left, 0, "the preview copy was removed");

    let err = read_file(&b.state, &host, &b.silo, file_id, 1000)
        .await
        .err()
        .unwrap();
    assert_eq!(err, "This file is too large to show here.");
}

#[tokio::test]
async fn an_imported_file_reads_back_and_reaches_storage() {
    let storage = tempfile::tempdir().unwrap();
    let host = OneTarget(BackupTarget {
        config: StoreConfig::Folder {
            path: storage.path().to_path_buf(),
        },
        label: String::new(),
        role: TargetRole::Working,
    });
    let phone = device(Uuid::new_v4(), None, &host);
    let source = phone._dir.path().join("scan");
    std::fs::write(&source, b"%PDF-1.7 a contract").unwrap();
    let root = {
        let sessions = phone.state.sessions.lock().unwrap();
        Vfs::new(&sessions[&phone.silo.id])
            .root_folder_id()
            .unwrap()
    };

    let file = silentsilo_app::files::import_file(
        &phone.state,
        &phone.silo,
        root,
        &source,
        "Contract.pdf",
        None,
    )
    .unwrap();
    assert_eq!(file.mime_type.as_deref(), Some("application/pdf"));
    assert_eq!(file.size_bytes, 19);

    let shown = read_file(&phone.state, &host, &phone.silo, file.id, 1024)
        .await
        .unwrap();
    assert_eq!(shown.bytes, b"%PDF-1.7 a contract");

    run_sync_pass(&phone.state, &host, &phone.silo)
        .await
        .unwrap();
    let store = silentsilo_store::FolderStore::new(storage.path().to_path_buf());
    use silentsilo_store::ObjectStore;
    assert!(
        store
            .head(&format!("blobs/{}.sslo", file.blob_id))
            .await
            .unwrap()
            .is_some()
    );
}
