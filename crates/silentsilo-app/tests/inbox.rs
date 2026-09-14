//! What a locked phone sent, moved into the silo by the sync pass.

use silentsilo_app::files::read_file;
use silentsilo_app::flows::{DeviceKey, enrol_device_key};
use silentsilo_app::{AppEvent, AppState, Host, SyncReport, run_sync_pass};
use silentsilo_crypto::inbox::EcSecret;
use silentsilo_store::{FolderStore, ObjectStore, StoreConfig};
use silentsilo_sync::inbox::{
    INBOX_VERSION, OutgoingItem, SenderIdentity, SenderRecord, ensure_inbox_key, register_sender,
    send_item,
};
use silentsilo_vault::{BackupTarget, SiloEntry, TargetRole, VaultSession};
use silentsilo_vfs::Vfs;
use uuid::Uuid;

struct Targets(Vec<BackupTarget>);

impl Host for Targets {
    fn emit(&self, _event: AppEvent) {}
    fn warn(&self, _area: &str, _detail: &str) {}
    fn targets(&self, _silo_id: Uuid) -> Vec<BackupTarget> {
        self.0.clone()
    }
}

fn folder_target(dir: &tempfile::TempDir) -> BackupTarget {
    BackupTarget {
        config: StoreConfig::Folder {
            path: dir.path().to_path_buf(),
        },
        label: String::new(),
        role: TargetRole::Working,
    }
}

struct Device {
    _dir: tempfile::TempDir,
    state: AppState,
    silo: SiloEntry,
}

impl Device {
    /// A silo with one enrolled key, `aa11`, published by a first pass.
    async fn new(host: &Targets) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("silo");
        let vault_id = Uuid::new_v4();
        let session = VaultSession::provision(root.clone(), vault_id, "s").unwrap();
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
        {
            let sessions = state.sessions.lock().unwrap();
            enrol_device_key(
                &sessions[&vault_id],
                &DeviceKey {
                    kind: silentsilo_vault::KIND_FIDO2.into(),
                    derivation: silentsilo_vault::DERIVATION_HMAC_V1.into(),
                    credential_id: "aa11".into(),
                    public_key: String::new(),
                    wrap_key: [1; 32],
                    label: "aa11".into(),
                },
            )
            .unwrap();
        }
        let device = Self {
            _dir: dir,
            state,
            silo,
        };
        device.pass(host).await;
        device
    }

    async fn pass(&self, host: &Targets) -> SyncReport {
        run_sync_pass(&self.state, host, &self.silo).await.unwrap()
    }

    fn kek(&self) -> silentsilo_crypto::ContentKek {
        self.state.sessions.lock().unwrap()[&self.silo.id]
            .kek
            .clone()
    }
}

/// A phone allowed to send, as it set itself up while the silo was open.
struct Phone {
    identity: SenderIdentity,
    secret: EcSecret,
}

async fn phone(store: &dyn ObjectStore, device: &Device, credential_id: &str) -> Phone {
    let kek = device.kek();
    let (key_id, inbox_public) = ensure_inbox_key(store, &kek).await.unwrap();
    let secret = EcSecret::generate();
    let sender_id = Uuid::new_v4();
    register_sender(
        store,
        &kek,
        &SenderRecord {
            version: INBOX_VERSION,
            sender_id,
            public_key: hex::encode(secret.public_key()),
            credential_id: credential_id.into(),
            label: "Phone".into(),
            created_at: 0,
        },
    )
    .await
    .unwrap();
    Phone {
        identity: SenderIdentity {
            vault_id: device.silo.id,
            sender_id,
            key_id,
            inbox_public,
        },
        secret,
    }
}

async fn send_photo(store: &dyn ObjectStore, phone: &Phone, bytes: &[u8]) -> Uuid {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("IMG_0001.jpg");
    std::fs::write(&source, bytes).unwrap();
    let item_id = Uuid::now_v7();
    send_item(
        store,
        &phone.identity,
        &OutgoingItem {
            item_id,
            source: &source,
            name: "IMG_0001.jpg".into(),
            mime_type: Some("image/jpeg".into()),
            taken_at: None,
            folder: vec!["Phone".into(), "Photos".into()],
            source_kind: "photos".into(),
        },
        &|message| Ok(phone.secret.sign(message)),
    )
    .await
    .unwrap();
    item_id
}

fn envelope(item_id: Uuid) -> String {
    format!("inbox/items/{item_id}.env")
}

#[tokio::test]
async fn a_sent_photo_becomes_a_file_and_leaves_the_inbox_a_pass_later() {
    let storage = tempfile::tempdir().unwrap();
    let host = Targets(vec![folder_target(&storage)]);
    let store = FolderStore::new(storage.path().to_path_buf());
    let device = Device::new(&host).await;
    let phone = phone(&store, &device, "aa11").await;
    let item_id = send_photo(&store, &phone, b"a photo").await;

    let first = device.pass(&host).await;
    assert_eq!(first.inbox_imported, 1);
    assert!(first.inbox_refused.is_empty());
    // Recorded, but not pushed yet, so still in the inbox.
    assert!(store.head(&envelope(item_id)).await.unwrap().is_some());

    let file = {
        let sessions = device.state.sessions.lock().unwrap();
        let vfs = Vfs::new(&sessions[&device.silo.id]);
        let file = vfs.get_file(item_id).unwrap();
        assert_eq!(
            vfs.get_folder(file.folder_id).unwrap().path,
            "/Phone/Photos"
        );
        file
    };
    let shown = read_file(&device.state, &host, &device.silo, file.id, 1024)
        .await
        .unwrap();
    assert_eq!(shown.bytes, b"a photo");

    let second = device.pass(&host).await;
    assert_eq!(second.inbox_imported, 0);
    assert!(store.head(&envelope(item_id)).await.unwrap().is_none());
    assert!(
        store
            .head(&format!("inbox/items/{item_id}.sslo"))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .head(&format!("blobs/{}.sslo", file.blob_id))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn a_phone_whose_key_was_removed_is_refused_and_its_item_stays() {
    let storage = tempfile::tempdir().unwrap();
    let host = Targets(vec![folder_target(&storage)]);
    let store = FolderStore::new(storage.path().to_path_buf());
    let device = Device::new(&host).await;
    let phone = phone(&store, &device, "bb22").await;
    let item_id = send_photo(&store, &phone, b"a photo").await;

    for _ in 0..2 {
        let report = device.pass(&host).await;
        assert_eq!(report.inbox_imported, 0);
        assert_eq!(report.inbox_refused.len(), 1);
    }
    assert!(store.head(&envelope(item_id)).await.unwrap().is_some());
    let sessions = device.state.sessions.lock().unwrap();
    assert!(
        !Vfs::new(&sessions[&device.silo.id])
            .file_id_known(item_id)
            .unwrap()
    );
}

#[tokio::test]
async fn with_two_copies_the_photo_reaches_the_one_it_was_not_sent_to() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let host = Targets(vec![folder_target(&first), folder_target(&second)]);
    let sent_to = FolderStore::new(first.path().to_path_buf());
    let other = FolderStore::new(second.path().to_path_buf());
    let device = Device::new(&host).await;
    let phone = phone(&sent_to, &device, "aa11").await;
    let item_id = send_photo(&sent_to, &phone, b"a photo").await;

    assert_eq!(device.pass(&host).await.inbox_imported, 1);
    device.pass(&host).await;

    let blob_id = {
        let sessions = device.state.sessions.lock().unwrap();
        Vfs::new(&sessions[&device.silo.id])
            .get_file(item_id)
            .unwrap()
            .blob_id
    };
    let blob = format!("blobs/{blob_id}.sslo");
    assert!(other.head(&blob).await.unwrap().is_some());
    assert!(sent_to.head(&blob).await.unwrap().is_some());
    assert!(sent_to.head(&envelope(item_id)).await.unwrap().is_none());
}

#[tokio::test]
async fn an_archive_copy_keeps_its_items_and_they_are_not_imported_twice() {
    let storage = tempfile::tempdir().unwrap();
    let mut target = folder_target(&storage);
    target.role = TargetRole::Archive;
    let host = Targets(vec![target]);
    let store = FolderStore::new(storage.path().to_path_buf());
    let device = Device::new(&host).await;
    let phone = phone(&store, &device, "aa11").await;
    let item_id = send_photo(&store, &phone, b"a photo").await;

    assert_eq!(device.pass(&host).await.inbox_imported, 1);
    for _ in 0..2 {
        assert_eq!(device.pass(&host).await.inbox_imported, 0);
    }
    assert!(store.head(&envelope(item_id)).await.unwrap().is_some());
}
