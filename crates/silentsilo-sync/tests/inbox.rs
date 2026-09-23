//! The inbox end to end: a sender that cannot open the silo, a folder store,
//! and an unlocked device importing into a real vault.

use std::collections::HashSet;

use silentsilo_crypto::inbox::EcSecret;
use silentsilo_crypto::{decrypt_blob, generate_dek, unwrap_content_key};
use silentsilo_store::{FolderStore, ObjectStore};
use silentsilo_sync::inbox::{
    INBOX_ITEMS_PREFIX, OutgoingItem, SenderIdentity, SenderRecord, ensure_inbox_key, finish_item,
    register_sender, remove_sender, scan_inbox, send_item, stage_item,
};
use silentsilo_sync::{reseal_under_new_key, sweep_orphan_blobs};
use silentsilo_vault::VaultSession;
use silentsilo_vfs::Vfs;
use uuid::Uuid;

const CREDENTIAL: &str = "a1b2c3d4";

struct Setup {
    _dirs: Vec<tempfile::TempDir>,
    store: FolderStore,
    session: VaultSession,
    identity: SenderIdentity,
    signer: EcSecret,
    photo: std::path::PathBuf,
}

async fn setup() -> Setup {
    let storage = tempfile::tempdir().unwrap();
    let store = FolderStore::new(storage.path().to_path_buf());
    let silo = tempfile::tempdir().unwrap();
    let session =
        VaultSession::provision(silo.path().join("silo"), Uuid::new_v4(), "test-secret").unwrap();
    Vfs::new(&session).ensure_initialized().unwrap();

    // The phone's device key is on the silo, and its sender is registered.
    store
        .put(&format!("keys/{CREDENTIAL}.env"), b"{}".to_vec())
        .await
        .unwrap();
    let signer = EcSecret::generate();
    let sender_id = Uuid::new_v4();
    register_sender(
        &store,
        &session.kek,
        &SenderRecord {
            version: 1,
            sender_id,
            public_key: hex::encode(signer.public_key()),
            credential_id: CREDENTIAL.into(),
            label: "Galaxy S23 Ultra".into(),
            created_at: 1_789_000_000,
        },
    )
    .await
    .unwrap();
    let (key_id, inbox_public) = ensure_inbox_key(&store, &session.kek).await.unwrap();

    let files = tempfile::tempdir().unwrap();
    let photo = files.path().join("IMG_0001.jpg");
    std::fs::write(
        &photo,
        (0..300_000).map(|i| (i % 253) as u8).collect::<Vec<_>>(),
    )
    .unwrap();

    Setup {
        identity: SenderIdentity {
            vault_id: session.vault_id,
            sender_id,
            key_id,
            inbox_public,
        },
        _dirs: vec![storage, silo, files],
        store,
        session,
        signer,
        photo,
    }
}

impl Setup {
    async fn send(&self) -> Uuid {
        self.send_as(Uuid::now_v7()).await
    }

    async fn send_as(&self, item_id: Uuid) -> Uuid {
        let signer = &self.signer;
        send_item(
            &self.store,
            &self.identity,
            &OutgoingItem {
                item_id,
                source: &self.photo,
                name: "IMG_0001.jpg".into(),
                mime_type: Some("image/jpeg".into()),
                taken_at: Some(1_789_000_000),
                folder: vec!["Phone".into(), "Photos".into()],
                source_kind: "photos".into(),
            },
            &|message| Ok(signer.sign(message)),
        )
        .await
        .unwrap();
        item_id
    }

    async fn inbox_objects(&self) -> Vec<String> {
        self.store
            .list(INBOX_ITEMS_PREFIX)
            .await
            .unwrap()
            .into_iter()
            .map(|o| o.key)
            .collect()
    }

    /// The whole import, the way an app runs it.
    async fn import(&self) -> usize {
        let scan = scan_inbox(&self.store, self.session.vault_id, &self.session.kek)
            .await
            .unwrap();
        let vfs = Vfs::new(&self.session);
        let mut imported = 0;
        for item in &scan.ready {
            if !vfs.file_id_known(item.item_id).unwrap() {
                stage_item(&self.store, item).await.unwrap();
                let folder = vfs.ensure_folder_path(&item.folder).unwrap();
                vfs.record_imported_file(
                    item.item_id,
                    folder.id,
                    &item.name,
                    item.blob_id,
                    item.size_bytes,
                    &item.content_hash,
                    item.mime_type.as_deref(),
                    &item.blob_key(&self.session.kek).unwrap(),
                )
                .unwrap();
                imported += 1;
            }
            finish_item(&self.store, item.item_id).await.unwrap();
        }
        imported
    }
}

#[tokio::test]
async fn a_sent_item_is_imported_as_a_file_that_opens() {
    let s = setup().await;
    let item_id = s.send().await;
    assert_eq!(s.inbox_objects().await.len(), 2);

    assert_eq!(s.import().await, 1);
    assert!(s.inbox_objects().await.is_empty(), "the inbox is emptied");

    let vfs = Vfs::new(&s.session);
    let file = vfs.get_file(item_id).unwrap();
    assert_eq!(file.name, "IMG_0001.jpg");
    assert_eq!(file.mime_type.as_deref(), Some("image/jpeg"));
    assert_eq!(file.size_bytes, 300_000);
    assert_eq!(
        vfs.get_folder(file.folder_id).unwrap().path,
        "/Phone/Photos"
    );

    // The content opens under the key the file's record carries.
    let dir = tempfile::tempdir().unwrap();
    let sealed = dir.path().join("blob.sslo");
    let plain = dir.path().join("plain.jpg");
    s.store
        .get_to_file(&format!("blobs/{}.sslo", file.blob_id), &sealed)
        .await
        .unwrap();
    let blob_key = vfs.blob_key(item_id).unwrap();
    let key = unwrap_content_key(&blob_key, &s.session.kek).unwrap();
    decrypt_blob(&sealed, &plain, &key, file.blob_id).unwrap();
    assert_eq!(
        std::fs::read(plain).unwrap(),
        std::fs::read(&s.photo).unwrap()
    );
}

#[tokio::test]
async fn an_import_stopped_anywhere_loses_nothing_and_records_once() {
    let s = setup().await;
    let item_id = s.send().await;
    let envelope_key = format!("{INBOX_ITEMS_PREFIX}{item_id}.env");
    let envelope = s.store.get(&envelope_key).await.unwrap();

    // Staged twice, then stopped before recording: the item is still there.
    let scan = scan_inbox(&s.store, s.session.vault_id, &s.session.kek)
        .await
        .unwrap();
    stage_item(&s.store, &scan.ready[0]).await.unwrap();
    stage_item(&s.store, &scan.ready[0]).await.unwrap();
    assert_eq!(s.inbox_objects().await.len(), 2);

    assert_eq!(s.import().await, 1);

    // The same envelope again, replayed by storage or left by a crash: it is
    // cleared and nothing is recorded twice.
    s.store.put(&envelope_key, envelope).await.unwrap();
    assert_eq!(s.import().await, 0);
    assert!(s.inbox_objects().await.is_empty());
    assert!(Vfs::new(&s.session).file_id_known(item_id).unwrap());
}

#[tokio::test]
async fn an_envelope_left_without_its_content_is_cleared_once_recorded() {
    let s = setup().await;
    let item_id = s.send().await;
    let scan = scan_inbox(&s.store, s.session.vault_id, &s.session.kek)
        .await
        .unwrap();
    let item = &scan.ready[0];
    stage_item(&s.store, item).await.unwrap();
    let vfs = Vfs::new(&s.session);
    let folder = vfs.ensure_folder_path(&item.folder).unwrap();
    vfs.record_imported_file(
        item.item_id,
        folder.id,
        &item.name,
        item.blob_id,
        item.size_bytes,
        &item.content_hash,
        None,
        &item.blob_key(&s.session.kek).unwrap(),
    )
    .unwrap();
    // The process died between the two deletes.
    s.store
        .delete(&format!("{INBOX_ITEMS_PREFIX}{item_id}.sslo"))
        .await
        .unwrap();

    assert_eq!(s.import().await, 0, "known, so nothing is recorded again");
    assert!(s.inbox_objects().await.is_empty());
}

#[tokio::test]
async fn items_from_a_sender_without_a_place_on_the_silo_are_refused_and_kept() {
    let s = setup().await;
    s.send().await;

    // The phone's key was removed from the silo.
    s.store
        .delete(&format!("keys/{CREDENTIAL}.env"))
        .await
        .unwrap();
    let scan = scan_inbox(&s.store, s.session.vault_id, &s.session.kek)
        .await
        .unwrap();
    assert!(scan.ready.is_empty());
    assert!(
        scan.refused[0].reason.contains("removed"),
        "{:?}",
        scan.refused
    );

    // Or the sender itself was removed.
    s.store
        .put(&format!("keys/{CREDENTIAL}.env"), b"{}".to_vec())
        .await
        .unwrap();
    remove_sender(&s.store, s.identity.sender_id).await.unwrap();
    let scan = scan_inbox(&s.store, s.session.vault_id, &s.session.kek)
        .await
        .unwrap();
    assert!(scan.ready.is_empty());
    assert!(
        scan.refused[0].reason.contains("allowed to send"),
        "{:?}",
        scan.refused
    );

    assert_eq!(s.inbox_objects().await.len(), 2, "refused items stay");
}

/// Puts `envelope` in place of an item's and returns why the scan refused it.
async fn refused_for(s: &Setup, key: &str, envelope: &serde_json::Value) -> String {
    s.store
        .put(key, serde_json::to_vec(envelope).unwrap())
        .await
        .unwrap();
    let scan = scan_inbox(&s.store, s.session.vault_id, &s.session.kek)
        .await
        .unwrap();
    assert!(scan.ready.is_empty(), "{envelope}");
    scan.refused[0].reason.clone()
}

#[tokio::test]
async fn a_forged_or_altered_item_is_refused() {
    let s = setup().await;
    let item_id = s.send().await;
    let key = format!("{INBOX_ITEMS_PREFIX}{item_id}.env");
    let original: serde_json::Value =
        serde_json::from_slice(&s.store.get(&key).await.unwrap()).unwrap();

    // Signed by a key that is not the sender's.
    let mut forged = original.clone();
    forged["signature"] = hex::encode(EcSecret::generate().sign(b"anything")).into();
    assert!(
        refused_for(&s, &key, &forged)
            .await
            .contains("allowed to send")
    );

    // A different size, which the signature covers.
    let mut resized = original.clone();
    resized["blob_size"] = 1.into();
    assert!(
        refused_for(&s, &key, &resized)
            .await
            .contains("allowed to send")
    );

    // The provider sees no sender in the envelope.
    assert!(original.get("sender_id").is_none(), "{original}");

    // Moved onto another item's name.
    let other = format!("{INBOX_ITEMS_PREFIX}{}.env", Uuid::now_v7());
    s.store.delete(&key).await.unwrap();
    assert!(
        refused_for(&s, &other, &original)
            .await
            .contains("different item")
    );
    s.store.delete(&other).await.unwrap();

    // A newer format.
    let mut newer = original.clone();
    newer["version"] = 2.into();
    assert!(refused_for(&s, &key, &newer).await.contains("newer"));

    // The untouched envelope still imports.
    s.store
        .put(&key, serde_json::to_vec(&original).unwrap())
        .await
        .unwrap();
    assert_eq!(s.import().await, 1);
}

#[tokio::test]
async fn content_that_is_not_the_signed_size_is_not_staged() {
    let s = setup().await;
    let item_id = s.send().await;
    let scan = scan_inbox(&s.store, s.session.vault_id, &s.session.kek)
        .await
        .unwrap();
    s.store
        .put(&format!("{INBOX_ITEMS_PREFIX}{item_id}.sslo"), vec![0; 10])
        .await
        .unwrap();
    assert!(stage_item(&s.store, &scan.ready[0]).await.is_err());
    assert!(s.store.list("blobs/").await.unwrap().is_empty());
}

#[tokio::test]
async fn sending_an_item_already_in_the_inbox_again_changes_nothing() {
    let s = setup().await;
    let item_id = s.send().await;
    let content = format!("{INBOX_ITEMS_PREFIX}{item_id}.sslo");
    let envelope = format!("{INBOX_ITEMS_PREFIX}{item_id}.env");
    let before = (
        s.store.get(&content).await.unwrap(),
        s.store.get(&envelope).await.unwrap(),
    );

    s.send_as(item_id).await;

    assert_eq!(s.store.get(&content).await.unwrap(), before.0);
    assert_eq!(s.store.get(&envelope).await.unwrap(), before.1);
    assert_eq!(s.import().await, 1);
}

#[tokio::test]
async fn content_resealed_under_another_blob_id_is_not_staged() {
    // What an older build's resend did: same item, same size, a new blob
    // id in the header. Recorded, it opened as "blob identity mismatch".
    let s = setup().await;
    let item_id = s.send().await;
    let scan = scan_inbox(&s.store, s.session.vault_id, &s.session.kek)
        .await
        .unwrap();
    let key = format!("{INBOX_ITEMS_PREFIX}{item_id}.sslo");
    let mut bytes = s.store.get(&key).await.unwrap();
    bytes[26..42].copy_from_slice(Uuid::new_v4().as_bytes());
    s.store.put(&key, bytes).await.unwrap();

    assert!(stage_item(&s.store, &scan.ready[0]).await.is_err());
    assert!(s.store.list("blobs/").await.unwrap().is_empty());
}

#[tokio::test]
async fn rotating_the_silo_key_leaves_waiting_items_importable() {
    // A 1.0.0 desktop rotating the vault key re-seals `ops/`, `snapshots/`
    // and the KEK envelope. The inbox is sealed under the KEK, which
    // rotation keeps, so nothing waiting here is stranded.
    let s = setup().await;
    s.send().await;
    let old = s.session.dek.clone();
    reseal_under_new_key(&s.store, &old, &generate_dek(), &mut |_, _| {})
        .await
        .unwrap();
    assert_eq!(s.import().await, 1);
}

#[tokio::test]
async fn the_orphan_sweep_never_touches_the_inbox() {
    let s = setup().await;
    s.send().await;
    let nothing = HashSet::new();
    let first = sweep_orphan_blobs(&s.store, &nothing, &nothing)
        .await
        .unwrap();
    let candidates = first.candidates.into_iter().collect();
    sweep_orphan_blobs(&s.store, &nothing, &candidates)
        .await
        .unwrap();
    assert_eq!(s.inbox_objects().await.len(), 2);
    assert_eq!(s.import().await, 1);
}

#[tokio::test]
async fn an_existing_inbox_key_is_reused() {
    let s = setup().await;
    let (again, public) = ensure_inbox_key(&s.store, &s.session.kek).await.unwrap();
    assert_eq!(again, s.identity.key_id);
    assert_eq!(public, s.identity.inbox_public);
    assert_eq!(s.store.list("inbox/keys/").await.unwrap().len(), 1);
}

/// A store where another device finishes an item between the listing and
/// the read: the listing still names it, the object is gone.
struct FinishedMeanwhile<'a> {
    inner: &'a FolderStore,
    item_id: Uuid,
}

#[async_trait::async_trait]
impl ObjectStore for FinishedMeanwhile<'_> {
    async fn put(&self, key: &str, body: Vec<u8>) -> Result<(), silentsilo_store::StoreError> {
        self.inner.put(key, body).await
    }
    async fn get(&self, key: &str) -> Result<Vec<u8>, silentsilo_store::StoreError> {
        self.inner.get(key).await
    }
    async fn head(&self, key: &str) -> Result<Option<i64>, silentsilo_store::StoreError> {
        self.inner.head(key).await
    }
    async fn delete(&self, key: &str) -> Result<(), silentsilo_store::StoreError> {
        self.inner.delete(key).await
    }
    async fn list(
        &self,
        prefix: &str,
    ) -> Result<Vec<silentsilo_store::StoredObject>, silentsilo_store::StoreError> {
        let listed = self.inner.list(prefix).await?;
        if prefix == INBOX_ITEMS_PREFIX {
            finish_item(self.inner, self.item_id).await.unwrap();
        }
        Ok(listed)
    }
    fn describe(&self) -> String {
        self.inner.describe()
    }
}

#[tokio::test]
async fn an_item_finished_elsewhere_during_the_scan_does_not_stop_the_others() {
    let s = setup().await;
    let gone = s.send().await;
    let kept = s.send().await;
    let store = FinishedMeanwhile {
        inner: &s.store,
        item_id: gone,
    };
    let scan = scan_inbox(&store, s.session.vault_id, &s.session.kek)
        .await
        .unwrap();
    let ready: Vec<Uuid> = scan.ready.iter().map(|i| i.item_id).collect();
    assert_eq!(ready, vec![kept]);
    assert!(scan.refused.is_empty());
}
