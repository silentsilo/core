//! Small objects outside `ops/` are refused unread when storage reports a
//! size no real one reaches: a hostile provider must not exhaust memory with
//! a gigabyte answer to `keys/x.env`.

use std::sync::Mutex;

use silentsilo_crypto::generate_content_kek;
use silentsilo_store::{FolderStore, ObjectStore, StoreError, StoredObject};
use silentsilo_sync::inbox::ensure_inbox_key;
use silentsilo_sync::{
    MAX_SMALL_OBJECT_BYTES, fetch_content_kek, fetch_key_envelopes, fetch_recovery_envelope,
    is_key_revoked, read_manifest, reconcile_key_envelopes,
};
use silentsilo_vault::{StoredFidoCredential, StoredFidoKeys};

/// A folder store that records every key read whole.
struct Watched {
    inner: FolderStore,
    read: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl ObjectStore for Watched {
    async fn put(&self, key: &str, body: Vec<u8>) -> Result<(), StoreError> {
        self.inner.put(key, body).await
    }
    async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        self.read.lock().unwrap().push(key.to_string());
        self.inner.get(key).await
    }
    async fn head(&self, key: &str) -> Result<Option<i64>, StoreError> {
        self.inner.head(key).await
    }
    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<StoredObject>, StoreError> {
        self.inner.list(prefix).await
    }
    fn describe(&self) -> String {
        self.inner.describe()
    }
}

const OVERSIZED: [&str; 7] = [
    "vault.json",
    "keys/content.kek",
    "recovery.env",
    "keys/aa11.env",
    "keys/revoked/bb22.sealed",
    "inbox/keys/0190a0a0-0000-7000-8000-000000000000.sealed",
    "inbox/senders/0190a0a0-0000-7000-8000-000000000001.sealed",
];

fn credential(id: &str) -> StoredFidoCredential {
    StoredFidoCredential {
        kind: silentsilo_vault::KIND_FIDO2.into(),
        derivation: silentsilo_vault::DERIVATION_HMAC_V1.into(),
        policy: silentsilo_vault::POLICY_ORG.into(),
        credential_id: id.into(),
        public_key: "ab".repeat(1024),
        key_slot: 255,
        rp_id: "silentsilo.com".into(),
        label: "a label somebody typed at length".repeat(8),
        wrapped_dek: "cd".repeat(256),
        platform: true,
        revoked: false,
    }
}

#[test]
fn the_ceiling_leaves_a_wide_margin_over_the_largest_real_envelope() {
    // A credential id at the longest any kind accepts, with generous room
    // for every other field.
    let largest = serde_json::to_vec(&credential(&"ef".repeat(1024))).unwrap();
    assert!(
        (largest.len() as i64) * 8 < MAX_SMALL_OBJECT_BYTES,
        "{} bytes",
        largest.len()
    );
}

#[tokio::test]
async fn oversized_small_objects_are_never_downloaded() {
    let dir = tempfile::tempdir().unwrap();
    let store = Watched {
        inner: FolderStore::new(dir.path().to_path_buf()),
        read: Mutex::default(),
    };
    let huge = vec![b' '; MAX_SMALL_OBJECT_BYTES as usize + 1];
    for key in OVERSIZED {
        store.put(key, huge.clone()).await.unwrap();
    }
    let kek = generate_content_kek();

    assert!(read_manifest(&store).await.is_err());
    assert!(fetch_content_kek(&store).await.is_err());
    assert!(fetch_recovery_envelope(&store).await.is_err());
    assert!(is_key_revoked(&store, &kek, "bb22").await.is_err());
    assert!(fetch_key_envelopes(&store).await.unwrap().is_empty());

    let mut local = StoredFidoKeys {
        keys: vec![credential("cc33")],
    };
    let outcome = reconcile_key_envelopes(&store, &kek, &mut local, 0)
        .await
        .unwrap();
    assert!(outcome.added.is_empty() && outcome.revoked.is_empty());

    // The oversized key is skipped and a usable one made beside it.
    ensure_inbox_key(&store, &kek).await.unwrap();

    let read = store.read.lock().unwrap().clone();
    for key in OVERSIZED {
        assert!(!read.iter().any(|r| r == key), "{key} was downloaded");
    }
}

#[tokio::test]
async fn an_object_at_the_ceiling_is_still_read() {
    let dir = tempfile::tempdir().unwrap();
    let store = FolderStore::new(dir.path().to_path_buf());
    let mut body = serde_json::to_vec(&credential("aa11")).unwrap();
    body.resize(MAX_SMALL_OBJECT_BYTES as usize, b' ');
    store.put("keys/aa11.env", body).await.unwrap();

    let fetched = fetch_key_envelopes(&store).await.unwrap();
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0].credential_id, "aa11");
}
