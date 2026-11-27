//! Which unlock password envelope a device keeps, adopts, publishes and
//! refuses.
//!
//! Folder stores, so these run without a bucket. The attacker is whoever can
//! write to storage or to the silo folder: they choose bytes and dates, and
//! cannot produce a tag, because neither the content KEK nor the vault key
//! leaves a device. Envelopes are built by hand: the tags do not depend on
//! the KDF, and 256 MiB per envelope would make this suite slow for nothing.

use silentsilo_crypto::{ContentKek, MasterDek, generate_content_kek, generate_dek};
use silentsilo_store::{FolderStore, ObjectStore, StoreError, StoredObject};
use silentsilo_sync::unlock_password::{
    PASSWORD_KEY, PasswordSettlement, StoredPassword, ensure_password_envelope,
    fetch_password_envelope, password_date_floor, push_password_envelope, remove_password,
    settle_password_envelope,
};
use silentsilo_sync::{PASSWORD_MARKER_ID, reconcile_key_envelopes, revocation_marks};
use silentsilo_vault::password::{
    PASSWORD_ENVELOPE_VERSION, PasswordEnvelope, has_unlock_password, load_password_envelope,
    save_password_envelope,
};

struct Silo {
    _dirs: (tempfile::TempDir, tempfile::TempDir),
    root: std::path::PathBuf,
    store: FolderStore,
    kek: ContentKek,
    dek: MasterDek,
}

impl Silo {
    fn new() -> Self {
        let silo = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let root = silo.path().to_path_buf();
        let store = FolderStore::new(storage.path().to_path_buf());
        Self {
            _dirs: (silo, storage),
            root,
            store,
            kek: generate_content_kek(),
            dek: generate_dek(),
        }
    }

    /// A second device on the same silo and the same storage.
    fn other_device(&self) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        (dir, root)
    }

    fn envelope(&self, created_at: i64) -> PasswordEnvelope {
        envelope_for(&self.kek, &self.dek, created_at)
    }

    async fn settle_at(&self, root: &std::path::Path) -> PasswordSettlement {
        let targets: [(&dyn ObjectStore, bool); 1] = [(&self.store, true)];
        settle_password_envelope(&targets, &self.kek, &self.dek, root).await
    }

    async fn settle(&self) -> PasswordSettlement {
        self.settle_at(&self.root).await
    }

    async fn stored(&self) -> StoredPassword {
        fetch_password_envelope(&self.store).await.unwrap()
    }
}

/// An envelope as a device of the silo makes it, minus the KDF.
fn envelope_for(kek: &ContentKek, dek: &MasterDek, created_at: i64) -> PasswordEnvelope {
    let mut envelope = PasswordEnvelope {
        version: PASSWORD_ENVELOPE_VERSION,
        id: uuid::Uuid::new_v4().to_string(),
        kdf: serde_json::from_value(serde_json::json!({
            "algorithm": "argon2id", "m_cost": 1024, "t_cost": 1, "p_cost": 1
        }))
        .unwrap(),
        salt: uuid::Uuid::new_v4().simple().to_string(),
        wrapped_dek: format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ),
        created_at,
        auth: String::new(),
        auth_dek: String::new(),
    };
    envelope.authenticate(kek, dek);
    envelope
}

fn id_of(stored: StoredPassword) -> Option<String> {
    match stored {
        StoredPassword::Envelope(e) => Some(e.id),
        _ => None,
    }
}

#[tokio::test]
async fn a_device_without_the_password_adopts_it_from_storage() {
    // Set on the phone, this computer has to open with it, offline too.
    let silo = Silo::new();
    let set_elsewhere = silo.envelope(100);
    push_password_envelope(&silo.store, &set_elsewhere)
        .await
        .unwrap();

    let settled = silo.settle().await;

    assert!(settled.adopted);
    assert_eq!(settled.envelope.unwrap().id, set_elsewhere.id);
    assert_eq!(
        load_password_envelope(&silo.root).unwrap().id,
        set_elsewhere.id
    );
}

#[tokio::test]
async fn a_password_changed_on_another_device_replaces_this_ones() {
    let silo = Silo::new();
    save_password_envelope(&silo.root, &silo.envelope(100)).unwrap();
    let changed = silo.envelope(200);
    push_password_envelope(&silo.store, &changed).await.unwrap();

    let settled = silo.settle().await;

    assert!(settled.adopted);
    assert_eq!(load_password_envelope(&silo.root).unwrap().id, changed.id);
}

#[tokio::test]
async fn an_older_envelope_in_storage_does_not_replace_this_ones() {
    let silo = Silo::new();
    let mine = silo.envelope(200);
    save_password_envelope(&silo.root, &mine).unwrap();
    push_password_envelope(&silo.store, &silo.envelope(100))
        .await
        .unwrap();

    let settled = silo.settle().await;

    assert!(!settled.adopted);
    assert_eq!(settled.envelope.unwrap().id, mine.id);
    // And publishing puts the current one over the older.
    assert!(
        ensure_password_envelope(&silo.store, &mine, &silo.kek, &silo.dek)
            .await
            .unwrap()
    );
    assert_eq!(id_of(silo.stored().await), Some(mine.id));
}

#[tokio::test]
async fn a_planted_envelope_is_never_adopted_and_never_blocks_publishing() {
    // The attack: an envelope under the attacker's own password, given a date
    // in the future so every device takes it, or so republishing stops.
    let silo = Silo::new();
    let mine = silo.envelope(100);
    save_password_envelope(&silo.root, &mine).unwrap();
    let planted = envelope_for(&generate_content_kek(), &generate_dek(), 9_999_999_999);
    push_password_envelope(&silo.store, &planted).await.unwrap();

    let settled = silo.settle().await;
    assert!(settled.refused);
    assert!(!settled.adopted);
    assert_eq!(settled.envelope.as_ref().unwrap().id, mine.id);

    assert!(
        ensure_password_envelope(&silo.store, &mine, &silo.kek, &silo.dek)
            .await
            .unwrap()
    );
    assert_eq!(id_of(silo.stored().await), Some(mine.id));
}

#[tokio::test]
async fn a_planted_envelope_is_not_adopted_by_a_device_that_has_none() {
    let silo = Silo::new();
    let planted = envelope_for(&generate_content_kek(), &generate_dek(), 100);
    push_password_envelope(&silo.store, &planted).await.unwrap();

    let settled = silo.settle().await;

    assert!(settled.refused);
    assert!(settled.envelope.is_none());
    assert!(!has_unlock_password(&silo.root));
}

#[tokio::test]
async fn an_envelope_with_only_the_kek_tag_is_not_adopted() {
    // Someone a rotation removed still holds the KEK, never the new key.
    let silo = Silo::new();
    let mut forged = silo.envelope(100);
    forged.auth_dek = "00".repeat(32);
    push_password_envelope(&silo.store, &forged).await.unwrap();

    let settled = silo.settle().await;

    assert!(settled.envelope.is_none());
    assert!(!has_unlock_password(&silo.root));
}

#[tokio::test]
async fn an_envelope_put_in_the_silo_folder_is_not_used() {
    // Whoever can write the synced silo folder cannot add a password.
    let silo = Silo::new();
    let planted = envelope_for(&generate_content_kek(), &generate_dek(), 100);
    save_password_envelope(&silo.root, &planted).unwrap();

    let settled = silo.settle().await;

    assert!(settled.refused);
    assert!(settled.envelope.is_none());
    assert!(!has_unlock_password(&silo.root));
}

#[tokio::test]
async fn after_a_rotation_by_an_older_release_the_password_is_dropped_and_said() {
    // A release that does not know about passwords rotated the vault key:
    // the envelope still opens the old key only. It is dropped here and in
    // storage, and the user is told to set it again.
    let silo = Silo::new();
    let before = silo.envelope(100);
    save_password_envelope(&silo.root, &before).unwrap();
    push_password_envelope(&silo.store, &before).await.unwrap();

    let rotated = generate_dek();
    let targets: [(&dyn ObjectStore, bool); 1] = [(&silo.store, true)];
    let settled = settle_password_envelope(&targets, &silo.kek, &rotated, &silo.root).await;

    assert!(settled.dropped_after_rotation);
    assert!(settled.envelope.is_none());
    assert!(!has_unlock_password(&silo.root));
    assert!(matches!(silo.stored().await, StoredPassword::Absent));
}

#[tokio::test]
async fn a_device_that_never_had_it_is_told_too_after_a_rotation() {
    let silo = Silo::new();
    push_password_envelope(&silo.store, &silo.envelope(100))
        .await
        .unwrap();
    let targets: [(&dyn ObjectStore, bool); 1] = [(&silo.store, false)];
    let settled = settle_password_envelope(&targets, &silo.kek, &generate_dek(), &silo.root).await;
    assert!(settled.dropped_after_rotation);
    assert!(settled.envelope.is_none());
    // A never-delete copy keeps the object; nothing deletes there.
    assert!(matches!(silo.stored().await, StoredPassword::Envelope(_)));
}

#[tokio::test]
async fn a_removal_reaches_a_device_that_had_not_heard() {
    let silo = Silo::new();
    let set = silo.envelope(100);
    save_password_envelope(&silo.root, &set).unwrap();
    push_password_envelope(&silo.store, &set).await.unwrap();
    let (_dir, other) = silo.other_device();
    save_password_envelope(&other, &set).unwrap();

    let targets: [(&dyn ObjectStore, bool); 1] = [(&silo.store, true)];
    remove_password(&targets, &silo.kek, &silo.root)
        .await
        .unwrap();
    assert!(!has_unlock_password(&silo.root));
    assert!(matches!(silo.stored().await, StoredPassword::Absent));

    let settled = silo.settle_at(&other).await;
    assert!(settled.removed_elsewhere);
    assert!(settled.envelope.is_none());
    assert!(!has_unlock_password(&other));
}

#[tokio::test]
async fn a_device_that_had_not_heard_does_not_put_a_removed_password_back() {
    let silo = Silo::new();
    let set = silo.envelope(100);
    let (_dir, other) = silo.other_device();
    save_password_envelope(&other, &set).unwrap();
    let targets: [(&dyn ObjectStore, bool); 1] = [(&silo.store, true)];
    remove_password(&targets, &silo.kek, &silo.root)
        .await
        .unwrap();

    // The order a pass runs in: settle, then publish what is left.
    let settled = silo.settle_at(&other).await;
    assert!(settled.envelope.is_none());
    assert!(matches!(silo.stored().await, StoredPassword::Absent));
}

#[tokio::test]
async fn a_password_set_again_after_a_removal_is_dated_past_it_and_kept() {
    let silo = Silo::new();
    let targets: [(&dyn ObjectStore, bool); 1] = [(&silo.store, true)];
    let removed_at = remove_password(&targets, &silo.kek, &silo.root)
        .await
        .unwrap();

    // A device whose clock is behind sets a new one.
    let mut again = silo.envelope(removed_at - 3600);
    let floor = password_date_floor(&[&silo.store], &silo.kek).await;
    again.date_after(floor, &silo.kek, &silo.dek);
    assert!(again.created_at > removed_at);
    save_password_envelope(&silo.root, &again).unwrap();
    push_password_envelope(&silo.store, &again).await.unwrap();

    let settled = silo.settle().await;
    assert!(!settled.removed_elsewhere);
    assert_eq!(settled.envelope.unwrap().id, again.id);
}

#[tokio::test]
async fn publishing_never_writes_over_a_newer_current_password() {
    // Another device changed it; this one has not settled yet.
    let silo = Silo::new();
    let mine = silo.envelope(100);
    let newer = silo.envelope(200);
    push_password_envelope(&silo.store, &newer).await.unwrap();

    assert!(
        !ensure_password_envelope(&silo.store, &mine, &silo.kek, &silo.dek)
            .await
            .unwrap()
    );
    assert_eq!(id_of(silo.stored().await), Some(newer.id));
}

#[tokio::test]
async fn publishing_never_writes_over_what_a_newer_release_wrote() {
    let silo = Silo::new();
    let mine = silo.envelope(100);
    let mut future = serde_json::to_value(silo.envelope(50)).unwrap();
    future["version"] = serde_json::json!(PASSWORD_ENVELOPE_VERSION + 1);
    silo.store
        .put(PASSWORD_KEY, serde_json::to_vec(&future).unwrap())
        .await
        .unwrap();

    assert!(matches!(silo.stored().await, StoredPassword::NeedsNewer));
    assert!(
        !ensure_password_envelope(&silo.store, &mine, &silo.kek, &silo.dek)
            .await
            .unwrap()
    );
    assert!(matches!(silo.stored().await, StoredPassword::NeedsNewer));
}

#[tokio::test]
async fn junk_and_oversized_objects_are_replaced_by_the_password() {
    let silo = Silo::new();
    let mine = silo.envelope(100);
    for junk in [b"not json".to_vec(), b"{}".to_vec(), vec![b' '; 70 * 1024]] {
        silo.store.put(PASSWORD_KEY, junk).await.unwrap();
        assert!(matches!(silo.stored().await, StoredPassword::Junk));
        assert!(
            ensure_password_envelope(&silo.store, &mine, &silo.kek, &silo.dek)
                .await
                .unwrap()
        );
        assert_eq!(id_of(silo.stored().await), Some(mine.id.clone()));
    }
}

/// A target whose reads of the password envelope fail, as a flaky network.
struct FailingReads(FolderStore);

#[async_trait::async_trait]
impl ObjectStore for FailingReads {
    async fn put(&self, key: &str, body: Vec<u8>) -> Result<(), StoreError> {
        self.0.put(key, body).await
    }
    async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        if key == PASSWORD_KEY {
            return Err(StoreError::Other("timed out".into()));
        }
        self.0.get(key).await
    }
    async fn get_prefix(&self, key: &str, len: u64) -> Result<Vec<u8>, StoreError> {
        if key == PASSWORD_KEY {
            return Err(StoreError::Other("timed out".into()));
        }
        self.0.get_prefix(key, len).await
    }
    async fn head(&self, key: &str) -> Result<Option<i64>, StoreError> {
        self.0.head(key).await
    }
    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.0.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<StoredObject>, StoreError> {
        self.0.list(prefix).await
    }
    fn describe(&self) -> String {
        self.0.describe()
    }
}

#[tokio::test]
async fn a_read_that_fails_writes_nothing_over_what_is_there() {
    // A newer password may be what failed to come down.
    let storage = tempfile::tempdir().unwrap();
    let (kek, dek) = (generate_content_kek(), generate_dek());
    let newer = envelope_for(&kek, &dek, 200);
    let plain = FolderStore::new(storage.path().to_path_buf());
    push_password_envelope(&plain, &newer).await.unwrap();
    let flaky = FailingReads(FolderStore::new(storage.path().to_path_buf()));

    let mine = envelope_for(&kek, &dek, 100);
    assert!(
        !ensure_password_envelope(&flaky, &mine, &kek, &dek)
            .await
            .unwrap()
    );
    assert_eq!(
        id_of(fetch_password_envelope(&plain).await.unwrap()),
        Some(newer.id)
    );
}

#[tokio::test]
async fn the_password_and_its_marker_are_not_taken_for_keys() {
    // What every release does with `keys/`: a marker there is skipped, and
    // the envelope at the root is never listed with the keys.
    let silo = Silo::new();
    push_password_envelope(&silo.store, &silo.envelope(100))
        .await
        .unwrap();
    let targets: [(&dyn ObjectStore, bool); 1] = [(&silo.store, true)];
    remove_password(&targets, &silo.kek, &silo.root)
        .await
        .unwrap();
    push_password_envelope(&silo.store, &silo.envelope(10_000_000_000))
        .await
        .unwrap();

    let keys = silentsilo_sync::fetch_key_envelopes(&silo.store)
        .await
        .unwrap();
    assert!(keys.is_empty(), "got {} keys", keys.len());
    let marks = revocation_marks(&silo.store, &silo.kek).await.unwrap();
    assert!(marks.contains(PASSWORD_MARKER_ID));

    let mut local = silentsilo_vault::StoredFidoKeys { keys: Vec::new() };
    let outcome = reconcile_key_envelopes(&silo.store, &silo.kek, &mut local, 0, &marks)
        .await
        .unwrap();
    assert!(local.keys.is_empty());
    assert!(!outcome.changed());
}

#[tokio::test]
async fn the_marker_and_the_envelope_never_collide_with_the_recovery_code() {
    let silo = Silo::new();
    let targets: [(&dyn ObjectStore, bool); 1] = [(&silo.store, true)];
    remove_password(&targets, &silo.kek, &silo.root)
        .await
        .unwrap();
    assert_eq!(
        silentsilo_sync::revoked_at(&silo.store, &silo.kek, silentsilo_sync::RECOVERY_MARKER_ID)
            .await
            .unwrap(),
        None,
        "removing the password turned the recovery code off"
    );
    assert_ne!(PASSWORD_KEY, silentsilo_sync::RECOVERY_KEY);
    assert!(!PASSWORD_KEY.starts_with("keys/"));
}
