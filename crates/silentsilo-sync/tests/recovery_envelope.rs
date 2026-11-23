//! Which recovery envelope a device keeps, and which one it refuses.
//!
//! Folder stores, so these run without a bucket. The attacker modelled here
//! is whoever can write to storage: they choose the bytes and the date, and
//! what they cannot do is produce a tag, because the content KEK never
//! leaves a device.

use silentsilo_crypto::{ContentKek, MasterDek, generate_content_kek, generate_dek};
use silentsilo_store::{FolderStore, ObjectStore};
use silentsilo_sync::{push_recovery_envelope, settle_recovery_envelope};
use silentsilo_vault::{RecoveryEnvelope, load_recovery_envelope, save_recovery_envelope};

/// A silo folder holding one envelope, and a store to sync it against.
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

    /// An envelope of this silo, dated as asked.
    fn envelope(&self, created_at: i64) -> RecoveryEnvelope {
        let (_, mut envelope) =
            silentsilo_vault::create_recovery_envelope(&self.dek, &self.kek).unwrap();
        envelope.created_at = created_at;
        envelope.authenticate(&self.kek, &self.dek);
        envelope
    }

    async fn settle(&self) -> silentsilo_sync::RecoverySettlement {
        let targets: [(&dyn ObjectStore, bool); 1] = [(&self.store, true)];
        settle_recovery_envelope(&targets, &self.kek, &self.dek, &self.root).await
    }
}

#[tokio::test]
async fn a_newer_envelope_from_another_device_is_adopted() {
    // The ordinary case the adoption rule exists for: someone regenerated
    // the code on their laptop and this machine has to follow.
    let silo = Silo::new();
    save_recovery_envelope(&silo.root, &silo.envelope(100)).unwrap();
    let newer = silo.envelope(200);
    push_recovery_envelope(&silo.store, &newer).await.unwrap();

    let settled = silo.settle().await;

    assert_eq!(settled.envelope.unwrap().salt, newer.salt);
    assert_eq!(load_recovery_envelope(&silo.root).unwrap().salt, newer.salt);
    assert!(!settled.refused_unauthenticated);
}

#[tokio::test]
async fn an_untagged_envelope_with_a_newer_date_is_refused() {
    // The attack: an old envelope, or one that opens nothing at all, given
    // a date past the current code so every device adopts it. Found out at
    // recovery otherwise, which is the one moment nothing can be retried.
    let silo = Silo::new();
    let mine = silo.envelope(100);
    save_recovery_envelope(&silo.root, &mine).unwrap();
    let mut forged = silo.envelope(200);
    forged.auth = None;
    push_recovery_envelope(&silo.store, &forged).await.unwrap();

    let settled = silo.settle().await;

    assert_eq!(settled.envelope.unwrap().salt, mine.salt);
    assert_eq!(load_recovery_envelope(&silo.root).unwrap().salt, mine.salt);
    assert!(
        settled.refused_unauthenticated,
        "the refusal has to reach the user, not only the local file"
    );
}

#[tokio::test]
async fn a_tag_from_another_silo_is_refused() {
    // A tag is not a checksum: it says "a device holding this silo's content
    // key wrote this", so one made elsewhere counts for nothing.
    let silo = Silo::new();
    let mine = silo.envelope(100);
    save_recovery_envelope(&silo.root, &mine).unwrap();
    let (_, mut theirs) =
        silentsilo_vault::create_recovery_envelope(&generate_dek(), &generate_content_kek())
            .unwrap();
    theirs.created_at = 200;
    push_recovery_envelope(&silo.store, &theirs).await.unwrap();

    let settled = silo.settle().await;

    assert_eq!(settled.envelope.unwrap().salt, mine.salt);
    assert!(settled.refused_unauthenticated);
}

#[tokio::test]
async fn a_silo_from_before_the_tag_still_follows_the_date_and_then_upgrades() {
    // Nothing on this silo has run 1.6.0 yet, so refusing an untagged
    // envelope would strand a fleet that has lost nothing. The pass adopts
    // it as 1.5.0 did and tags what it ends up holding, which closes the
    // door for every pass after this one.
    let silo = Silo::new();
    let mut mine = silo.envelope(100);
    mine.auth = None;
    save_recovery_envelope(&silo.root, &mine).unwrap();
    let mut newer = silo.envelope(200);
    newer.auth = None;
    push_recovery_envelope(&silo.store, &newer).await.unwrap();

    let settled = silo.settle().await;

    let kept = settled.envelope.expect("a silo with a code keeps one");
    assert_eq!(kept.salt, newer.salt, "the newer envelope was not adopted");
    assert!(!settled.refused_unauthenticated);

    let on_disk = load_recovery_envelope(&silo.root).unwrap();
    assert!(
        on_disk.is_authentic(&silo.kek),
        "the local envelope must come out of the pass tagged"
    );

    // And now the same forgery as above no longer gets in.
    let mut forged = silo.envelope(300);
    forged.auth = None;
    push_recovery_envelope(&silo.store, &forged).await.unwrap();
    let settled = silo.settle().await;
    assert_eq!(settled.envelope.unwrap().salt, newer.salt);
    assert!(settled.refused_unauthenticated);
}

#[tokio::test]
async fn a_tag_that_does_not_verify_is_left_alone_rather_than_stamped() {
    // The local file is trusted, but only far enough to fill in a tag that
    // was never there. Rewriting one that disagrees would launder a damaged
    // envelope into one every other device adopts.
    let silo = Silo::new();
    let mut mine = silo.envelope(100);
    mine.auth = Some("aa".repeat(32));
    save_recovery_envelope(&silo.root, &mine).unwrap();

    let settled = silo.settle().await;

    assert_eq!(settled.envelope.unwrap().auth, mine.auth);
    assert_eq!(load_recovery_envelope(&silo.root).unwrap().auth, mine.auth);
}

#[tokio::test]
async fn an_envelope_tagged_with_the_content_key_alone_is_not_adopted() {
    // A former holder of the content key, after a rotation retired their
    // vault key: they can still make the older tag, not the one that also
    // takes the current vault key.
    let silo = Silo::new();
    save_recovery_envelope(&silo.root, &silo.envelope(100)).unwrap();
    let retired = generate_dek();
    let (_, mut forged) = silentsilo_vault::create_recovery_envelope(&retired, &silo.kek).unwrap();
    forged.created_at = 200;
    forged.authenticate(&silo.kek, &retired);
    assert!(forged.is_authentic(&silo.kek));
    push_recovery_envelope(&silo.store, &forged).await.unwrap();

    let settled = silo.settle().await;
    assert!(settled.refused_unauthenticated);
    assert_eq!(load_recovery_envelope(&silo.root).unwrap().created_at, 100);
}

/// A folder whose reads fail while its other answers work: a connection
/// that drops on the download, or a provider answering 500 for one key.
struct ReadsFail(FolderStore);

#[async_trait::async_trait]
impl ObjectStore for ReadsFail {
    async fn put(&self, key: &str, body: Vec<u8>) -> Result<(), silentsilo_store::StoreError> {
        self.0.put(key, body).await
    }

    async fn get(&self, _key: &str) -> Result<Vec<u8>, silentsilo_store::StoreError> {
        Err(silentsilo_store::StoreError::Other(
            "connection reset".into(),
        ))
    }

    async fn head(&self, key: &str) -> Result<Option<i64>, silentsilo_store::StoreError> {
        self.0.head(key).await
    }

    async fn delete(&self, key: &str) -> Result<(), silentsilo_store::StoreError> {
        self.0.delete(key).await
    }

    async fn list(
        &self,
        prefix: &str,
    ) -> Result<Vec<silentsilo_store::StoredObject>, silentsilo_store::StoreError> {
        self.0.list(prefix).await
    }

    fn describe(&self) -> String {
        self.0.describe()
    }
}

#[tokio::test]
async fn a_read_that_fails_does_not_put_an_older_code_back() {
    // A device that had not heard of a new code republishes its old one on
    // every pass. When the read of the copy's envelope failed, it wrote over
    // the new one: the code the user had just written down stopped working.
    let dir = tempfile::tempdir().unwrap();
    let dek = silentsilo_crypto::generate_dek();
    let kek = silentsilo_crypto::generate_content_kek();
    let (_, mut old) = silentsilo_vault::create_recovery_envelope(&dek, &kek).unwrap();
    let (_, new) = silentsilo_vault::create_recovery_envelope(&dek, &kek).unwrap();
    old.created_at = new.created_at - 3600;

    let folder = FolderStore::new(dir.path().to_path_buf());
    assert!(
        silentsilo_sync::ensure_recovery_envelope(&folder, &new)
            .await
            .unwrap()
    );

    let flaky = ReadsFail(FolderStore::new(dir.path().to_path_buf()));
    assert!(
        !silentsilo_sync::ensure_recovery_envelope(&flaky, &old)
            .await
            .unwrap()
    );
    let held = silentsilo_sync::fetch_recovery_envelope(&folder)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.created_at, new.created_at, "the new code was replaced");

    // Read properly, the newer one is still left alone, and a missing one
    // is still written.
    assert!(
        !silentsilo_sync::ensure_recovery_envelope(&folder, &old)
            .await
            .unwrap()
    );
    folder.delete(silentsilo_sync::RECOVERY_KEY).await.unwrap();
    assert!(
        silentsilo_sync::ensure_recovery_envelope(&flaky, &old)
            .await
            .unwrap()
    );
}
