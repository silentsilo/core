//! Which recovery envelope a device keeps, and which one it refuses.
//!
//! Folder stores, so these run without a bucket. The attacker modelled here
//! is whoever can write to storage: they choose the bytes and the date, and
//! what they cannot do is produce a tag, because the content KEK never
//! leaves a device.

use silentsilo_crypto::{ContentKek, generate_content_kek, generate_dek};
use silentsilo_store::{FolderStore, ObjectStore};
use silentsilo_sync::{push_recovery_envelope, settle_recovery_envelope};
use silentsilo_vault::{RecoveryEnvelope, load_recovery_envelope, save_recovery_envelope};

/// A silo folder holding one envelope, and a store to sync it against.
struct Silo {
    _dirs: (tempfile::TempDir, tempfile::TempDir),
    root: std::path::PathBuf,
    store: FolderStore,
    kek: ContentKek,
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
        }
    }

    /// An envelope of this silo, dated as asked.
    fn envelope(&self, created_at: i64) -> RecoveryEnvelope {
        let (_, mut envelope) =
            silentsilo_vault::create_recovery_envelope(&generate_dek(), &self.kek).unwrap();
        envelope.created_at = created_at;
        envelope.authenticate(&self.kek);
        envelope
    }

    async fn settle(&self) -> silentsilo_sync::RecoverySettlement {
        let targets: [(&dyn ObjectStore, bool); 1] = [(&self.store, true)];
        settle_recovery_envelope(&targets, &self.kek, &self.root).await
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
