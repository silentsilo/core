//! What every release before the unlock password makes of storage that holds
//! one. Answered by each release's own code, pulled in by tag: core 1.0.0
//! (desktop 1.0.0), 1.6.1 (desktop 1.1.0, Android 1.1.0), 1.10.0 (desktop
//! 1.5.0) and 1.10.4 (desktop 1.5.2, the phone apps up to 1.4.x).
//!
//! The promise: an older client leaves the envelope and its removal marker
//! alone, does not take either for a key, and reads, joins, compacts, sweeps
//! and seeds exactly as before. And a silo with no key at all, only a
//! password and the recovery code, still opens on every one of them with the
//! code.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use silentsilo_fixture::{FIXTURE_CODE, FIXTURE_PASSWORD, store_dir};
use silentsilo_store::{ObjectStore, StoreConfig};
use silentsilo_sync::unlock_password::{
    PASSWORD_KEY, StoredPassword, ensure_password_envelope, fetch_password_envelope,
};
use silentsilo_vault::password::{seal_under_password, unwrap_with_password};

const MARKER: &str = "keys/revoked/unlock-password.sealed";

fn store(root: &Path) -> Box<dyn ObjectStore> {
    StoreConfig::Folder {
        path: store_dir(root),
    }
    .open()
    .unwrap()
}

fn bytes_of(root: &Path, key: &str) -> Vec<u8> {
    std::fs::read(store_dir(root).join(key)).unwrap_or_else(|e| panic!("{key}: {e}"))
}

/// A rich silo written now, which carries a password, plus a removal marker
/// dated before it (so the password stays valid), as a silo looks after its
/// password was removed once and set again.
async fn rich_with_password() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("silo");
    silentsilo_fixture::create_rich(&root).await.unwrap();
    let (dek, kek) = open_with_code(&root).await;
    let store = store(&root);
    silentsilo_sync::mark_password_removed(&*store, &kek, 1)
        .await
        .unwrap();
    let StoredPassword::Envelope(envelope) = fetch_password_envelope(&*store).await.unwrap() else {
        panic!("the rich fixture carries no password");
    };
    assert!(envelope.is_authentic_now(&kek, &dek));
    (dir, root)
}

/// A silo with no key envelope at all: only the recovery code and a
/// password. What a user who chooses a password and no key ends up with.
async fn password_only() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("silo");
    silentsilo_fixture::create(&root).await.unwrap();
    let (dek, kek) = open_with_code(&root).await;
    let store = store(&root);
    assert!(
        silentsilo_sync::fetch_key_envelopes(&*store)
            .await
            .unwrap()
            .is_empty(),
        "the plain fixture was meant to have no key"
    );
    let envelope = seal_under_password(&dek, &kek, FIXTURE_PASSWORD, &[], false).unwrap();
    silentsilo_sync::unlock_password::push_password_envelope(&*store, &envelope)
        .await
        .unwrap();
    (dir, root)
}

async fn open_with_code(
    root: &Path,
) -> (silentsilo_crypto::MasterDek, silentsilo_crypto::ContentKek) {
    let store = store(root);
    let envelope = silentsilo_sync::fetch_recovery_envelope(&*store)
        .await
        .unwrap()
        .unwrap();
    let dek = silentsilo_vault::unwrap_with_code(&envelope, FIXTURE_CODE).unwrap();
    let kek = silentsilo_vault::unwrap_kek_bytes(
        &silentsilo_sync::fetch_content_kek(&*store)
            .await
            .unwrap()
            .unwrap(),
        &dek,
    )
    .unwrap();
    (dek, kek)
}

/// Everything an older client could touch is still byte for byte the same.
fn assert_untouched(root: &Path, envelope: &[u8], marker: &[u8], who: &str) {
    assert_eq!(
        bytes_of(root, PASSWORD_KEY),
        envelope,
        "{who} changed the password envelope"
    );
    assert_eq!(
        bytes_of(root, MARKER),
        marker,
        "{who} changed the removal marker"
    );
}

#[tokio::test]
async fn core_1_0_0_leaves_the_password_alone_and_takes_nothing_for_a_key() {
    use silentsilo_store_v1_0_0 as store_old;
    use silentsilo_sync_v1_0_0 as sync_old;

    let (_dir, root) = rich_with_password().await;
    let (envelope, marker) = (bytes_of(&root, PASSWORD_KEY), bytes_of(&root, MARKER));
    let old: Box<dyn store_old::ObjectStore> = store_old::StoreConfig::Folder {
        path: store_dir(&root),
    }
    .open()
    .unwrap();

    // Its join reads every object under `keys/`, the marker included.
    let keys = sync_old::fetch_key_envelopes(&*old).await.unwrap();
    assert_eq!(
        keys.len(),
        3,
        "1.0.0 took the password or its marker for a key"
    );
    assert!(sync_old::read_manifest(&*old).await.unwrap().is_some());
    assert!(
        sync_old::fetch_recovery_envelope(&*old)
            .await
            .unwrap()
            .is_some()
    );

    // Compaction and the blob sweep, at their most destructive.
    sync_old::prune_ops_below(&*old, u64::MAX).await.unwrap();
    sync_old::sweep_orphan_blobs(&*old, &HashSet::new(), &HashSet::new())
        .await
        .unwrap();
    assert_untouched(&root, &envelope, &marker, "1.0.0");

    // Seeding a new copy: the root is not copied, and a current client puts
    // the password there on its next pass.
    let copy = tempfile::tempdir().unwrap();
    let to: Box<dyn store_old::ObjectStore> = store_old::StoreConfig::Folder {
        path: copy.path().to_path_buf(),
    }
    .open()
    .unwrap();
    sync_old::seed_target(&*old, &*to, &mut |_, _| {}, &|| false)
        .await
        .unwrap();
    assert_untouched(&root, &envelope, &marker, "1.0.0 seeding");
    republished_on(copy.path(), &root).await;
}

#[tokio::test]
async fn core_1_6_1_leaves_the_password_alone_and_takes_nothing_for_a_key() {
    use silentsilo_store_v1_6_1 as store_old;
    use silentsilo_sync_v1_6_1 as sync_old;

    let (_dir, root) = rich_with_password().await;
    let (envelope, marker) = (bytes_of(&root, PASSWORD_KEY), bytes_of(&root, MARKER));
    let old: Box<dyn store_old::ObjectStore> = store_old::StoreConfig::Folder {
        path: store_dir(&root),
    }
    .open()
    .unwrap();

    let keys = sync_old::fetch_key_envelopes(&*old).await.unwrap();
    assert_eq!(
        keys.len(),
        3,
        "1.6.1 took the password or its marker for a key"
    );
    assert!(sync_old::read_manifest(&*old).await.unwrap().is_some());
    assert!(
        sync_old::fetch_recovery_envelope(&*old)
            .await
            .unwrap()
            .is_some()
    );

    sync_old::prune_ops_below(&*old, u64::MAX).await.unwrap();
    sync_old::sweep_orphan_blobs(&*old, &HashSet::new(), &HashSet::new())
        .await
        .unwrap();
    assert_untouched(&root, &envelope, &marker, "1.6.1");

    let copy = tempfile::tempdir().unwrap();
    let to: Box<dyn store_old::ObjectStore> = store_old::StoreConfig::Folder {
        path: copy.path().to_path_buf(),
    }
    .open()
    .unwrap();
    sync_old::seed_target(&*old, &*to, &mut |_| {}, &|| false)
        .await
        .unwrap();
    assert_untouched(&root, &envelope, &marker, "1.6.1 seeding");
    republished_on(copy.path(), &root).await;
}

#[tokio::test]
async fn core_1_10_0_leaves_the_password_alone_and_takes_nothing_for_a_key() {
    use silentsilo_store_v1_10_0 as store_old;
    use silentsilo_sync_v1_10_0 as sync_old;

    let (_dir, root) = rich_with_password().await;
    let (envelope, marker) = (bytes_of(&root, PASSWORD_KEY), bytes_of(&root, MARKER));
    let old: Box<dyn store_old::ObjectStore> = store_old::StoreConfig::Folder {
        path: store_dir(&root),
    }
    .open()
    .unwrap();

    let keys = sync_old::fetch_key_envelopes(&*old).await.unwrap();
    assert_eq!(
        keys.len(),
        3,
        "1.10.0 took the password or its marker for a key"
    );
    assert!(sync_old::read_manifest(&*old).await.unwrap().is_some());
    assert!(
        sync_old::fetch_recovery_envelope(&*old)
            .await
            .unwrap()
            .is_some()
    );

    sync_old::prune_ops_below(&*old, u64::MAX).await.unwrap();
    sync_old::sweep_orphan_blobs(&*old, &HashSet::new(), &HashSet::new())
        .await
        .unwrap();
    assert_untouched(&root, &envelope, &marker, "1.10.0");

    let copy = tempfile::tempdir().unwrap();
    let to: Box<dyn store_old::ObjectStore> = store_old::StoreConfig::Folder {
        path: copy.path().to_path_buf(),
    }
    .open()
    .unwrap();
    sync_old::seed_target(&*old, &*to, &mut |_| {}, &|| false)
        .await
        .unwrap();
    assert_untouched(&root, &envelope, &marker, "1.10.0 seeding");
    republished_on(copy.path(), &root).await;
}

#[tokio::test]
async fn core_1_10_4_leaves_the_password_alone_and_takes_nothing_for_a_key() {
    use silentsilo_store_v1_10_4 as store_old;
    use silentsilo_sync_v1_10_4 as sync_old;

    let (_dir, root) = rich_with_password().await;
    let (envelope, marker) = (bytes_of(&root, PASSWORD_KEY), bytes_of(&root, MARKER));
    let old: Box<dyn store_old::ObjectStore> = store_old::StoreConfig::Folder {
        path: store_dir(&root),
    }
    .open()
    .unwrap();

    let keys = sync_old::fetch_key_envelopes(&*old).await.unwrap();
    assert_eq!(
        keys.len(),
        3,
        "1.10.4 took the password or its marker for a key"
    );
    assert!(sync_old::read_manifest(&*old).await.unwrap().is_some());
    assert!(
        sync_old::fetch_recovery_envelope(&*old)
            .await
            .unwrap()
            .is_some()
    );

    sync_old::prune_ops_below(&*old, u64::MAX).await.unwrap();
    sync_old::sweep_orphan_blobs(&*old, &HashSet::new(), &HashSet::new())
        .await
        .unwrap();
    assert_untouched(&root, &envelope, &marker, "1.10.4");

    let copy = tempfile::tempdir().unwrap();
    let to: Box<dyn store_old::ObjectStore> = store_old::StoreConfig::Folder {
        path: copy.path().to_path_buf(),
    }
    .open()
    .unwrap();
    sync_old::seed_target(&*old, &*to, &mut |_| {}, &|| false)
        .await
        .unwrap();
    assert_untouched(&root, &envelope, &marker, "1.10.4 seeding");
    republished_on(copy.path(), &root).await;
}

/// A copy an older release seeded has no password at the root; a current
/// client's pass publishes it there, and it opens with the password.
async fn republished_on(copy: &Path, root: &Path) {
    let to = StoreConfig::Folder {
        path: copy.to_path_buf(),
    }
    .open()
    .unwrap();
    assert!(matches!(
        fetch_password_envelope(&*to).await.unwrap(),
        StoredPassword::Absent
    ));
    let (dek, kek) = open_with_code(root).await;
    let StoredPassword::Envelope(envelope) = fetch_password_envelope(&*store(root)).await.unwrap()
    else {
        panic!("the source lost its password");
    };
    assert!(
        ensure_password_envelope(&*to, &envelope, &kek, &dek)
            .await
            .unwrap()
    );
    let StoredPassword::Envelope(there) = fetch_password_envelope(&*to).await.unwrap() else {
        panic!("not republished");
    };
    assert_eq!(
        unwrap_with_password(&there, FIXTURE_PASSWORD)
            .unwrap()
            .as_bytes(),
        dek.as_bytes()
    );
}

/// What a joining device of each release reads from a silo with no key:
/// the manifest, the recovery envelope, the KEK, an empty key list without
/// an error, and every record.
macro_rules! joins_a_password_only_silo_with_the_code {
    ($name:ident, $store:ident, $sync:ident, $vault:ident, $label:literal) => {
        #[tokio::test]
        async fn $name() {
            use $store as store_old;
            use $sync as sync_old;
            use $vault as vault_old;

            let (_dir, root) = password_only().await;
            let envelope_bytes = bytes_of(&root, PASSWORD_KEY);
            let old: Box<dyn store_old::ObjectStore> = store_old::StoreConfig::Folder {
                path: store_dir(&root),
            }
            .open()
            .unwrap();

            assert!(sync_old::read_manifest(&*old).await.unwrap().is_some());
            let recovery = sync_old::fetch_recovery_envelope(&*old)
                .await
                .unwrap()
                .unwrap();
            let dek = vault_old::unwrap_with_code(&recovery, FIXTURE_CODE)
                .unwrap_or_else(|e| panic!("{}: the code does not open it: {e}", $label));
            let keys = sync_old::fetch_key_envelopes(&*old)
                .await
                .unwrap_or_else(|e| panic!("{}: an empty key list is an error: {e}", $label));
            assert!(
                keys.is_empty(),
                "{}: found a key in a silo that has none",
                $label
            );
            let ops = sync_old::fetch_all_ops_above(&*old, &dek, 0)
                .await
                .unwrap_or_else(|e| panic!("{}: cannot read the records: {e}", $label));
            assert!(!ops.is_empty(), "{}", $label);
            assert_eq!(bytes_of(&root, PASSWORD_KEY), envelope_bytes, "{}", $label);
        }
    };
}

joins_a_password_only_silo_with_the_code!(
    core_1_0_0_joins_a_password_only_silo_with_the_code,
    silentsilo_store_v1_0_0,
    silentsilo_sync_v1_0_0,
    silentsilo_vault_v1_0_0,
    "1.0.0"
);
joins_a_password_only_silo_with_the_code!(
    core_1_6_1_joins_a_password_only_silo_with_the_code,
    silentsilo_store_v1_6_1,
    silentsilo_sync_v1_6_1,
    silentsilo_vault_v1_6_1,
    "1.6.1"
);
joins_a_password_only_silo_with_the_code!(
    core_1_10_0_joins_a_password_only_silo_with_the_code,
    silentsilo_store_v1_10_0,
    silentsilo_sync_v1_10_0,
    silentsilo_vault_v1_10_0,
    "1.10.0"
);
joins_a_password_only_silo_with_the_code!(
    core_1_10_4_joins_a_password_only_silo_with_the_code,
    silentsilo_store_v1_10_4,
    silentsilo_sync_v1_10_4,
    silentsilo_vault_v1_10_4,
    "1.10.4"
);

#[tokio::test]
async fn the_password_of_a_password_only_silo_opens_it_today() {
    let (_dir, root) = password_only().await;
    let (dek, _) = open_with_code(&root).await;
    let StoredPassword::Envelope(envelope) = fetch_password_envelope(&*store(&root)).await.unwrap()
    else {
        panic!("no password");
    };
    assert_eq!(
        unwrap_with_password(&envelope, FIXTURE_PASSWORD)
            .unwrap()
            .as_bytes(),
        dek.as_bytes()
    );
}
