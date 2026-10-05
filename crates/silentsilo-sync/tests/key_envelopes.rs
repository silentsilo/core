//! Publishing and revoking the wrapped DEKs, plus what a pass refuses to read.
//!
//! Against a folder store rather than a bucket, so these run everywhere.
//! `joining.rs` covers the same ground over real S3 and is skipped unless an
//! endpoint is configured, which is precisely why the revocation bug below
//! survived: nothing exercised it on an ordinary `cargo test`.

use silentsilo_crypto::generate_dek;
use silentsilo_store::{FolderStore, ObjectStore};
use silentsilo_sync::{
    fetch_all_ops_above, fetch_key_envelopes, fetch_missing_ops, publish_key_envelopes,
    reconcile_key_envelopes, revocation_marks,
};
use silentsilo_vault::{StoredFidoCredential, StoredFidoKeys};

fn store(dir: &tempfile::TempDir) -> FolderStore {
    FolderStore::new(dir.path().to_path_buf())
}

fn credential(id: &str, slot: u8) -> StoredFidoCredential {
    StoredFidoCredential {
        kind: silentsilo_vault::KIND_FIDO2.to_string(),
        derivation: silentsilo_vault::DERIVATION_HMAC_V1.to_string(),
        policy: String::new(),
        credential_id: id.into(),
        public_key: "cafe".into(),
        key_slot: slot,
        rp_id: "silentsilo.com".into(),
        label: format!("Key {slot}"),
        wrapped_dek: "deadbeef".into(),
        platform: false,
        revoked: false,
    }
}

async fn published_ids(client: &dyn ObjectStore) -> Vec<String> {
    let mut ids: Vec<String> = fetch_key_envelopes(client)
        .await
        .unwrap()
        .into_iter()
        .map(|k| k.credential_id)
        .collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn enrolled_keys_are_published() {
    let dir = tempfile::tempdir().unwrap();
    let client = store(&dir);
    let keys = StoredFidoKeys {
        keys: vec![credential("aa11", 0), credential("bb22", 1)],
    };

    let report = publish_key_envelopes(&client as &dyn ObjectStore, &keys, true)
        .await
        .unwrap();

    assert_eq!(report.published, 2);
    assert!(report.revoked.is_empty());
    assert_eq!(published_ids(&client).await, vec!["aa11", "bb22"]);
}

#[tokio::test]
async fn a_revoked_key_stops_being_published_and_its_envelope_goes() {
    // The demonstrated hole: removing a key deleted the local row, made one
    // attempt at storage, and reported success whatever happened. A pass that
    // only wrote had no way to notice a credential it no longer knew about,
    // so the published envelope kept opening the vault from any machine.
    let dir = tempfile::tempdir().unwrap();
    let client = store(&dir);

    let mut keys = StoredFidoKeys {
        keys: vec![credential("aa11", 0), credential("bb22", 1)],
    };
    publish_key_envelopes(&client as &dyn ObjectStore, &keys, true)
        .await
        .unwrap();
    assert_eq!(published_ids(&client).await, vec!["aa11", "bb22"]);

    keys.keys[1].revoked = true;
    let report = publish_key_envelopes(&client as &dyn ObjectStore, &keys, true)
        .await
        .unwrap();

    // Nothing written: the surviving envelope is already up there unchanged,
    // and rewriting it every pass is what this stopped doing. What the bucket
    // holds afterwards is the assertion that matters.
    assert_eq!(
        report.published, 0,
        "an unchanged envelope was written again"
    );
    assert_eq!(report.revoked, vec!["bb22"]);
    assert_eq!(published_ids(&client).await, vec!["aa11"]);
}

#[tokio::test]
async fn a_revocation_made_offline_is_retried_on_the_next_pass() {
    // The tombstone's whole reason: the first attempt happened with no
    // storage configured, so nothing was deleted and nothing recorded it.
    let dir = tempfile::tempdir().unwrap();
    let client = store(&dir);

    let mut keys = StoredFidoKeys {
        keys: vec![credential("aa11", 0), credential("bb22", 1)],
    };
    publish_key_envelopes(&client as &dyn ObjectStore, &keys, true)
        .await
        .unwrap();

    // Removed while offline: the row is marked, storage is untouched.
    keys.keys[1].revoked = true;
    assert_eq!(published_ids(&client).await, vec!["aa11", "bb22"]);

    // The next pass that does reach storage finishes the job.
    let report = publish_key_envelopes(&client as &dyn ObjectStore, &keys, true)
        .await
        .unwrap();
    assert_eq!(report.revoked, vec!["bb22"]);
    assert_eq!(published_ids(&client).await, vec!["aa11"]);
}

#[tokio::test]
async fn publishing_does_not_touch_envelopes_this_device_never_heard_of() {
    // Deleting everything absent from the local list would be a reconcile,
    // and it would revoke a key another device enrolled while this one was
    // away. Key envelopes are what let a device join at all, so that mistake
    // locks people out rather than merely losing state.
    let dir = tempfile::tempdir().unwrap();
    let client = store(&dir);

    publish_key_envelopes(
        &client as &dyn ObjectStore,
        &StoredFidoKeys {
            keys: vec![credential("cc33", 7)],
        },
        true,
    )
    .await
    .unwrap();

    publish_key_envelopes(
        &client as &dyn ObjectStore,
        &StoredFidoKeys {
            keys: vec![credential("aa11", 0)],
        },
        true,
    )
    .await
    .unwrap();

    assert_eq!(published_ids(&client).await, vec!["aa11", "cc33"]);
}

#[tokio::test]
async fn a_key_put_back_after_an_offline_removal_keeps_its_envelope() {
    // Enrolment clears the tombstone, so this is belt and braces: were both
    // rows to survive, the delete would undo the publish in the same pass.
    let dir = tempfile::tempdir().unwrap();
    let client = store(&dir);

    let mut revoked = credential("aa11", 0);
    revoked.revoked = true;
    let keys = StoredFidoKeys {
        keys: vec![revoked, credential("aa11", 1)],
    };

    let report = publish_key_envelopes(&client as &dyn ObjectStore, &keys, true)
        .await
        .unwrap();

    assert_eq!(report.published, 1);
    assert!(report.revoked.is_empty());
    assert_eq!(published_ids(&client).await, vec!["aa11"]);
}

#[tokio::test]
async fn an_operation_object_sized_to_exhaust_memory_is_refused() {
    // Storage is not trusted. Records name things and carry a password entry
    // at most, so an object this size is a hostile or broken provider, and
    // reading it whole is how the app runs out of memory.
    let dir = tempfile::tempdir().unwrap();
    let client = store(&dir);

    client
        .put(
            "ops/00000000000000000001-aa-bb.op",
            vec![0u8; 5 * 1024 * 1024],
        )
        .await
        .unwrap();

    let got = fetch_missing_ops(
        &client as &dyn ObjectStore,
        &generate_dek(),
        &Default::default(),
        0,
    )
    .await
    .unwrap();
    assert!(got.records.is_empty());
    assert_eq!(got.unreadable.len(), 1);
    assert!(
        got.unreadable[0].error.contains("far larger"),
        "got: {}",
        got.unreadable[0].error
    );

    // The strict path, which joins and restores use, refuses outright.
    let err = fetch_all_ops_above(&client as &dyn ObjectStore, &generate_dek(), 0)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("far larger"), "got: {err}");
}

#[tokio::test]
async fn an_operation_of_ordinary_size_is_still_read() {
    // The ceiling must not be so eager that it refuses a real record. This
    // one is not decryptable with a fresh DEK, so reaching the unseal error
    // is what proves the size check let it through.
    let dir = tempfile::tempdir().unwrap();
    let client = store(&dir);

    client
        .put("ops/00000000000000000001-aa-bb.op", vec![0u8; 4096])
        .await
        .unwrap();

    let got = fetch_missing_ops(
        &client as &dyn ObjectStore,
        &generate_dek(),
        &Default::default(),
        0,
    )
    .await
    .unwrap();
    assert_eq!(got.unreadable.len(), 1);
    assert!(
        got.unreadable[0].error.contains("key"),
        "the size ceiling refused an ordinary record: {}",
        got.unreadable[0].error
    );
}

#[tokio::test]
async fn a_credential_with_no_wrapped_dek_is_not_published() {
    // It cannot unlock anything on its own, so publishing it would only
    // mislead a joining device into thinking it had a usable key.
    let dir = tempfile::tempdir().unwrap();
    let client = store(&dir);

    let mut useless = credential("aa11", 0);
    useless.wrapped_dek = String::new();

    let report = publish_key_envelopes(
        &client as &dyn ObjectStore,
        &StoredFidoKeys {
            keys: vec![useless],
        },
        true,
    )
    .await
    .unwrap();

    assert_eq!(report.published, 0);
    assert!(published_ids(&client).await.is_empty());
}

#[tokio::test]
async fn a_rewrapped_key_is_republished_even_at_the_same_length() {
    // The envelope is skipped when the bucket already holds it, which is what
    // stops a new version being written every couple of minutes. Deciding
    // that by size would be wrong in the one case that matters: a wrapped DEK
    // is the hex of a fixed-length key, so re-wrapping produces different
    // bytes of identical length. Skipping there leaves a device unable to
    // unlock with the rotated key, and nothing on screen would say why.
    let dir = tempfile::tempdir().unwrap();
    let client = store(&dir);

    let original = credential("aa11", 0);
    publish_key_envelopes(
        &client as &dyn ObjectStore,
        &StoredFidoKeys {
            keys: vec![original.clone()],
        },
        true,
    )
    .await
    .unwrap();

    let mut rewrapped = original.clone();
    rewrapped.wrapped_dek = "feedface".into();
    assert_eq!(
        rewrapped.wrapped_dek.len(),
        original.wrapped_dek.len(),
        "this test only means something while the two are the same length"
    );

    let report = publish_key_envelopes(
        &client as &dyn ObjectStore,
        &StoredFidoKeys {
            keys: vec![rewrapped],
        },
        true,
    )
    .await
    .unwrap();

    assert_eq!(report.published, 1, "the re-wrapped envelope was skipped");
    let held = fetch_key_envelopes(&client as &dyn ObjectStore)
        .await
        .unwrap();
    assert_eq!(held[0].wrapped_dek, "feedface");
}

#[tokio::test]
async fn an_unchanged_envelope_is_left_where_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let client = store(&dir);
    let keys = StoredFidoKeys {
        keys: vec![credential("aa11", 0)],
    };

    publish_key_envelopes(&client as &dyn ObjectStore, &keys, true)
        .await
        .unwrap();
    let second = publish_key_envelopes(&client as &dyn ObjectStore, &keys, true)
        .await
        .unwrap();

    assert_eq!(second.published, 0);
}

/// A key of a kind this build cannot use still belongs in the bucket.
///
/// Publishing is bookkeeping about the silo, not about this machine: the Mac
/// that enrolled a Touch ID key has to be able to put its envelope up, and a
/// Windows client syncing afterwards must not treat "I cannot use this" as
/// "this should not be here". Retiring another platform's key behind its back
/// is how a two-device household ends up with one device locked out.
#[tokio::test]
async fn a_key_of_another_kind_is_published_and_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let client = store(&dir);

    let mut foreign = credential("touch-id-key-1", 1);
    foreign.kind = "secure-enclave".into();
    foreign.platform = true;
    let keys = StoredFidoKeys {
        keys: vec![credential("aa11", 0), foreign],
    };

    let report = publish_key_envelopes(&client as &dyn ObjectStore, &keys, true)
        .await
        .unwrap();
    assert_eq!(report.published, 2, "both envelopes belong in the bucket");

    let held = fetch_key_envelopes(&client as &dyn ObjectStore)
        .await
        .unwrap();
    assert_eq!(held.len(), 2, "reading back must not drop the unknown kind");

    // The half that matters on the reading side: the silo has two keys, and
    // exactly one of them can open it here.
    let held = StoredFidoKeys { keys: held };
    assert_eq!(held.usable().count(), 1);
    assert_eq!(
        held.credential_ids_bytes().expect("no error"),
        vec![vec![0xaa, 0x11]],
        "a credential id that is not hex must not fail the whole join"
    );
}

/// An organisation key stays an organisation key after a trip through storage.
///
/// This is the linchpin the whole escrow feature rests on and the one thing
/// that was never tested. Every guard against an employee cutting the company
/// out keys off `policy` being `org`, and a joined or recovered silo learns
/// that field from nowhere but the published envelope. Were `policy` dropped
/// on publish or fetch, a device that joined from the bucket would read the
/// company's key as an ordinary one and let its holder retire it, with no
/// error and nothing on screen to say the silo had quietly stopped being
/// administered. The field serialises unconditionally today; this fails the
/// day someone makes it skippable.
#[tokio::test]
async fn an_organisation_policy_survives_publish_and_fetch() {
    let dir = tempfile::tempdir().unwrap();
    let client = store(&dir);

    let mut org = credential("aa11", 0);
    org.policy = silentsilo_vault::POLICY_ORG.to_string();
    let keys = StoredFidoKeys {
        keys: vec![org, credential("bb22", 1)],
    };

    publish_key_envelopes(&client as &dyn ObjectStore, &keys, true)
        .await
        .unwrap();

    let held = StoredFidoKeys {
        keys: fetch_key_envelopes(&client as &dyn ObjectStore)
            .await
            .unwrap(),
    };

    assert!(
        held.is_org_controlled(),
        "a silo joined from this bucket must still know it is administered"
    );
    assert_eq!(
        held.managed()
            .map(|k| k.credential_id.as_str())
            .collect::<Vec<_>>(),
        vec!["aa11"],
        "the organisation key, and only it, comes back managed"
    );
}

/// A folder store that records every key read whole.
struct Watched {
    inner: FolderStore,
    read: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl ObjectStore for Watched {
    async fn put(&self, key: &str, body: Vec<u8>) -> Result<(), silentsilo_store::StoreError> {
        self.inner.put(key, body).await
    }
    async fn get(&self, key: &str) -> Result<Vec<u8>, silentsilo_store::StoreError> {
        self.read.lock().unwrap().push(key.to_string());
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
        self.inner.list(prefix).await
    }
    fn describe(&self) -> String {
        self.inner.describe()
    }
}

#[tokio::test]
async fn fetching_envelopes_reads_only_envelopes() {
    let dir = tempfile::tempdir().unwrap();
    let client = Watched {
        inner: store(&dir),
        read: Default::default(),
    };
    let keys = StoredFidoKeys {
        keys: vec![credential("aa11", 0)],
    };
    publish_key_envelopes(&client as &dyn ObjectStore, &keys, true)
        .await
        .unwrap();
    // The KEK envelope and a revocation marker share the prefix and are not
    // JSON: a join used to download both and report them unreadable.
    client.put("keys/content.kek", vec![1; 80]).await.unwrap();
    client
        .put("keys/revoked/bb22.sealed", vec![2; 80])
        .await
        .unwrap();
    client.read.lock().unwrap().clear();

    let held = fetch_key_envelopes(&client as &dyn ObjectStore)
        .await
        .unwrap();

    assert_eq!(held.len(), 1);
    assert_eq!(held[0].credential_id, "aa11");
    assert_eq!(*client.read.lock().unwrap(), vec!["keys/aa11.env"]);
}

#[tokio::test]
async fn a_copy_unplugged_during_a_removal_does_not_bring_the_key_back() {
    let kek = silentsilo_crypto::generate_content_kek();
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (working, drive) = (store(&dir_a), store(&dir_b));
    let both = StoredFidoKeys {
        keys: vec![credential("aa11", 0), credential("bb22", 1)],
    };
    for copy in [&working, &drive] {
        publish_key_envelopes(copy as &dyn ObjectStore, &both, true)
            .await
            .unwrap();
    }

    // bb22 is removed while the drive is unplugged: the working copy gets
    // the marker and loses the envelope, and the tombstone goes.
    let mut removing = both.clone();
    removing.keys[1].revoked = true;
    reconcile_key_envelopes(&working, &kek, &mut removing, 0, &Default::default())
        .await
        .unwrap();
    publish_key_envelopes(&working as &dyn ObjectStore, &removing, true)
        .await
        .unwrap();
    let after = StoredFidoKeys {
        keys: vec![credential("aa11", 0)],
    };

    // Judged on the drive's own markers, the drive puts it back.
    let mut alone = after.clone();
    reconcile_key_envelopes(&drive, &kek, &mut alone, 0, &Default::default())
        .await
        .unwrap();
    assert!(alone.keys.iter().any(|k| k.credential_id == "bb22"));

    // With every copy's markers, it stays removed.
    let marked = revocation_marks(&working, &kek).await.unwrap();
    let mut local = after.clone();
    let outcome = reconcile_key_envelopes(&drive, &kek, &mut local, 0, &marked)
        .await
        .unwrap();
    assert!(outcome.added.is_empty(), "{outcome:?}");
    assert_eq!(local.keys.len(), 1);
}

#[tokio::test]
async fn a_marker_that_does_not_open_counts_for_nothing() {
    let kek = silentsilo_crypto::generate_content_kek();
    let dir = tempfile::tempdir().unwrap();
    let client = store(&dir);
    client
        .put("keys/revoked/bb22.sealed", vec![9; 80])
        .await
        .unwrap();
    assert!(revocation_marks(&client, &kek).await.unwrap().is_empty());
}
