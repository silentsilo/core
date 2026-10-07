//! Audit finding L1: a sealed object's AAD is its 5-byte header, so it does
//! not bind the object's role or its name. Whoever can write to storage can
//! put a real sealed object under another object's name, of the same kind
//! or of another, and it still opens. Every reader has to bind the name to
//! the content itself; these move real objects around and run the readers.
//!
//! The inbox keys and senders are in `inbox.rs`, the activity log in
//! `audit_log.rs` and `silentsilo-audit`, the local key files in
//! `silentsilo-vault`.

use std::collections::HashSet;

use silentsilo_crypto::{MasterDek, generate_content_kek, generate_dek, wrap_content_key};
use silentsilo_store::{FolderStore, ObjectStore};
use silentsilo_sync::inbox::{SenderRecord, ensure_inbox_key, register_sender};
use silentsilo_sync::{
    CONTENT_KEK_KEY, KekState, VerifyDepth, fetch_all_ops_above, fetch_content_kek,
    fetch_key_envelopes, fetch_missing_ops, is_key_revoked, kek_envelope_state, latest_snapshot,
    mark_recovery_disabled, newest_readable_lamport, publish_content_kek,
    publish_content_kek_checked, publish_key_envelopes, push_ops, put_snapshot,
    reconcile_key_envelopes, repair_from, revocation_marks, revoked_at, seed_target_checked,
    verify_against,
};
use silentsilo_vault::{StoredFidoCredential, StoredFidoKeys};
use silentsilo_vfs::{OpRecord, Snapshot, VaultOp};
use uuid::Uuid;

fn store() -> (tempfile::TempDir, FolderStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = FolderStore::new(dir.path().to_path_buf());
    (dir, store)
}

fn record(lamport: u64, device_id: Uuid) -> OpRecord {
    OpRecord::authored(
        Uuid::new_v4(),
        lamport,
        device_id,
        1_700_000_000,
        lamport,
        None,
        VaultOp::CreateFolder {
            id: Uuid::new_v4(),
            parent_id: Uuid::new_v4(),
            name: format!("folder-{lamport}"),
        },
    )
}

fn op_name(record: &OpRecord) -> String {
    format!("ops/{}.op", record.object_key())
}

fn snapshot_name(horizon: u64) -> String {
    format!("snapshots/{horizon:020}.snap")
}

fn snapshot_at(horizon: u64) -> Snapshot {
    Snapshot {
        version: silentsilo_vfs::SNAPSHOT_VERSION,
        vault_id: Uuid::new_v4(),
        horizon,
        captured_at: 1_700_000_000,
        folders: Vec::new(),
        files: Vec::new(),
        passwords: Vec::new(),
        name_claims: Vec::new(),
        device_labels: Vec::new(),
        purged: Default::default(),
    }
}

fn credential(id: &str, wrapped_dek: &str) -> StoredFidoCredential {
    StoredFidoCredential {
        kind: silentsilo_vault::KIND_FIDO2.to_string(),
        derivation: silentsilo_vault::DERIVATION_HMAC_V1.to_string(),
        policy: String::new(),
        credential_id: id.into(),
        public_key: "cafe".into(),
        key_slot: 0,
        rp_id: "silentsilo.com".into(),
        label: format!("Key {id}"),
        wrapped_dek: wrapped_dek.into(),
        platform: false,
        revoked: false,
    }
}

/// A silo's storage with one of every DEK-sealed kind: three records, a
/// snapshot and the KEK envelope. Returns the records.
async fn silo(store: &FolderStore, dek: &MasterDek) -> Vec<OpRecord> {
    let device = Uuid::new_v4();
    let records: Vec<OpRecord> = (1..=3).map(|l| record(l, device)).collect();
    push_ops(store, dek, &records).await.unwrap();
    put_snapshot(store, dek, &snapshot_at(2)).await.unwrap();
    let kek = silentsilo_vault::wrap_kek_bytes(&generate_content_kek(), dek).unwrap();
    publish_content_kek(store, &kek).await.unwrap();
    records
}

async fn copy(store: &FolderStore, from: &str, to: &str) {
    let bytes = store.get(from).await.unwrap();
    store.put(to, bytes).await.unwrap();
}

// ── Operation records ───────────────────────────────────────────────

#[tokio::test]
async fn objects_of_another_kind_under_a_record_name_are_never_applied() {
    let (_dir, store) = store();
    let dek = generate_dek();
    let records = silo(&store, &dek).await;
    let device = records[0].device_id;
    let name = |lamport: u64| format!("ops/{lamport:020}-{device}-{}.op", Uuid::new_v4());
    let (as_snapshot, as_kek) = (name(10), name(11));
    copy(&store, &snapshot_name(2), &as_snapshot).await;
    copy(&store, CONTENT_KEK_KEY, &as_kek).await;

    let got = fetch_missing_ops(&store, &dek, &HashSet::new(), 0)
        .await
        .unwrap();
    assert_eq!(got.records.len(), 3, "only the records themselves");
    let unreadable: HashSet<String> = got.unreadable.into_iter().map(|u| u.key).collect();
    assert_eq!(unreadable, HashSet::from([as_snapshot, as_kek]));
    assert!(fetch_all_ops_above(&store, &dek, 0).await.is_err());
}

#[tokio::test]
async fn a_check_names_a_record_moved_under_another_name_and_a_repair_puts_it_right() {
    let (_dir, target) = store();
    let (_other, source) = store();
    let dek = generate_dek();
    let records = silo(&target, &dek).await;
    push_ops(&source, &dek, &records).await.unwrap();
    // The second record's name on the copy now holds the first record.
    copy(&target, &op_name(&records[0]), &op_name(&records[1])).await;

    let found = verify_against(
        &target,
        &dek,
        &HashSet::new(),
        VerifyDepth::Listing,
        &mut |_| None,
        &mut |_, _| {},
        &|| false,
    )
    .await
    .unwrap();
    assert_eq!(found.records_read, 2);
    assert_eq!(found.damaged.len(), 1, "{found:?}");
    assert_eq!(found.damaged[0].0, op_name(&records[1]));

    // A source that holds the same misplaced bytes is no source.
    let (_third, wrong) = store();
    wrong
        .put(
            &op_name(&records[1]),
            target.get(&op_name(&records[1])).await.unwrap(),
        )
        .await
        .unwrap();
    let report = repair_from(
        &target,
        &found,
        &[("wrong", &wrong as &dyn ObjectStore)],
        &dek,
        &mut |_| None,
        &|| false,
    )
    .await
    .unwrap();
    assert!(report.repaired.is_empty(), "{report:?}");

    let report = repair_from(
        &target,
        &found,
        &[("good", &source as &dyn ObjectStore)],
        &dek,
        &mut |_| None,
        &|| false,
    )
    .await
    .unwrap();
    assert_eq!(report.repaired.len(), 1, "{report:?}");
    let got = fetch_missing_ops(&target, &dek, &HashSet::new(), 0)
        .await
        .unwrap();
    assert_eq!(got.records.len(), 3);
    assert!(got.misplaced.is_empty());
}

// ── Snapshots ───────────────────────────────────────────────────────

#[tokio::test]
async fn objects_of_another_kind_under_a_snapshot_name_are_never_adopted() {
    let (_dir, store) = store();
    let dek = generate_dek();
    let records = silo(&store, &dek).await;

    for moved in [op_name(&records[2]), CONTENT_KEK_KEY.to_string()] {
        copy(&store, &moved, &snapshot_name(50)).await;
        assert!(
            latest_snapshot(&store, &dek).await.is_err(),
            "{moved} was read as a snapshot"
        );
    }
    store.delete(&snapshot_name(50)).await.unwrap();
    assert_eq!(
        latest_snapshot(&store, &dek)
            .await
            .unwrap()
            .unwrap()
            .horizon,
        2
    );
}

// ── The KEK envelope ────────────────────────────────────────────────

#[tokio::test]
async fn objects_of_another_kind_at_the_kek_envelope_are_not_a_key() {
    // One per silo, so nothing of its own kind can be moved there.
    let (_dir, store) = store();
    let dek = generate_dek();
    let records = silo(&store, &dek).await;
    let genuine = store.get(CONTENT_KEK_KEY).await.unwrap();

    for moved in [op_name(&records[0]), snapshot_name(2)] {
        copy(&store, &moved, CONTENT_KEK_KEY).await;
        let held = fetch_content_kek(&store).await.unwrap().unwrap();
        assert!(silentsilo_vault::unwrap_kek_bytes(&held, &dek).is_err());
        // The records beside it still open: storage was written to.
        assert_eq!(
            kek_envelope_state(&store, &dek).await.unwrap(),
            KekState::Replaced,
            "{moved} read as the silo's content key"
        );
        // A pass does not take it as current, and does not write over it.
        assert!(
            publish_content_kek_checked(&store, &dek, &genuine)
                .await
                .is_err()
        );
        assert_eq!(store.get(CONTENT_KEK_KEY).await.unwrap(), held);
    }
}

#[tokio::test]
async fn a_record_copied_under_a_newer_name_is_no_witness() {
    // A device on a retired key reads the rotated envelope. Records sealed
    // under its old key, copied under the newest names, used to count as
    // ones that still open, and turned "rotated" into "replaced".
    let (_dir, store) = store();
    let (old, new) = (generate_dek(), generate_dek());
    let records = silo(&store, &new).await;
    let stale = record(1, Uuid::new_v4());
    let (_scratch, elsewhere) = self::store();
    push_ops(&elsewhere, &old, std::slice::from_ref(&stale))
        .await
        .unwrap();
    let bytes = elsewhere.get(&op_name(&stale)).await.unwrap();
    for lamport in 900..905 {
        let planted = format!(
            "ops/{lamport:020}-{}-{}.op",
            records[0].device_id,
            Uuid::new_v4()
        );
        store.put(&planted, bytes.clone()).await.unwrap();
    }

    assert_eq!(
        kek_envelope_state(&store, &old).await.unwrap(),
        KekState::Rotated
    );

    // Nor does it lift the newest record a key opens there.
    let (_dir, current) = self::store();
    let records = silo(&current, &old).await;
    copy(
        &current,
        &op_name(&records[1]),
        &format!(
            "ops/{:020}-{}-{}.op",
            900, records[1].device_id, records[1].op_id
        ),
    )
    .await;
    assert_eq!(
        newest_readable_lamport(&current, &old).await.unwrap(),
        Some(3)
    );
}

#[tokio::test]
async fn a_seed_copies_nothing_that_is_not_what_its_name_says() {
    let (_a, from) = store();
    let (_b, to) = store();
    let dek = generate_dek();
    let records = silo(&from, &dek).await;
    let kek = silentsilo_vault::wrap_kek_bytes(&generate_content_kek(), &dek).unwrap();
    publish_content_kek(&to, &kek).await.unwrap();
    copy(&from, &op_name(&records[0]), CONTENT_KEK_KEY).await;
    copy(&from, &op_name(&records[0]), &op_name(&records[1])).await;
    copy(&from, &op_name(&records[0]), &snapshot_name(2)).await;

    let outcome = seed_target_checked(
        &from,
        &to,
        &dek,
        &StoredFidoKeys { keys: Vec::new() },
        &mut |_| {},
        &|| false,
    )
    .await
    .unwrap();

    assert_eq!(outcome.stale, 3, "{outcome:?}");
    assert_eq!(to.get(CONTENT_KEK_KEY).await.unwrap(), kek);
    assert!(to.head(&op_name(&records[1])).await.unwrap().is_none());
    assert!(to.head(&snapshot_name(2)).await.unwrap().is_none());
    assert!(to.head(&op_name(&records[0])).await.unwrap().is_some());
}

// ── Revocation markers ──────────────────────────────────────────────

fn marker_name(id: &str) -> String {
    format!("keys/revoked/{id}.sealed")
}

#[tokio::test]
async fn a_revocation_marker_moved_under_another_keys_name_is_not_honoured() {
    let (_dir, store) = store();
    let kek = generate_content_kek();
    let mut removed = StoredFidoKeys {
        keys: vec![credential("aa11", "01"), credential("bb22", "02")],
    };
    removed.keys[0].revoked = true;
    reconcile_key_envelopes(&store, &kek, &mut removed, 7, &HashSet::new())
        .await
        .unwrap();
    mark_recovery_disabled(&store, &kek, 9).await.unwrap();
    assert!(is_key_revoked(&store, &kek, "aa11").await.unwrap());

    copy(&store, &marker_name("aa11"), &marker_name("bb22")).await;
    copy(&store, &marker_name("recovery"), &marker_name("cc33")).await;
    store.delete(&marker_name("recovery")).await.unwrap();
    copy(&store, &marker_name("aa11"), &marker_name("recovery")).await;

    for id in ["bb22", "cc33"] {
        assert!(!is_key_revoked(&store, &kek, id).await.unwrap(), "{id}");
        assert_eq!(revoked_at(&store, &kek, id).await.unwrap(), None, "{id}");
    }
    assert_eq!(revoked_at(&store, &kek, "recovery").await.unwrap(), None);
    assert_eq!(
        revocation_marks(&store, &kek).await.unwrap(),
        HashSet::from(["aa11".to_string()])
    );

    let mut other = StoredFidoKeys {
        keys: vec![
            credential("bb22", "02"),
            credential("cc33", "03"),
            credential("dd44", "04"),
        ],
    };
    let outcome = reconcile_key_envelopes(&store, &kek, &mut other, 8, &HashSet::new())
        .await
        .unwrap();
    assert!(outcome.revoked.is_empty(), "{outcome:?}");
    assert!(other.keys.iter().all(|k| !k.revoked));
}

#[tokio::test]
async fn objects_of_another_kind_under_a_marker_name_are_not_honoured() {
    let (_dir, store) = store();
    let kek = generate_content_kek();
    let dek = generate_dek();
    let sender = Uuid::new_v4();
    register_sender(
        &store,
        &kek,
        &SenderRecord {
            version: 1,
            sender_id: sender,
            public_key: "04".into(),
            credential_id: "bb22".into(),
            label: "Phone".into(),
            created_at: 1,
        },
    )
    .await
    .unwrap();
    let (inbox_key, _) = ensure_inbox_key(&store, &kek).await.unwrap();
    let records = silo(&store, &dek).await;
    // A content key wrapped under the KEK, as records carry them.
    let content = wrap_content_key(&silentsilo_crypto::generate_content_key(), &kek).unwrap();
    store
        .put(&marker_name("ee55"), hex::decode(content).unwrap())
        .await
        .unwrap();

    copy(
        &store,
        &format!("inbox/senders/{sender}.sealed"),
        &marker_name("bb22"),
    )
    .await;
    copy(
        &store,
        &format!("inbox/keys/{inbox_key}.sealed"),
        &marker_name("cc33"),
    )
    .await;
    copy(&store, &op_name(&records[0]), &marker_name("dd44")).await;

    assert!(revocation_marks(&store, &kek).await.unwrap().is_empty());
    for id in ["bb22", "cc33", "dd44", "ee55"] {
        assert!(!is_key_revoked(&store, &kek, id).await.unwrap(), "{id}");
    }
}

// ── Key envelopes ───────────────────────────────────────────────────

#[tokio::test]
async fn a_key_envelope_moved_under_another_keys_name_opens_only_for_its_own_key() {
    // Envelopes are plain JSON: the reader takes the key from inside, and
    // the wrapped DEK opens only under that key's wrap key.
    let (_dir, store) = store();
    let dek = generate_dek();
    let (key_a, key_b) = ([1u8; 32], [2u8; 32]);
    let wrapped = hex::encode(silentsilo_vault::wrap_dek_bytes(&dek, &key_a).unwrap());
    let keys = StoredFidoKeys {
        keys: vec![credential("aa11", &wrapped)],
    };
    publish_key_envelopes(&store, &keys, true).await.unwrap();
    copy(&store, "keys/aa11.env", "keys/bb22.env").await;

    let read = fetch_key_envelopes(&store).await.unwrap();
    assert_eq!(read.len(), 2);
    assert!(read.iter().all(|k| k.credential_id == "aa11"));
    assert!(silentsilo_vault::unwrap_dek_hex(&read[1].wrapped_dek, &key_b).is_err());
    assert_eq!(
        silentsilo_vault::unwrap_dek_hex(&read[1].wrapped_dek, &key_a)
            .unwrap()
            .as_bytes(),
        dek.as_bytes()
    );
}
