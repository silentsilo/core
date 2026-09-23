//! A snapshot from this build carries what purges left behind (`purged`),
//! which 1.0.0 and 1.6.1 never wrote. What they do with it, by their own
//! code: read the snapshot, ignore the field, and restore the same tree
//! they would have restored from one without it.

use silentsilo_vault::VaultSession;
use silentsilo_vfs::{OpRecord, VaultOp, Vfs, root_folder_id_for};
use uuid::Uuid;

/// A snapshot at a horizon above a purge, so `purged` is not empty.
fn snapshot_with_a_purge() -> silentsilo_vfs::Snapshot {
    let dir = tempfile::tempdir().unwrap();
    let vault_id = Uuid::new_v4();
    let session = VaultSession::provision(dir.path().join("silo"), vault_id, "s").unwrap();
    Vfs::new(&session).ensure_initialized().unwrap();
    let root = root_folder_id_for(vault_id);
    let (old, kept) = (Uuid::new_v4(), Uuid::new_v4());
    let device = Uuid::new_v4();
    let mut prev = None;
    let records: Vec<OpRecord> = [
        VaultOp::CreateFolder {
            id: old,
            parent_id: root,
            name: "Old".into(),
        },
        VaultOp::CreateFolder {
            id: kept,
            parent_id: root,
            name: "Kept".into(),
        },
        VaultOp::TrashFolder { id: old },
        VaultOp::Purge {
            folder_ids: vec![old],
            file_ids: Vec::new(),
        },
        VaultOp::CreateFolder {
            id: Uuid::new_v4(),
            parent_id: kept,
            name: "After".into(),
        },
    ]
    .into_iter()
    .enumerate()
    .map(|(i, op)| {
        let record = OpRecord::authored(
            Uuid::new_v4(),
            i as u64 + 1,
            device,
            1_700_000_000,
            i as u64,
            prev.clone(),
            op,
        );
        prev = Some(record.fingerprint().unwrap());
        record
    })
    .collect();
    silentsilo_vfs::replay(&session.conn, records).unwrap();
    let snapshot = silentsilo_vfs::capture_at(&session.conn, vault_id, 4).unwrap();
    assert!(!snapshot.purged.is_empty(), "the purge is in it");
    snapshot
}

#[test]
fn version_1_6_1_reads_a_snapshot_that_remembers_purges() {
    let snapshot = snapshot_with_a_purge();
    let bytes = snapshot.to_bytes().unwrap();
    let old = silentsilo_vfs_v1_6_1::Snapshot::from_bytes(&bytes).expect("1.6.1 reads it");
    assert_eq!(old.horizon, snapshot.horizon);
    let names = |folders: Vec<String>| {
        let mut n = folders;
        n.sort();
        n
    };
    assert_eq!(
        names(old.folders.iter().map(|f| f.path.clone()).collect()),
        names(snapshot.folders.iter().map(|f| f.path.clone()).collect())
    );
    assert_eq!(old.files.len(), snapshot.files.len());
}

#[test]
fn version_1_0_0_reads_a_snapshot_that_remembers_purges() {
    let snapshot = snapshot_with_a_purge();
    let bytes = snapshot.to_bytes().unwrap();
    let old = silentsilo_vfs_v1_0_0::Snapshot::from_bytes(&bytes).expect("1.0.0 reads it");
    assert_eq!(old.horizon, snapshot.horizon);
    assert_eq!(old.folders.len(), snapshot.folders.len());
    assert_eq!(old.files.len(), snapshot.files.len());
}
