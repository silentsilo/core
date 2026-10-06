//! The activity log lives under `audit/`, which no earlier release lists.
//! What they delete from storage, by their own code: operation records a
//! snapshot covers (`prune_ops_below`) and blobs nothing references
//! (`sweep_orphan_blobs`). Both run here, as 1.0.0 and 1.6.1 shipped them,
//! over storage that holds a log, and the log comes out byte for byte.

use std::collections::HashSet;
use std::path::Path;

use silentsilo_audit::{
    AuditKey, Event, KeyPair, Scope, Segment, audit_key_path, codes, seal_event,
};
use uuid::Uuid;

/// A storage folder with a log in it, and something each old routine
/// deletes, so it is plain the routines ran.
fn storage_with_a_log(root: &Path) -> Vec<(String, Vec<u8>)> {
    let keys = KeyPair::generate();
    let device = Uuid::new_v4();
    let record = seal_event(&keys.public, device, &Event::new(codes::UNLOCKED, 1)).unwrap();
    let segment = Segment {
        device,
        seq: 0,
        prev: [0; 32],
        closed_at: 1,
        records: vec![record],
    };
    let key = AuditKey::new(&keys, Scope::Silo, 1);
    let log = vec![
        (segment.key(), segment.to_bytes()),
        (audit_key_path(&keys.id()), key.to_json().unwrap()),
        ("audit/policy.sealed".to_string(), vec![7; 40]),
    ];

    let mut objects = log.clone();
    // A record below any horizon, and a blob nothing references.
    objects.push((
        format!("ops/{:020}-{device}-{}.op", 1, Uuid::new_v4()),
        vec![1; 16],
    ));
    objects.push((format!("blobs/{}.sslo", Uuid::new_v4()), vec![2; 16]));
    for (key, bytes) in &objects {
        let path = root.join(key);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    log
}

fn assert_log_intact(root: &Path, log: &[(String, Vec<u8>)]) {
    for (key, bytes) in log {
        assert_eq!(&std::fs::read(root.join(key)).unwrap(), bytes, "{key}");
    }
}

fn gone(root: &Path, prefix: &str) -> bool {
    std::fs::read_dir(root.join(prefix))
        .map(|mut d| d.next().is_none())
        .unwrap_or(true)
}

#[tokio::test]
async fn version_1_0_0_compacts_and_sweeps_around_the_log() {
    use silentsilo_store_v1_0_0::FolderStore;
    use silentsilo_sync_v1_0_0 as sync;

    let dir = tempfile::tempdir().unwrap();
    let log = storage_with_a_log(dir.path());
    let store = FolderStore::new(dir.path().to_path_buf());

    sync::prune_ops_below(&store, u64::MAX).await.unwrap();
    // A sweep deletes only what the previous one named, so twice.
    let first = sync::sweep_orphan_blobs(&store, &HashSet::new(), &HashSet::new())
        .await
        .unwrap();
    let named: HashSet<Uuid> = first.candidates.into_iter().collect();
    sync::sweep_orphan_blobs(&store, &HashSet::new(), &named)
        .await
        .unwrap();

    assert!(gone(dir.path(), "ops"), "1.0.0 pruned the record");
    assert!(gone(dir.path(), "blobs"), "1.0.0 swept the blob");
    assert_log_intact(dir.path(), &log);
}

#[tokio::test]
async fn version_1_6_1_compacts_and_sweeps_around_the_log() {
    use silentsilo_store_v1_6_1::FolderStore;
    use silentsilo_sync_v1_6_1 as sync;

    let dir = tempfile::tempdir().unwrap();
    let log = storage_with_a_log(dir.path());
    let store = FolderStore::new(dir.path().to_path_buf());

    sync::prune_ops_below(&store, u64::MAX).await.unwrap();
    let first = sync::sweep_orphan_blobs(&store, &HashSet::new(), &HashSet::new())
        .await
        .unwrap();
    let named: HashSet<Uuid> = first.candidates.into_iter().collect();
    sync::sweep_orphan_blobs(&store, &HashSet::new(), &named)
        .await
        .unwrap();

    assert!(gone(dir.path(), "ops"), "1.6.1 pruned the record");
    assert!(gone(dir.path(), "blobs"), "1.6.1 swept the blob");
    assert_log_intact(dir.path(), &log);
}
