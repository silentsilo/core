//! Content no backup holds is remembered, and forgotten once it turns up.

use silentsilo_store::{FolderStore, ObjectStore};
use silentsilo_sync::{fetch_blob_from_targets, recheck_absent_blobs};
use uuid::Uuid;

#[tokio::test]
async fn a_blob_no_target_holds_is_remembered_until_one_does() {
    let storage = tempfile::tempdir().unwrap();
    let silo = tempfile::tempdir().unwrap();
    let store = FolderStore::new(storage.path().to_path_buf());
    let target = (Uuid::new_v4(), &store as &dyn ObjectStore);
    let blob = Uuid::new_v4();

    assert!(
        fetch_blob_from_targets(&[target], silo.path(), blob)
            .await
            .is_err()
    );
    assert_eq!(
        silentsilo_vault::list_absent_blob_ids(silo.path()),
        vec![blob]
    );

    assert_eq!(recheck_absent_blobs(&[target], silo.path()).await, 0);
    store
        .put(&format!("blobs/{blob}.sslo"), b"bytes".to_vec())
        .await
        .unwrap();
    assert_eq!(recheck_absent_blobs(&[target], silo.path()).await, 1);
    assert!(silentsilo_vault::list_absent_blob_ids(silo.path()).is_empty());

    // Remembered again, then cleared by a download that works.
    store.delete(&format!("blobs/{blob}.sslo")).await.unwrap();
    assert!(
        fetch_blob_from_targets(&[target], silo.path(), blob)
            .await
            .is_err()
    );
    store
        .put(&format!("blobs/{blob}.sslo"), b"bytes".to_vec())
        .await
        .unwrap();
    fetch_blob_from_targets(&[target], silo.path(), blob)
        .await
        .unwrap();
    assert!(silentsilo_vault::list_absent_blob_ids(silo.path()).is_empty());
}
