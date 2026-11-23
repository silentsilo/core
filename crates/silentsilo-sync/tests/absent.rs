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
        fetch_blob_from_targets(&[target], silo.path(), blob, true)
            .await
            .is_err()
    );
    assert_eq!(
        silentsilo_vault::list_absent_blob_ids(silo.path()),
        vec![blob]
    );

    assert_eq!(recheck_absent_blobs(&[target], silo.path()).await, 0);
    store
        .put(
            &format!("blobs/{blob}.sslo"),
            silentsilo_testkit::fake_blob(blob.as_bytes(), b"bytes"),
        )
        .await
        .unwrap();
    assert_eq!(recheck_absent_blobs(&[target], silo.path()).await, 1);
    assert!(silentsilo_vault::list_absent_blob_ids(silo.path()).is_empty());

    // Remembered again, then cleared by a download that works.
    store.delete(&format!("blobs/{blob}.sslo")).await.unwrap();
    assert!(
        fetch_blob_from_targets(&[target], silo.path(), blob, true)
            .await
            .is_err()
    );
    store
        .put(
            &format!("blobs/{blob}.sslo"),
            silentsilo_testkit::fake_blob(blob.as_bytes(), b"bytes"),
        )
        .await
        .unwrap();
    fetch_blob_from_targets(&[target], silo.path(), blob, true)
        .await
        .unwrap();
    assert!(silentsilo_vault::list_absent_blob_ids(silo.path()).is_empty());

    // A list that leaves a copy out records nothing.
    store.delete(&format!("blobs/{blob}.sslo")).await.unwrap();
    std::fs::remove_file(silo.path().join("blobs").join(format!("{blob}.sslo"))).ok();
    assert!(
        fetch_blob_from_targets(&[target], silo.path(), blob, false)
            .await
            .is_err()
    );
    assert!(silentsilo_vault::list_absent_blob_ids(silo.path()).is_empty());
}

#[tokio::test]
async fn a_copy_that_holds_something_else_under_the_name_is_passed_over() {
    // Another blob copied under this one's name, or bytes that are no blob
    // at all. Taken into the cache, they were opened as the file and sent
    // to every copy that lacked it.
    let wrong = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    let silo = tempfile::tempdir().unwrap();
    let blob = Uuid::new_v4();
    let key = format!("blobs/{blob}.sslo");
    let wrong_store = FolderStore::new(wrong.path().to_path_buf());
    let right_store = FolderStore::new(right.path().to_path_buf());
    let genuine = silentsilo_testkit::fake_blob(blob.as_bytes(), b"the file");
    right_store.put(&key, genuine.clone()).await.unwrap();
    let cached = silo.path().join("blobs").join(format!("{blob}.sslo"));

    for planted in [
        silentsilo_testkit::fake_blob(Uuid::new_v4().as_bytes(), b"another file"),
        b"not a blob".to_vec(),
    ] {
        wrong_store.put(&key, planted).await.unwrap();
        let alone = [(Uuid::new_v4(), &wrong_store as &dyn ObjectStore)];
        assert!(
            fetch_blob_from_targets(&alone, silo.path(), blob, false)
                .await
                .is_err()
        );
        assert!(!cached.exists(), "the planted bytes reached the cache");

        let both = [
            (Uuid::new_v4(), &wrong_store as &dyn ObjectStore),
            (Uuid::new_v4(), &right_store as &dyn ObjectStore),
        ];
        fetch_blob_from_targets(&both, silo.path(), blob, true)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&cached).unwrap(), genuine);
        std::fs::remove_file(&cached).unwrap();
    }
}
