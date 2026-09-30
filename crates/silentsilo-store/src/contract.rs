//! The assertions every backend must pass, one function each, taking a
//! fresh, empty store. `tests/contract.rs` runs them against the folder,
//! S3, WebDAV and SFTP backends; `silentsilo-cloud` runs them against its
//! fake OneDrive, Dropbox and Google Drive servers and, when configured,
//! the real ones. Test code: nothing in an app calls it.

use std::ops::ControlFlow;

use crate::{ObjectStore, StoreError};

pub async fn an_object_survives_the_round_trip_byte_for_byte(store: Box<dyn ObjectStore>) {
    // Binary with NULs and high bytes: everything stored is ciphertext,
    // and a backend that mangled either would corrupt a file beyond
    // recovery while looking like it worked.
    let content: Vec<u8> = (0u8..=255).cycle().take(5000).collect();
    store.put("ops/000001.op", content.clone()).await.unwrap();

    assert_eq!(store.get("ops/000001.op").await.unwrap(), content);
}

pub async fn head_answers_without_moving_the_bytes(store: Box<dyn ObjectStore>) {
    assert_eq!(store.head("blobs/missing.sslo").await.unwrap(), None);

    store.put("blobs/a.sslo", vec![7; 1234]).await.unwrap();
    assert_eq!(store.head("blobs/a.sslo").await.unwrap(), Some(1234));
}

pub async fn a_prefix_read_returns_the_first_bytes_only(store: Box<dyn ObjectStore>) {
    let content: Vec<u8> = (0u8..=255).cycle().take(5000).collect();
    store.put("blobs/p.sslo", content.clone()).await.unwrap();

    assert_eq!(
        store.get_prefix("blobs/p.sslo", 82).await.unwrap(),
        content[..82]
    );
    assert_eq!(
        store.get_prefix("blobs/p.sslo", 9000).await.unwrap(),
        content,
        "shorter than asked is the whole object"
    );
    assert!(matches!(
        store.get_prefix("blobs/none.sslo", 82).await,
        Err(StoreError::NotFound(_))
    ));
}

pub async fn listing_is_ordered_by_key(store: Box<dyn ObjectStore>) {
    // Operation keys are the Lamport counter zero-padded, so
    // lexicographic order is logical order. Written out of order on
    // purpose: a backend that echoed insertion order would pass a
    // weaker test than this.
    for n in [7u32, 1, 30, 2] {
        store
            .put(&format!("ops/{n:020}.op"), vec![0])
            .await
            .unwrap();
    }

    let keys: Vec<String> = store
        .list("ops/")
        .await
        .unwrap()
        .into_iter()
        .map(|o| o.key)
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "callers rely on lexicographic order");
    assert_eq!(keys.len(), 4);
}

/// The normal state of storage nothing has been written to yet.
pub async fn listing_an_empty_prefix_is_not_an_error(store: Box<dyn ObjectStore>) {
    assert!(store.list("ops/").await.unwrap().is_empty());
}

pub async fn listing_does_not_leak_a_neighbouring_prefix(store: Box<dyn ObjectStore>) {
    store.put("ops/000001.op", vec![1]).await.unwrap();
    store.put("blobs/a.sslo", vec![2]).await.unwrap();

    let keys: Vec<String> = store
        .list("ops/")
        .await
        .unwrap()
        .into_iter()
        .map(|o| o.key)
        .collect();
    assert_eq!(keys, vec!["ops/000001.op".to_string()]);
}

/// Callers use delete to clean up after a failure, where the object may
/// never have landed.
pub async fn deleting_something_absent_is_the_desired_end_state(store: Box<dyn ObjectStore>) {
    store.delete("blobs/never-existed.sslo").await.unwrap();
}

pub async fn a_deleted_object_is_gone_from_both_head_and_list(store: Box<dyn ObjectStore>) {
    store.put("blobs/a.sslo", vec![1, 2, 3]).await.unwrap();
    store.delete("blobs/a.sslo").await.unwrap();

    assert_eq!(store.head("blobs/a.sslo").await.unwrap(), None);
    assert!(store.list("blobs/").await.unwrap().is_empty());
}

pub async fn reading_something_absent_reports_not_found(store: Box<dyn ObjectStore>) {
    let err = store.get("ops/nothing-here.op").await.unwrap_err();
    assert!(
        matches!(err, StoreError::NotFound(_)),
        "callers distinguish a missing object from a broken connection: got {err:?}"
    );
}

/// Not needed by the operation log, which never rewrites, but the
/// manifest and the key envelopes do.
pub async fn rewriting_a_key_replaces_it(store: Box<dyn ObjectStore>) {
    store.put("vault.json", b"first".to_vec()).await.unwrap();
    store.put("vault.json", b"second".to_vec()).await.unwrap();

    assert_eq!(store.get("vault.json").await.unwrap(), b"second");
    assert_eq!(
        store.list("").await.unwrap().len(),
        1,
        "one key, one object"
    );
}

/// Two devices publishing the manifest, or two runs of a phone's backup
/// job sending the same item. A shared temporary name made one of them
/// fail with "no such file".
pub async fn two_writers_of_one_key_at_once_both_succeed(store: Box<dyn ObjectStore>) {
    let key = "inbox/items/race.sslo";
    let first = vec![1u8; 256 * 1024];
    let second = vec![2u8; 256 * 1024];
    let (a, b) = tokio::join!(
        store.put(key, first.clone()),
        store.put(key, second.clone())
    );
    a.expect("the first writer succeeds");
    b.expect("the second writer succeeds");

    let stored = store.get(key).await.unwrap();
    assert!(stored == first || stored == second, "one whole write wins");
    let listed = store.list("inbox/items/").await.unwrap();
    assert_eq!(listed.len(), 1, "no temporary file is listed: {listed:?}");
    store.delete(key).await.unwrap();
}

/// The inbox import copies an item into `blobs/` before it records the
/// file, and deletes the original only afterwards. A copy that moved,
/// truncated or failed to replace would lose a photo nobody else holds.
pub async fn a_copy_is_the_same_bytes_under_the_new_key_and_leaves_the_original(
    store: Box<dyn ObjectStore>,
) {
    let bytes: Vec<u8> = (0..(1024 * 1024 + 7)).map(|i| (i % 251) as u8).collect();
    store
        .put("inbox/items/a.sslo", bytes.clone())
        .await
        .unwrap();
    store.put("blobs/b.sslo", vec![9; 10]).await.unwrap();

    store
        .copy("inbox/items/a.sslo", "blobs/b.sslo")
        .await
        .unwrap();

    assert_eq!(
        store.get("blobs/b.sslo").await.unwrap(),
        bytes,
        "{}: the copy is not the original",
        store.describe()
    );
    assert_eq!(
        store.get("inbox/items/a.sslo").await.unwrap(),
        bytes,
        "{}: the original changed",
        store.describe()
    );

    let missing = store.copy("inbox/items/absent.sslo", "blobs/c.sslo").await;
    assert!(
        matches!(missing, Err(StoreError::NotFound(_))),
        "{}: copying nothing must say so: got {missing:?}",
        store.describe()
    );
    assert_eq!(store.head("blobs/c.sslo").await.unwrap(), None);
}

pub async fn the_write_check_round_trips_and_leaves_nothing_behind(store: Box<dyn ObjectStore>) {
    store.check().await.unwrap();
    assert!(
        store.list("").await.unwrap().is_empty(),
        "a probe left in the user's own storage is litter"
    );
}

/// Blobs move through disk rather than memory, so every backend has to
/// implement the file-shaped transfer as well as the buffer-shaped one.
/// Overridden natively by each of them and easy to get subtly wrong: a
/// truncated upload or a download that drops its tail is a file the user
/// cannot open, and nothing above this layer would notice.
pub async fn a_file_survives_the_round_trip_through_disk(store: Box<dyn ObjectStore>) {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("blob.sslo");
    let restored = dir.path().join("restored.sslo");
    // Bigger than one buffer of every streaming loop in the backends,
    // and not a round multiple of any of them, so a boundary bug shows.
    let bytes: Vec<u8> = (0..(1024 * 1024 + 7)).map(|i| (i % 251) as u8).collect();
    std::fs::write(&source, &bytes).unwrap();

    store
        .put_from_file("blobs/streamed.sslo", &source)
        .await
        .unwrap();

    assert_eq!(
        store.head("blobs/streamed.sslo").await.unwrap(),
        Some(bytes.len() as i64),
        "{}: the stored object is not the size that went up",
        store.describe()
    );
    store
        .get_to_file("blobs/streamed.sslo", &restored)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(&restored).unwrap(),
        bytes,
        "{}: the bytes came back different",
        store.describe()
    );

    // And the buffer-shaped read agrees with the file-shaped one, since
    // callers mix them: verify streams, exports do not.
    assert_eq!(
        store.get("blobs/streamed.sslo").await.unwrap(),
        bytes,
        "{}: get and get_to_file disagree",
        store.describe()
    );
}

/// An empty file is a real case: a zero-byte document, or a blob whose
/// content was truncated before it was sealed. A backend that refuses one,
/// or turns it into a missing object, breaks the sync pass rather than the
/// file.
pub async fn an_empty_file_round_trips_too(store: Box<dyn ObjectStore>) {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("empty.bin");
    let restored = dir.path().join("restored.bin");
    std::fs::write(&source, b"").unwrap();

    store
        .put_from_file("blobs/empty.sslo", &source)
        .await
        .unwrap();

    assert_eq!(
        store.head("blobs/empty.sslo").await.unwrap(),
        Some(0),
        "{}: an empty object went missing",
        store.describe()
    );
    store
        .get_to_file("blobs/empty.sslo", &restored)
        .await
        .unwrap();
    assert!(std::fs::read(&restored).unwrap().is_empty());
}

/// Downloading something that is not there must not leave a file behind:
/// the caller renames what it fetched into the blob cache, and an empty
/// file there reads as content that decrypts to nothing.
pub async fn a_download_that_finds_nothing_reports_it(store: Box<dyn ObjectStore>) {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("nothing.sslo");

    let result = store.get_to_file("blobs/absent.sslo", &dest).await;

    assert!(
        matches!(result, Err(StoreError::NotFound(_))),
        "{}: expected NotFound, got {result:?}",
        store.describe()
    );
}

/// The reporting transfers carry the same bytes as the plain ones and say
/// so as they go: what they report has to add up to the file, on every
/// backend, or a progress bar drawn from it lies in both directions.
pub async fn what_a_transfer_reports_adds_up_to_the_file(store: Box<dyn ObjectStore>) {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("blob.sslo");
    let restored = dir.path().join("restored.sslo");
    // Not a round multiple of any backend's buffer, so a boundary bug
    // shows up as a count that does not add up.
    let bytes: Vec<u8> = (0..(1024 * 1024 + 7)).map(|i| (i % 251) as u8).collect();
    std::fs::write(&source, &bytes).unwrap();

    let mut up: Vec<u64> = Vec::new();
    store
        .put_from_file_reporting("blobs/watched.sslo", &source, &mut |moved| {
            up.push(moved);
            ControlFlow::Continue(())
        })
        .await
        .unwrap();
    assert_eq!(
        up.iter().sum::<u64>(),
        bytes.len() as u64,
        "{}: the upload reported {up:?}",
        store.describe()
    );
    assert_eq!(
        store.head("blobs/watched.sslo").await.unwrap(),
        Some(bytes.len() as i64),
        "{}: the object is not the size that went up",
        store.describe()
    );

    let mut down: Vec<u64> = Vec::new();
    store
        .get_to_file_reporting("blobs/watched.sslo", &restored, &mut |moved| {
            down.push(moved);
            ControlFlow::Continue(())
        })
        .await
        .unwrap();
    assert_eq!(
        down.iter().sum::<u64>(),
        bytes.len() as u64,
        "{}: the download reported {down:?}",
        store.describe()
    );
    assert_eq!(
        std::fs::read(&restored).unwrap(),
        bytes,
        "{}: the bytes came back different",
        store.describe()
    );
}

/// Stopping a transfer is answered as a stop rather than as a failure, and
/// it never leaves half an object behind: a truncated blob is content that
/// decrypts to nothing, and nothing above this layer would notice.
pub async fn a_stopped_transfer_says_so_and_leaves_nothing_half_written(
    store: Box<dyn ObjectStore>,
) {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("blob.sslo");
    let dest = dir.path().join("down.sslo");
    let bytes: Vec<u8> = (0..(1024 * 1024 + 7)).map(|i| (i % 251) as u8).collect();
    std::fs::write(&source, &bytes).unwrap();

    let stopped = store
        .put_from_file_reporting("blobs/stopped.sslo", &source, &mut |_| {
            ControlFlow::Break(())
        })
        .await;
    assert!(
        matches!(stopped, Err(StoreError::Cancelled)),
        "{}: a stop is not a failure to retry: got {stopped:?}",
        store.describe()
    );
    // Either the key was never written or the whole object is there.
    // Which of the two depends on where the backend can break off, but
    // a short object is never an answer.
    match store.head("blobs/stopped.sslo").await.unwrap() {
        None => {}
        Some(size) => assert_eq!(
            size,
            bytes.len() as i64,
            "{}: a stopped upload left part of an object",
            store.describe()
        ),
    }

    store
        .put_from_file("blobs/whole.sslo", &source)
        .await
        .unwrap();
    let stopped = store
        .get_to_file_reporting("blobs/whole.sslo", &dest, &mut |_| ControlFlow::Break(()))
        .await;
    assert!(
        matches!(stopped, Err(StoreError::Cancelled)),
        "{}: got {stopped:?}",
        store.describe()
    );
    assert!(
        !dest.exists(),
        "{}: a stopped download left a file a caller would take for an object",
        store.describe()
    );
}

/// Every backend answers the stale-upload sweep, with nothing to do on an
/// empty prefix. Only S3 has unfinished uploads at all.
pub async fn every_backend_answers_the_stale_upload_sweep(store: Box<dyn ObjectStore>) {
    let day = std::time::Duration::from_secs(24 * 60 * 60);
    assert_eq!(store.abort_stale_uploads("blobs/", day).await.unwrap(), 0);
}

/// Every function above as a `#[tokio::test]`, run against the store
/// `$make` (an async expression giving a `Box<dyn ObjectStore>`). One test
/// per assertion, so a failure names the rule it broke.
#[macro_export]
macro_rules! contract_tests {
    ($make:expr) => {
        #[tokio::test]
        async fn an_object_survives_the_round_trip_byte_for_byte() {
            $crate::contract::an_object_survives_the_round_trip_byte_for_byte($make.await).await;
        }
        #[tokio::test]
        async fn head_answers_without_moving_the_bytes() {
            $crate::contract::head_answers_without_moving_the_bytes($make.await).await;
        }
        #[tokio::test]
        async fn a_prefix_read_returns_the_first_bytes_only() {
            $crate::contract::a_prefix_read_returns_the_first_bytes_only($make.await).await;
        }
        #[tokio::test]
        async fn listing_is_ordered_by_key() {
            $crate::contract::listing_is_ordered_by_key($make.await).await;
        }
        #[tokio::test]
        async fn listing_an_empty_prefix_is_not_an_error() {
            $crate::contract::listing_an_empty_prefix_is_not_an_error($make.await).await;
        }
        #[tokio::test]
        async fn listing_does_not_leak_a_neighbouring_prefix() {
            $crate::contract::listing_does_not_leak_a_neighbouring_prefix($make.await).await;
        }
        #[tokio::test]
        async fn deleting_something_absent_is_the_desired_end_state() {
            $crate::contract::deleting_something_absent_is_the_desired_end_state($make.await).await;
        }
        #[tokio::test]
        async fn a_deleted_object_is_gone_from_both_head_and_list() {
            $crate::contract::a_deleted_object_is_gone_from_both_head_and_list($make.await).await;
        }
        #[tokio::test]
        async fn reading_something_absent_reports_not_found() {
            $crate::contract::reading_something_absent_reports_not_found($make.await).await;
        }
        #[tokio::test]
        async fn rewriting_a_key_replaces_it() {
            $crate::contract::rewriting_a_key_replaces_it($make.await).await;
        }
        #[tokio::test]
        async fn two_writers_of_one_key_at_once_both_succeed() {
            $crate::contract::two_writers_of_one_key_at_once_both_succeed($make.await).await;
        }
        #[tokio::test]
        async fn a_copy_is_the_same_bytes_under_the_new_key_and_leaves_the_original() {
            $crate::contract::a_copy_is_the_same_bytes_under_the_new_key_and_leaves_the_original(
                $make.await,
            )
            .await;
        }
        #[tokio::test]
        async fn the_write_check_round_trips_and_leaves_nothing_behind() {
            $crate::contract::the_write_check_round_trips_and_leaves_nothing_behind($make.await)
                .await;
        }
        #[tokio::test]
        async fn a_file_survives_the_round_trip_through_disk() {
            $crate::contract::a_file_survives_the_round_trip_through_disk($make.await).await;
        }
        #[tokio::test]
        async fn an_empty_file_round_trips_too() {
            $crate::contract::an_empty_file_round_trips_too($make.await).await;
        }
        #[tokio::test]
        async fn a_download_that_finds_nothing_reports_it() {
            $crate::contract::a_download_that_finds_nothing_reports_it($make.await).await;
        }
        #[tokio::test]
        async fn what_a_transfer_reports_adds_up_to_the_file() {
            $crate::contract::what_a_transfer_reports_adds_up_to_the_file($make.await).await;
        }
        #[tokio::test]
        async fn a_stopped_transfer_says_so_and_leaves_nothing_half_written() {
            $crate::contract::a_stopped_transfer_says_so_and_leaves_nothing_half_written(
                $make.await,
            )
            .await;
        }
        #[tokio::test]
        async fn every_backend_answers_the_stale_upload_sweep() {
            $crate::contract::every_backend_answers_the_stale_upload_sweep($make.await).await;
        }
    };
}
