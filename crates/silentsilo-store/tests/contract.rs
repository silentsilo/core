//! One set of assertions, run against every backend: a backend that passes
//! here can host a silo, and one that does not fails in ways the sync
//! layer cannot see. The S3 pass skips without
//! `SILENTSILO_TEST_S3_ENDPOINT`; the folder pass always runs, so the
//! contract is exercised on every `cargo test`.

use silentsilo_core::S3Config;
use silentsilo_store::{
    FolderStore, ObjectStore, SftpAuth, SftpConfig, SftpStore, StoreError, WebDavConfig,
    WebDavStore, contract, probe_host_key,
};
use uuid::Uuid;

fn folder_store() -> (tempfile::TempDir, Box<dyn ObjectStore>) {
    let dir = tempfile::tempdir().unwrap();
    let store = FolderStore::new(dir.path().to_path_buf());
    (dir, Box::new(store))
}

fn s3_store() -> Option<Box<dyn ObjectStore>> {
    let endpoint = std::env::var("SILENTSILO_TEST_S3_ENDPOINT").ok()?;
    let client = silentsilo_s3::S3Client::new(S3Config {
        endpoint,
        region: "us-east-1".into(),
        bucket: std::env::var("SILENTSILO_TEST_S3_BUCKET").unwrap_or_else(|_| "vault-test".into()),
        prefix: format!("contract-{}", Uuid::new_v4()),
        access_key_id: std::env::var("SILENTSILO_TEST_S3_KEY")
            .unwrap_or_else(|_| "silentsilo".into()),
        secret_access_key: std::env::var("SILENTSILO_TEST_S3_SECRET")
            .unwrap_or_else(|_| "silentsilo123".into()),
        path_style: true,
    })
    .ok()?;
    Some(Box::new(client))
}

/// Each run gets its own collection, so a failing test cannot leave state
/// that makes the next one pass or fail for the wrong reason.
fn webdav_store() -> Option<Box<dyn ObjectStore>> {
    let base = std::env::var("SILENTSILO_TEST_WEBDAV_URL").ok()?;
    WebDavStore::new(WebDavConfig {
        url: format!("{}/contract-{}", base.trim_end_matches('/'), Uuid::new_v4()),
        username: std::env::var("SILENTSILO_TEST_WEBDAV_USER")
            .unwrap_or_else(|_| "silentsilo".into()),
        password: std::env::var("SILENTSILO_TEST_WEBDAV_PASSWORD")
            .unwrap_or_else(|_| "silentsilo123".into()),
    })
    .ok()
    .map(|s| Box::new(s) as Box<dyn ObjectStore>)
}

/// The host key is learned first, exactly as the app does it — which also
/// means this test would fail if pinning were broken, since a store with no
/// confirmed fingerprint refuses to be built at all.
async fn sftp_store() -> Option<Box<dyn ObjectStore>> {
    let host = std::env::var("SILENTSILO_TEST_SFTP_HOST").ok()?;
    let port: u16 = std::env::var("SILENTSILO_TEST_SFTP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(2222);
    let fingerprint = probe_host_key(&host, port).await.ok()?;

    SftpStore::new(SftpConfig {
        host,
        port,
        username: std::env::var("SILENTSILO_TEST_SFTP_USER")
            .unwrap_or_else(|_| "silentsilo".into()),
        auth: SftpAuth::Password {
            password: std::env::var("SILENTSILO_TEST_SFTP_PASSWORD")
                .unwrap_or_else(|_| "silentsilo123".into()),
        },
        path: format!("silo/contract-{}", Uuid::new_v4()),
        host_fingerprint: Some(fingerprint),
    })
    .ok()
    .map(|s| Box::new(s) as Box<dyn ObjectStore>)
}

/// Runs `body` against every backend available on this machine.
async fn for_each_store<F, Fut>(body: F)
where
    F: Fn(Box<dyn ObjectStore>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let (_dir, folder) = folder_store();
    body(folder).await;

    match s3_store() {
        Some(s3) => body(s3).await,
        None => silentsilo_testkit::skip_or_fail("S3: SILENTSILO_TEST_S3_ENDPOINT is not set"),
    }

    match webdav_store() {
        Some(dav) => body(dav).await,
        None => silentsilo_testkit::skip_or_fail("WebDAV: SILENTSILO_TEST_WEBDAV_URL is not set"),
    }

    match sftp_store().await {
        Some(sftp) => body(sftp).await,
        None => silentsilo_testkit::skip_or_fail("SFTP: SILENTSILO_TEST_SFTP_HOST is not set"),
    }
}

#[tokio::test]
async fn an_object_survives_the_round_trip_byte_for_byte() {
    for_each_store(contract::an_object_survives_the_round_trip_byte_for_byte).await;
}

#[tokio::test]
async fn head_answers_without_moving_the_bytes() {
    for_each_store(contract::head_answers_without_moving_the_bytes).await;
}

#[tokio::test]
async fn a_prefix_read_returns_the_first_bytes_only() {
    for_each_store(contract::a_prefix_read_returns_the_first_bytes_only).await;
}

#[tokio::test]
async fn listing_is_ordered_by_key() {
    for_each_store(contract::listing_is_ordered_by_key).await;
}

#[tokio::test]
async fn listing_an_empty_prefix_is_not_an_error() {
    for_each_store(contract::listing_an_empty_prefix_is_not_an_error).await;
}

#[tokio::test]
async fn listing_does_not_leak_a_neighbouring_prefix() {
    for_each_store(contract::listing_does_not_leak_a_neighbouring_prefix).await;
}

#[tokio::test]
async fn deleting_something_absent_is_the_desired_end_state() {
    for_each_store(contract::deleting_something_absent_is_the_desired_end_state).await;
}

#[tokio::test]
async fn a_deleted_object_is_gone_from_both_head_and_list() {
    for_each_store(contract::a_deleted_object_is_gone_from_both_head_and_list).await;
}

#[tokio::test]
async fn reading_something_absent_reports_not_found() {
    for_each_store(contract::reading_something_absent_reports_not_found).await;
}

#[tokio::test]
async fn rewriting_a_key_replaces_it() {
    for_each_store(contract::rewriting_a_key_replaces_it).await;
}

#[tokio::test]
async fn two_writers_of_one_key_at_once_both_succeed() {
    for_each_store(contract::two_writers_of_one_key_at_once_both_succeed).await;
}

#[tokio::test]
async fn a_copy_is_the_same_bytes_under_the_new_key_and_leaves_the_original() {
    for_each_store(contract::a_copy_is_the_same_bytes_under_the_new_key_and_leaves_the_original)
        .await;
}

#[tokio::test]
async fn the_write_check_round_trips_and_leaves_nothing_behind() {
    for_each_store(contract::the_write_check_round_trips_and_leaves_nothing_behind).await;
}

#[tokio::test]
async fn sftp_refuses_a_server_whose_key_is_not_the_pinned_one() {
    // The unit tests cover refusing to build a store with no fingerprint.
    // This covers the case that actually protects the user: a real server,
    // reachable and offering a real key, that is not the expected one.
    let Ok(host) = std::env::var("SILENTSILO_TEST_SFTP_HOST") else {
        silentsilo_testkit::skip_or_fail("SFTP pinning: SILENTSILO_TEST_SFTP_HOST is not set");
        return;
    };

    let store = SftpStore::new(SftpConfig {
        host,
        port: 2222,
        username: "silentsilo".into(),
        auth: SftpAuth::Password {
            password: "silentsilo123".into(),
        },
        path: "silo".into(),
        host_fingerprint: Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
    })
    .unwrap();

    let err = store.list("").await.unwrap_err();
    assert!(
        matches!(err, StoreError::Denied(_)),
        "a changed host key must be refused, not retried as a network problem: got {err:?}"
    );
    assert!(
        err.to_string().contains("identity has changed"),
        "the message has to say what happened: got {err}"
    );
}

#[tokio::test]
async fn a_folder_store_whose_root_is_gone_cannot_be_listed() {
    // An unplugged drive. Listed as empty, it would count as a target that
    // was reached and holds nothing.
    let dir = tempfile::tempdir().unwrap();
    let store = FolderStore::new(dir.path().join("unplugged"));
    assert!(matches!(
        store.list("vault/").await,
        Err(StoreError::Unreachable(_))
    ));
}

#[tokio::test]
async fn a_folder_store_whose_root_is_gone_writes_nothing() {
    // A write used to recreate the root, and the pass then filled it as a
    // new, empty copy. Only `check`, run while the user adds the place,
    // creates it.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("unplugged");
    let store = FolderStore::new(root.clone());
    let unreachable = |r: Result<(), StoreError>| matches!(r, Err(StoreError::Unreachable(_)));
    assert!(unreachable(store.put("vault/ops/1", vec![1]).await));
    assert!(unreachable(store.delete("vault/ops/1").await));
    assert!(unreachable(store.head("vault/ops/1").await.map(|_| ())));
    assert!(unreachable(store.get("vault/ops/1").await.map(|_| ())));
    assert!(!root.exists());

    store.check().await.unwrap();
    assert!(root.is_dir());
    store.put("vault/ops/1", vec![1]).await.unwrap();
}

#[tokio::test]
async fn a_folder_store_refuses_a_key_that_climbs_out_of_it() {
    // Only reachable through a bug or a tampered silo, but this is the one
    // backend where a bad key becomes a write anywhere on the user's disk.
    let (dir, store) = folder_store();
    assert!(store.put("../escaped.txt", vec![1]).await.is_err());
    assert!(!dir.path().parent().unwrap().join("escaped.txt").exists());
}

#[tokio::test]
async fn a_folder_store_hides_partial_writes_from_listings() {
    // A sync client watching the folder, or a rename that never finished.
    // Reporting one as an object would hand the caller a truncated file.
    let (dir, store) = folder_store();
    store.put("ops/000001.op", vec![1]).await.unwrap();
    std::fs::create_dir_all(dir.path().join("ops")).unwrap();
    std::fs::write(dir.path().join("ops/000002.op.part"), b"half").unwrap();

    let keys: Vec<String> = store
        .list("ops/")
        .await
        .unwrap()
        .into_iter()
        .map(|o| o.key)
        .collect();
    assert_eq!(keys, vec!["ops/000001.op".to_string()]);
}

#[tokio::test]
#[cfg(unix)]
async fn a_folder_store_survives_a_link_pointing_back_at_itself() {
    // The target is a directory the user chose, so it can hold anything,
    // including a link to an ancestor. `is_dir()` follows those, and the
    // walk went round in a circle until the stack ran out: a sweep against
    // such a folder took the app down rather than reporting anything.
    let (dir, store) = folder_store();
    store.put("ops/000001.op", vec![1]).await.unwrap();
    std::os::unix::fs::symlink(dir.path(), dir.path().join("ops/loop")).unwrap();

    let keys: Vec<String> = store
        .list("ops/")
        .await
        .unwrap()
        .into_iter()
        .map(|o| o.key)
        .collect();
    assert!(
        keys.contains(&"ops/000001.op".to_string()),
        "the real object was lost: {keys:?}"
    );
}

#[tokio::test]
async fn a_folder_store_lists_a_nested_tree_once() {
    // The guard skips a directory it has already walked, so the ordinary
    // case has to keep working: nothing legitimate may be dropped, and
    // nothing may be reported twice.
    let (_dir, store) = folder_store();
    store.put("ops/000001.op", vec![1]).await.unwrap();
    store.put("ops/nested/000002.op", vec![2]).await.unwrap();

    let keys: Vec<String> = store
        .list("ops/")
        .await
        .unwrap()
        .into_iter()
        .map(|o| o.key)
        .collect();
    assert_eq!(
        keys,
        vec![
            "ops/000001.op".to_string(),
            "ops/nested/000002.op".to_string()
        ]
    );
}

#[tokio::test]
async fn a_file_survives_the_round_trip_through_disk() {
    for_each_store(contract::a_file_survives_the_round_trip_through_disk).await;
}

#[tokio::test]
async fn an_empty_file_round_trips_too() {
    for_each_store(contract::an_empty_file_round_trips_too).await;
}

#[tokio::test]
async fn a_download_that_finds_nothing_reports_it() {
    for_each_store(contract::a_download_that_finds_nothing_reports_it).await;
}

#[tokio::test]
async fn what_a_transfer_reports_adds_up_to_the_file() {
    for_each_store(contract::what_a_transfer_reports_adds_up_to_the_file).await;
}

#[tokio::test]
async fn a_stopped_transfer_says_so_and_leaves_nothing_half_written() {
    for_each_store(contract::a_stopped_transfer_says_so_and_leaves_nothing_half_written).await;
}

#[tokio::test]
async fn a_small_read_says_absent_or_refuses_what_is_too_large() {
    for_each_store(contract::a_small_read_says_absent_or_refuses_what_is_too_large).await;
}

#[tokio::test]
async fn every_backend_answers_the_stale_upload_sweep() {
    for_each_store(contract::every_backend_answers_the_stale_upload_sweep).await;
}

/// An unfinished upload younger than the sweep's age is left alone through
/// the trait: it may be another device's, still running.
#[tokio::test]
async fn the_s3_sweep_leaves_a_young_upload_alone() {
    let Some(endpoint) = std::env::var("SILENTSILO_TEST_S3_ENDPOINT").ok() else {
        silentsilo_testkit::skip_or_fail("S3: SILENTSILO_TEST_S3_ENDPOINT is not set");
        return;
    };
    let client = silentsilo_s3::S3Client::new(S3Config {
        endpoint,
        region: "us-east-1".into(),
        bucket: std::env::var("SILENTSILO_TEST_S3_BUCKET").unwrap_or_else(|_| "vault-test".into()),
        prefix: format!("contract-{}", Uuid::new_v4()),
        access_key_id: std::env::var("SILENTSILO_TEST_S3_KEY")
            .unwrap_or_else(|_| "silentsilo".into()),
        secret_access_key: std::env::var("SILENTSILO_TEST_S3_SECRET")
            .unwrap_or_else(|_| "silentsilo123".into()),
        path_style: true,
    })
    .unwrap();
    let key = "blobs/running.sslo";
    client
        .start_abandoned_upload(key, vec![1u8; 1024])
        .await
        .unwrap();

    let store: &dyn ObjectStore = &client;
    let hour = std::time::Duration::from_secs(60 * 60);
    assert_eq!(store.abort_stale_uploads(key, hour).await.unwrap(), 0);
    assert_eq!(client.pending_uploads(key).await.unwrap().len(), 1);

    client
        .abort_uploads_started_before(key, std::time::SystemTime::now() + hour)
        .await
        .unwrap();
}
