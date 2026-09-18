//! End-to-end checks against a real S3-compatible server.
//!
//! Skipped unless `SILENTSILO_TEST_S3_ENDPOINT` is set, so `cargo test` stays
//! green on a machine with no server running. To run them:
//!
//! ```text
//! docker run -d --name silentsilo-minio -p 9100:9000 \
//!   -e MINIO_ROOT_USER=silentsilo -e MINIO_ROOT_PASSWORD=silentsilo123 \
//!   quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z server /data
//! # create a bucket named `vault-test`, then:
//! SILENTSILO_TEST_S3_ENDPOINT=http://localhost:9100 \
//! SILENTSILO_TEST_S3_KEY=silentsilo \
//! SILENTSILO_TEST_S3_SECRET=silentsilo123 \
//! SILENTSILO_TEST_S3_BUCKET=vault-test \
//!   cargo test -p silentsilo-s3 --test live_roundtrip
//! ```
//!
//! These exist because the unit tests only cover construction. Signing,
//! header compatibility and response parsing need a real server, and they
//! are exactly where an S3 client breaks against non-AWS providers.

use silentsilo_core::S3Config;
use silentsilo_s3::S3Client;
use uuid::Uuid;

fn config() -> Option<S3Config> {
    let endpoint = std::env::var("SILENTSILO_TEST_S3_ENDPOINT").ok()?;
    Some(S3Config {
        endpoint,
        region: std::env::var("SILENTSILO_TEST_S3_REGION").unwrap_or_else(|_| "us-east-1".into()),
        bucket: std::env::var("SILENTSILO_TEST_S3_BUCKET").unwrap_or_else(|_| "vault-test".into()),
        // A unique prefix per run, so repeated runs and parallel tests never
        // see each other's objects.
        prefix: format!("test-{}", Uuid::new_v4()),
        access_key_id: std::env::var("SILENTSILO_TEST_S3_KEY")
            .unwrap_or_else(|_| "silentsilo".into()),
        secret_access_key: std::env::var("SILENTSILO_TEST_S3_SECRET")
            .unwrap_or_else(|_| "silentsilo123".into()),
        path_style: true,
    })
}

macro_rules! client_or_skip {
    () => {
        match config() {
            Some(c) => S3Client::new(c).expect("client should build"),
            None => {
                silentsilo_testkit::skip_or_fail("SILENTSILO_TEST_S3_ENDPOINT is not set");
                return;
            }
        }
    };
}

#[tokio::test]
async fn test_connection_round_trips_a_probe_object() {
    let client = client_or_skip!();
    client
        .test_connection()
        .await
        .expect("probe write/read/delete should succeed");
}

#[tokio::test]
async fn an_object_survives_a_put_and_get_unchanged() {
    let client = client_or_skip!();
    // Deliberately binary, including a NUL and high bytes: blobs are
    // ciphertext, not text, and a client that mangles either would corrupt
    // every file in the vault.
    let payload: Vec<u8> = (0u8..=255).cycle().take(5000).collect();

    client
        .put("blobs/binary.sslo", payload.clone())
        .await
        .unwrap();
    let fetched = client.get("blobs/binary.sslo").await.unwrap();

    assert_eq!(fetched, payload);
}

#[tokio::test]
async fn head_distinguishes_missing_from_present() {
    let client = client_or_skip!();
    assert_eq!(client.head("ops/never-written").await.unwrap(), None);

    client
        .put("ops/written", b"1234567890".to_vec())
        .await
        .unwrap();
    assert_eq!(client.head("ops/written").await.unwrap(), Some(10));
}

#[tokio::test]
async fn listing_returns_keys_relative_to_the_prefix() {
    let client = client_or_skip!();
    client.put("ops/a", b"x".to_vec()).await.unwrap();
    client.put("ops/b", b"y".to_vec()).await.unwrap();
    client.put("blobs/c", b"z".to_vec()).await.unwrap();

    let mut ops: Vec<String> = client
        .list("ops/")
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.key)
        .collect();
    ops.sort();

    // The configured prefix is stripped: callers work in vault-relative
    // keys and never have to know where in the bucket they live.
    assert_eq!(ops, vec!["ops/a".to_string(), "ops/b".to_string()]);
}

#[tokio::test]
async fn listing_pages_past_the_thousand_key_limit() {
    let client = client_or_skip!();
    // One page is 1000 keys. A truncated listing would read as "these
    // operations don't exist", which is the worst possible way to be wrong.
    for i in 0..1050 {
        client
            .put(&format!("many/{i:05}"), b"x".to_vec())
            .await
            .unwrap();
    }
    assert_eq!(client.list("many/").await.unwrap().len(), 1050);
}

#[tokio::test]
async fn delete_removes_the_object() {
    let client = client_or_skip!();
    client.put("tmp/gone", b"x".to_vec()).await.unwrap();
    client.delete("tmp/gone").await.unwrap();
    assert_eq!(client.head("tmp/gone").await.unwrap(), None);
}

#[tokio::test]
async fn wrong_credentials_report_something_actionable() {
    let Some(mut cfg) = config() else {
        silentsilo_testkit::skip_or_fail("SILENTSILO_TEST_S3_ENDPOINT is not set");
        return;
    };
    cfg.secret_access_key = "definitely-not-the-secret".into();
    let client = S3Client::new(cfg).unwrap();

    let err = client
        .put("x", b"y".to_vec())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("403") || err.to_lowercase().contains("signature"),
        "a rejected signature should say so, got: {err}"
    );
}

/// The HTTP client Android uses, over plain HTTP here: signing, streamed
/// bodies, listings and a 404 all go through it the way they do on a phone.
#[tokio::test]
async fn the_platform_verifier_client_does_everything_the_default_one_does() {
    let Some(cfg) = config() else {
        silentsilo_testkit::skip_or_fail("SILENTSILO_TEST_S3_ENDPOINT is not set");
        return;
    };
    let client = S3Client::with_platform_verifier(cfg).unwrap();
    client.test_connection().await.unwrap();

    let payload: Vec<u8> = (0u8..=255).cycle().take(300_000).collect();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("up");
    std::fs::write(&source, &payload).unwrap();
    client.put_file("blobs/big.sslo", &source).await.unwrap();
    let back = dir.path().join("down");
    client.get_file("blobs/big.sslo", &back).await.unwrap();
    assert_eq!(std::fs::read(&back).unwrap(), payload);

    assert_eq!(client.head("blobs/big.sslo").await.unwrap(), Some(300_000));
    assert_eq!(client.head("blobs/absent.sslo").await.unwrap(), None);
    let listed = client.list("blobs/").await.unwrap();
    assert_eq!(listed.len(), 1);
    client.delete("blobs/big.sslo").await.unwrap();
}

/// An HTTPS address on a server that speaks plain HTTP: the handshake fails
/// as an error, never a panic or a hang.
#[tokio::test]
async fn a_failed_handshake_is_an_error() {
    let Some(mut cfg) = config() else {
        silentsilo_testkit::skip_or_fail("SILENTSILO_TEST_S3_ENDPOINT is not set");
        return;
    };
    cfg.endpoint = cfg.endpoint.replacen("http://", "https://", 1);
    let client = S3Client::with_platform_verifier(cfg).unwrap();
    assert!(client.put("x", b"y".to_vec()).await.is_err());
}

/// A file past the multipart threshold goes up in parts, which is what puts
/// a number on a large blob while it is moving and what lifts the 5 GiB
/// ceiling a single PUT has. The parts have to come back as one object.
#[tokio::test]
async fn a_large_file_goes_up_in_parts_and_says_so_as_it_goes() {
    let client = client_or_skip!();
    let len = (S3Client::MULTIPART_ABOVE + 3 * 1024 * 1024) as usize;
    let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("big.sslo");
    let back = dir.path().join("back.sslo");
    std::fs::write(&source, &payload).unwrap();

    let mut reports: Vec<u64> = Vec::new();
    client
        .put_file_reporting("blobs/parts.sslo", &source, &mut |bytes| {
            reports.push(bytes);
            std::ops::ControlFlow::Continue(())
        })
        .await
        .unwrap();

    assert!(
        reports.len() > 1,
        "one report for a file this size is the counter that sits still: {reports:?}"
    );
    assert_eq!(reports.iter().sum::<u64>(), len as u64);
    assert_eq!(
        client.head("blobs/parts.sslo").await.unwrap(),
        Some(len as i64)
    );

    let mut down: Vec<u64> = Vec::new();
    client
        .get_file_reporting("blobs/parts.sslo", &back, &mut |bytes| {
            down.push(bytes);
            std::ops::ControlFlow::Continue(())
        })
        .await
        .unwrap();
    assert_eq!(down.iter().sum::<u64>(), len as u64);
    assert_eq!(std::fs::read(&back).unwrap(), payload, "the parts rejoined");
}

/// A stop during a multipart upload aborts it. Parts left behind are billed
/// and invisible: they are not the object and no listing shows them.
#[tokio::test]
async fn a_stopped_multipart_upload_leaves_no_object() {
    let client = client_or_skip!();
    let len = (S3Client::MULTIPART_ABOVE + 3 * 1024 * 1024) as usize;
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("big.sslo");
    std::fs::write(&source, vec![9u8; len]).unwrap();

    let stopped = client
        .put_file_reporting("blobs/stopped.sslo", &source, &mut |_| {
            std::ops::ControlFlow::Break(())
        })
        .await;

    assert!(
        matches!(stopped, Err(silentsilo_s3::S3Error::Cancelled)),
        "got {stopped:?}"
    );
    assert_eq!(client.head("blobs/stopped.sslo").await.unwrap(), None);
}

/// Unfinished uploads are listed by prefix, and MinIO answers only for a
/// prefix that is a whole key, with an empty list otherwise. AWS lists by
/// any prefix. So these tests ask per key, which both answer; the prefix
/// sweep is the same code with a shorter prefix.
async fn pending(client: &S3Client, key: &str) -> Vec<silentsilo_s3::PendingUpload> {
    client
        .pending_uploads(key)
        .await
        .unwrap()
        .into_iter()
        .filter(|u| u.key == key)
        .collect()
}

const DAY: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// A process killed mid-upload aborts nothing. The retry that follows
/// uploads the same key again, and has to take the dead upload's parts with
/// it, or they stay billed and invisible for good.
#[tokio::test]
async fn a_retried_upload_clears_what_a_killed_one_left() {
    let client = client_or_skip!();
    client
        .start_abandoned_upload("blobs/killed.sslo", vec![1u8; 1024])
        .await
        .unwrap();
    // Shares the prefix, not the key: not this upload's to abort.
    client
        .start_abandoned_upload("blobs/killed.sslo.other", vec![2u8; 1024])
        .await
        .unwrap();
    assert_eq!(pending(&client, "blobs/killed.sslo").await.len(), 1);

    let len = (S3Client::MULTIPART_ABOVE + 1024 * 1024) as usize;
    let payload: Vec<u8> = (0..len).map(|i| (i % 253) as u8).collect();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("up");
    let back = dir.path().join("down");
    std::fs::write(&source, &payload).unwrap();
    client.put_file("blobs/killed.sslo", &source).await.unwrap();

    assert!(pending(&client, "blobs/killed.sslo").await.is_empty());
    assert_eq!(pending(&client, "blobs/killed.sslo.other").await.len(), 1);
    client.get_file("blobs/killed.sslo", &back).await.unwrap();
    assert_eq!(
        std::fs::read(&back).unwrap(),
        payload,
        "the object is whole"
    );

    client
        .abort_uploads_started_before(
            "blobs/killed.sslo.other",
            std::time::SystemTime::now() + DAY,
        )
        .await
        .unwrap();
}

/// The sweep aborts an upload older than its threshold and leaves a younger
/// one, which may be another device's still running. The threshold is set
/// between the two uploads' start times as the server reports them, so the
/// test does not depend on this machine's clock agreeing with the server's.
#[tokio::test]
async fn only_uploads_older_than_the_cutoff_are_aborted() {
    let client = client_or_skip!();
    let key = "blobs/aged.sslo";
    client
        .start_abandoned_upload(key, vec![1u8; 1024])
        .await
        .unwrap();
    // Start times may be kept to the second.
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    client
        .start_abandoned_upload(key, vec![2u8; 1024])
        .await
        .unwrap();

    let mut times: Vec<std::time::SystemTime> = pending(&client, key)
        .await
        .iter()
        .map(|u| u.initiated.expect("the server gives a start time"))
        .collect();
    times.sort();
    assert_eq!(times.len(), 2);
    let (old, fresh) = (times[0], times[1]);
    assert!(old < fresh, "{times:?}");
    let cutoff = old + fresh.duration_since(old).unwrap() / 2;

    assert_eq!(
        client
            .abort_uploads_started_before(key, cutoff)
            .await
            .unwrap(),
        1
    );
    let left = pending(&client, key).await;
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].initiated, Some(fresh), "the younger one stays");

    client
        .abort_uploads_started_before(key, fresh + DAY)
        .await
        .unwrap();
    assert!(pending(&client, key).await.is_empty());
}

/// More unfinished uploads than one listing page holds (1000): the ones past
/// the first page are found too.
#[tokio::test]
async fn unfinished_uploads_are_listed_past_one_page() {
    let client = client_or_skip!();
    let key = "blobs/many.sslo";
    for _ in 0..1010 {
        client.start_abandoned_upload(key, vec![0u8]).await.unwrap();
    }
    assert_eq!(pending(&client, key).await.len(), 1010);
    let aborted = client
        .abort_uploads_started_before(key, std::time::SystemTime::now() + DAY)
        .await
        .unwrap();
    assert_eq!(aborted, 1010);
    assert!(pending(&client, key).await.is_empty());
}
