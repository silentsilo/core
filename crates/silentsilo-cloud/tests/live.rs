//! The contract suite against the real providers, in a fresh folder of a
//! test account each run.
//!
//! Skipped unless the provider's refresh token is set, so `cargo test` stays
//! green without accounts. `scripts/test-local.ps1` loads them from
//! `%USERPROFILE%\.silentsilo-test\cloud.env`, which
//! `cargo run -p silentsilo-cloud --example sign-in -- <onedrive|dropbox|google-drive>`
//! writes. Use accounts of their own: the suite writes and deletes files.

use std::ops::ControlFlow;
use std::sync::Arc;

use silentsilo_cloud::{OAuth, PersistToken, Provider, TokenSource};
use silentsilo_store::{CloudConfig, ObjectStore, contract};

/// A token the provider rotates during the run is not written back: the one
/// in `cloud.env` stays valid for the next run.
struct Discard;

impl PersistToken for Discard {
    fn save(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
}

fn token_var(provider: Provider) -> &'static str {
    match provider {
        Provider::OneDrive => "SILENTSILO_TEST_ONEDRIVE_TOKEN",
        Provider::Dropbox => "SILENTSILO_TEST_DROPBOX_TOKEN",
        Provider::GoogleDrive => "SILENTSILO_TEST_GDRIVE_TOKEN",
    }
}

async fn tokens(provider: Provider) -> Option<Arc<TokenSource>> {
    let var = token_var(provider);
    let Ok(token) = std::env::var(var) else {
        eprintln!("skipped: {var} is not set");
        return None;
    };
    let oauth = OAuth::new(provider).expect("token endpoint");
    Some(Arc::new(TokenSource::new(oauth, token, Arc::new(Discard))))
}

/// A store in a folder no earlier run used.
async fn fresh_store(provider: Provider, tokens: &Arc<TokenSource>) -> Box<dyn ObjectStore> {
    let account = silentsilo_cloud::account(provider, tokens.clone())
        .await
        .expect("the account answers");
    let config = CloudConfig {
        account_id: account.id,
        account_label: account.label,
        folder: format!("silentsilo-tests-{:016x}", rand::random::<u64>()),
    };
    silentsilo_cloud::open(provider, config, tokens.clone()).expect("store")
}

async fn whole_contract(provider: Provider) {
    let Some(tokens) = tokens(provider).await else {
        return;
    };
    macro_rules! run {
        ($($name:ident),* $(,)?) => {
            $(
                eprintln!("{}: {}", provider.name(), stringify!($name));
                contract::$name(fresh_store(provider, &tokens).await).await;
            )*
        };
    }
    run!(
        an_object_survives_the_round_trip_byte_for_byte,
        head_answers_without_moving_the_bytes,
        a_prefix_read_returns_the_first_bytes_only,
        listing_is_ordered_by_key,
        listing_an_empty_prefix_is_not_an_error,
        listing_does_not_leak_a_neighbouring_prefix,
        deleting_something_absent_is_the_desired_end_state,
        a_deleted_object_is_gone_from_both_head_and_list,
        reading_something_absent_reports_not_found,
        rewriting_a_key_replaces_it,
        two_writers_of_one_key_at_once_both_succeed,
        a_copy_is_the_same_bytes_under_the_new_key_and_leaves_the_original,
        the_write_check_round_trips_and_leaves_nothing_behind,
        a_file_survives_the_round_trip_through_disk,
        an_empty_file_round_trips_too,
        a_download_that_finds_nothing_reports_it,
        what_a_transfer_reports_adds_up_to_the_file,
        a_stopped_transfer_says_so_and_leaves_nothing_half_written,
        every_backend_answers_the_stale_upload_sweep,
        a_small_read_says_absent_or_refuses_what_is_too_large,
    );

    // A file large enough for an upload session at every provider, and the
    // silo folders the account now holds.
    let store = fresh_store(provider, &tokens).await;
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("big.sslo");
    let back = dir.path().join("back.sslo");
    let bytes: Vec<u8> = (0..(25 * 1024 * 1024 + 7))
        .map(|i| (i % 251) as u8)
        .collect();
    std::fs::write(&source, &bytes).unwrap();
    let mut reported = 0u64;
    store
        .put_from_file_reporting("blobs/big.sslo", &source, &mut |n| {
            reported += n;
            ControlFlow::Continue(())
        })
        .await
        .expect("a large upload");
    assert_eq!(reported, bytes.len() as u64);
    store.get_to_file("blobs/big.sslo", &back).await.unwrap();
    assert_eq!(std::fs::read(&back).unwrap(), bytes);
    store.delete("blobs/big.sslo").await.unwrap();

    let folders = silentsilo_cloud::silo_folders(provider, tokens.clone())
        .await
        .expect("the silo folders");
    assert!(folders.iter().any(|f| f.starts_with("silentsilo-tests-")));
}

#[tokio::test]
async fn onedrive_keeps_the_contract() {
    whole_contract(Provider::OneDrive).await;
}

#[tokio::test]
async fn dropbox_keeps_the_contract() {
    whole_contract(Provider::Dropbox).await;
}

#[tokio::test]
async fn google_drive_keeps_the_contract() {
    whole_contract(Provider::GoogleDrive).await;
}
