//! The refresh token of each OneDrive, Dropbox or Google Drive target, and
//! opening those targets with it.
//!
//! Kept like the storage settings: in the keyring where it fits, else in a
//! DPAPI-wrapped file on this machine, never in the silo folder. Keyed by
//! target id, which names the account and the folder, so two silos never
//! share one. The access token lives only in memory, in the one
//! [`TokenSource`] each target gets for the life of the process.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use keyring::Entry;
use silentsilo_cloud::{Account, CloudError, OAuth, PersistToken, Provider, TokenSource};
use silentsilo_store::{ObjectStore, StoreConfig, StoreError};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::dpapi;
use crate::error::VaultError;

const KEYRING_USER: &str = "cloud-token";
const DPAPI_MAGIC: &[u8] = b"SSDPAPI1";

fn keyring_user(target_id: Uuid) -> String {
    format!("{KEYRING_USER}:{target_id}")
}

fn keyring_entry(target_id: Uuid) -> Result<Entry, keyring::Error> {
    Entry::new(crate::keychain::service(), &keyring_user(target_id))
}

fn token_path(target_id: Uuid) -> PathBuf {
    crate::workdir::work_base()
        .join("secrets")
        .join("cloud")
        .join(format!("{target_id}.token"))
}

/// One source per target for the whole process, so a sync pass that opens
/// the store again does not refresh again.
fn sources() -> &'static Mutex<HashMap<Uuid, Arc<TokenSource>>> {
    static SOURCES: OnceLock<Mutex<HashMap<Uuid, Arc<TokenSource>>>> = OnceLock::new();
    SOURCES.get_or_init(Default::default)
}

/// Stores a refresh token, from a sign-in or a rotation. A new sign-in
/// replaces the source held for the target, so the next open uses it.
pub fn save_cloud_token(target_id: Uuid, refresh_token: &str) -> Result<(), VaultError> {
    write_token(target_id, refresh_token)?;
    if let Ok(mut sources) = sources().lock() {
        sources.remove(&target_id);
    }
    Ok(())
}

fn write_token(target_id: Uuid, refresh_token: &str) -> Result<(), VaultError> {
    // Verify after write, as for the storage settings: some Credential
    // Manager setups report success without the entry becoming readable.
    if crate::keychain::set_password(
        crate::keychain::service(),
        &keyring_user(target_id),
        refresh_token,
    )
    .is_ok()
        && let Ok(entry) = keyring_entry(target_id)
        && matches!(entry.get_password(), Ok(held) if held == refresh_token)
    {
        let _ = std::fs::remove_file(token_path(target_id));
        return Ok(());
    }

    // Microsoft's tokens can pass the 1280 characters Credential Manager
    // takes. The file is written first and the stale entry goes after, as
    // for the target list: reads prefer the entry.
    let json = Zeroizing::new(refresh_token.as_bytes().to_vec());
    let to_write = match dpapi::protect(&json) {
        Some(protected) => {
            let mut out = DPAPI_MAGIC.to_vec();
            out.extend_from_slice(&protected);
            out
        }
        None => json.to_vec(),
    };
    crate::workdir::write_private(&token_path(target_id), &to_write)?;
    if let Ok(entry) = keyring_entry(target_id) {
        let _ = entry.delete_credential();
    }
    Ok(())
}

pub(crate) fn load_cloud_token(target_id: Uuid) -> Option<Zeroizing<String>> {
    // Credential Manager now and then fails a read of an entry it holds, or
    // answers "no entry" just after a write it confirmed. A missing token
    // asks the user to sign in again, which a glitch should not, so every
    // answer but the token is asked twice more before the file is tried.
    for attempt in 0..3 {
        if let Ok(Ok(token)) = keyring_entry(target_id).map(|entry| entry.get_password()) {
            return Some(Zeroizing::new(token));
        }
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(30));
        }
    }
    let raw = std::fs::read(token_path(target_id)).ok()?;
    let bytes = match raw.strip_prefix(DPAPI_MAGIC) {
        Some(protected) => dpapi::unprotect(protected)?,
        None => raw,
    };
    String::from_utf8(bytes).ok().map(Zeroizing::new)
}

/// Forgets a target's token, on removing the target or the silo. The
/// provider may still list the app as allowed; the app says where to remove
/// it.
pub fn forget_cloud_token(target_id: Uuid) {
    if let Ok(mut sources) = sources().lock() {
        sources.remove(&target_id);
    }
    crate::s3_store::forget_keyring_entry(|| keyring_entry(target_id));
    let _ = std::fs::remove_file(token_path(target_id));
}

/// Lets `StoreConfig::open` open the cloud kinds. Called once at startup by
/// every app; a build that does not refuses them with a message.
pub fn install_cloud() {
    silentsilo_store::set_cloud_opener(open_cloud);
}

fn provider_of(config: &StoreConfig) -> Option<Provider> {
    match config {
        StoreConfig::OneDrive(_) => Some(Provider::OneDrive),
        StoreConfig::Dropbox(_) => Some(Provider::Dropbox),
        StoreConfig::GoogleDrive(_) => Some(Provider::GoogleDrive),
        _ => None,
    }
}

fn open_cloud(config: &StoreConfig) -> Result<Box<dyn ObjectStore>, StoreError> {
    let (Some(provider), Some(cloud)) = (provider_of(config), config.cloud()) else {
        return Err(StoreError::Other("not a cloud storage".into()));
    };
    let tokens = token_source(provider, config.target_id())?;
    silentsilo_cloud::open(provider, cloud.clone(), tokens)
}

fn token_source(provider: Provider, target_id: Uuid) -> Result<Arc<TokenSource>, StoreError> {
    let mut sources = sources()
        .lock()
        .map_err(|_| StoreError::Other("token cache poisoned".into()))?;
    if let Some(source) = sources.get(&target_id) {
        return Ok(source.clone());
    }
    let refresh = load_cloud_token(target_id)
        .ok_or_else(|| StoreError::Denied(format!("Sign in to {} again", provider.name())))?;
    let oauth = OAuth::new(provider).map_err(|e| StoreError::Other(e.to_string()))?;
    let source = Arc::new(TokenSource::new(
        oauth,
        refresh.to_string(),
        Arc::new(Keep(target_id)),
    ));
    sources.insert(target_id, source.clone());
    Ok(source)
}

/// A sign-in not yet given to a target is dropped after this.
const PENDING_FOR: Duration = Duration::from_secs(30 * 60);

/// A finished sign-in waiting for the target it is for. The frontend holds
/// only its id: the tokens never leave this process.
struct Pending {
    provider: Provider,
    account: Account,
    tokens: Arc<TokenSource>,
    at: Instant,
}

fn pending() -> &'static Mutex<HashMap<Uuid, Pending>> {
    static PENDING: OnceLock<Mutex<HashMap<Uuid, Pending>>> = OnceLock::new();
    PENDING.get_or_init(Default::default)
}

/// What the app shows of a sign-in.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudSignIn {
    pub id: Uuid,
    pub provider: Provider,
    pub account: Account,
}

/// A rotated token of a sign-in with no target yet has nowhere to go: it
/// stays in memory and moves with the rest when the sign-in is adopted.
struct NotYet;

impl PersistToken for NotYet {
    fn save(&self, _: &str) -> Result<(), String> {
        Err("not stored yet".into())
    }
}

fn store_error(error: CloudError) -> StoreError {
    match error {
        CloudError::Revoked => StoreError::Denied("the sign-in is no longer valid".into()),
        CloudError::Unreachable(what) => StoreError::Unreachable(format!("could not reach {what}")),
        CloudError::Refused(message) => StoreError::Denied(message),
        CloudError::Other(message) => StoreError::Other(message),
    }
}

/// Signs in to `provider` in the user's browser (`open` gets the page) and
/// keeps the result until a target adopts it.
pub async fn cloud_sign_in(
    provider: Provider,
    open: impl FnOnce(&str) -> Result<(), String>,
) -> Result<CloudSignIn, StoreError> {
    let signed_in = silentsilo_cloud::sign_in(provider, Arc::new(NotYet), open)
        .await
        .map_err(store_error)?;
    let id = Uuid::new_v4();
    let shown = CloudSignIn {
        id,
        provider,
        account: signed_in.account.clone(),
    };
    let mut pending = pending()
        .lock()
        .map_err(|_| StoreError::Other("sign-in list poisoned".into()))?;
    pending.retain(|_, p| p.at.elapsed() < PENDING_FOR);
    pending.insert(
        id,
        Pending {
            provider,
            account: signed_in.account,
            tokens: signed_in.tokens,
            at: Instant::now(),
        },
    );
    Ok(shown)
}

fn pending_tokens(sign_in: Uuid) -> Result<(Provider, Arc<TokenSource>), StoreError> {
    let pending = pending()
        .lock()
        .map_err(|_| StoreError::Other("sign-in list poisoned".into()))?;
    pending
        .get(&sign_in)
        .filter(|p| p.at.elapsed() < PENDING_FOR)
        .map(|p| (p.provider, p.tokens.clone()))
        .ok_or_else(|| StoreError::Denied("the sign-in expired; sign in again".into()))
}

/// The provider and account of a pending sign-in, to build the target.
pub fn cloud_sign_in_account(sign_in: Uuid) -> Option<(Provider, Account)> {
    let pending = pending().lock().ok()?;
    pending
        .get(&sign_in)
        .filter(|p| p.at.elapsed() < PENDING_FOR)
        .map(|p| (p.provider, p.account.clone()))
}

/// Opens a target not saved yet with a pending sign-in's tokens, to check
/// it before anything is stored.
pub fn open_with_sign_in(
    sign_in: Uuid,
    config: &StoreConfig,
) -> Result<Box<dyn ObjectStore>, StoreError> {
    let (provider, tokens) = pending_tokens(sign_in)?;
    let (Some(cloud), Some(kind)) = (config.cloud(), provider_of(config)) else {
        return Err(StoreError::Other("not a cloud storage".into()));
    };
    let account_id = cloud_sign_in_account(sign_in)
        .map(|(_, account)| account.id)
        .unwrap_or_default();
    if kind != provider || cloud.account_id != account_id {
        return Err(StoreError::Denied(format!(
            "That is a different {} account.",
            provider.name()
        )));
    }
    silentsilo_cloud::open(provider, cloud.clone(), tokens)
}

/// The silo folders a pending sign-in can see: what a second computer
/// offers to join, before any target exists.
pub async fn cloud_silo_folders(sign_in: Uuid) -> Result<Vec<String>, StoreError> {
    let (provider, tokens) = pending_tokens(sign_in)?;
    silentsilo_cloud::silo_folders(provider, tokens).await
}

/// Gives a pending sign-in to the target it was for, new or reconnected.
/// Refused when the target names another account: a reconnect to a
/// different account would point the target at an empty folder.
pub async fn adopt_cloud_sign_in(sign_in: Uuid, config: &StoreConfig) -> Result<(), StoreError> {
    let (provider, tokens) = pending_tokens(sign_in)?;
    let account_id = pending()
        .lock()
        .ok()
        .and_then(|p| p.get(&sign_in).map(|p| p.account.id.clone()))
        .unwrap_or_default();
    let Some(cloud) = config.cloud() else {
        return Err(StoreError::Other("not a cloud storage".into()));
    };
    if provider_of(config) != Some(provider) {
        return Err(StoreError::Other(
            "the sign-in is for another provider".into(),
        ));
    }
    if cloud.account_id != account_id {
        return Err(StoreError::Denied(format!(
            "That is a different {} account. Sign in with the one this storage uses.",
            provider.name()
        )));
    }
    save_cloud_token(config.target_id(), &tokens.refresh_token().await)
        .map_err(|e| StoreError::Other(e.to_string()))?;
    if let Ok(mut pending) = pending().lock() {
        pending.remove(&sign_in);
    }
    Ok(())
}

/// Ends a target's sign-in: at the provider where that touches no other
/// sign-in (Dropbox), then here. Best effort at the provider: the local
/// token goes either way.
pub async fn end_cloud_sign_in(config: &StoreConfig) {
    let target_id = config.target_id();
    if let Some(provider) = provider_of(config)
        && let Ok(tokens) = token_source(provider, target_id)
    {
        let _ = tokens.revoke().await;
    }
    forget_cloud_token(target_id);
}

/// Writes a refresh token the provider rotated.
struct Keep(Uuid);

impl PersistToken for Keep {
    fn save(&self, refresh_token: &str) -> Result<(), String> {
        write_token(self.0, refresh_token).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::s3_store::tests::keyring_lock;

    struct Scratch(Uuid);

    impl Drop for Scratch {
        fn drop(&mut self) {
            forget_cloud_token(self.0);
        }
    }

    #[test]
    fn a_token_round_trips_and_is_forgotten() {
        let _serial = keyring_lock();
        let target = Scratch(Uuid::new_v4());
        save_cloud_token(target.0, "rt-short").unwrap();
        assert_eq!(
            load_cloud_token(target.0).as_deref().map(|t| t.as_str()),
            Some("rt-short")
        );

        forget_cloud_token(target.0);
        assert!(gone(target.0), "a forgotten token must not come back");
    }

    /// Credential Manager can still answer with an entry for a moment after
    /// a delete it confirmed; what matters is that it stops.
    pub(crate) fn gone(target_id: Uuid) -> bool {
        (0..20).any(|_| {
            let none = load_cloud_token(target_id).is_none();
            if !none {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            none
        })
    }

    #[test]
    fn a_token_credential_manager_refuses_is_kept_in_the_file() {
        // Longer than the 1280 characters Credential Manager takes.
        let _serial = keyring_lock();
        let target = Scratch(Uuid::new_v4());
        let long = "M.C5_BAY.".to_string() + &"a".repeat(2000);
        save_cloud_token(target.0, &long).unwrap();
        assert_eq!(
            load_cloud_token(target.0).as_deref().map(|t| t.len()),
            Some(long.len())
        );
    }

    fn onedrive(account: &str, folder: &str) -> StoreConfig {
        StoreConfig::OneDrive(silentsilo_store::CloudConfig {
            account_id: account.into(),
            account_label: "ana@outlook.com".into(),
            folder: folder.into(),
        })
    }

    /// A sign-in as `cloud_sign_in` leaves it, without the browser.
    fn pending_for(account: &str) -> Uuid {
        let oauth = OAuth::new(Provider::OneDrive).unwrap();
        let tokens = Arc::new(TokenSource::new(oauth, "rt-new".into(), Arc::new(NotYet)));
        let id = Uuid::new_v4();
        pending().lock().unwrap().insert(
            id,
            Pending {
                provider: Provider::OneDrive,
                account: Account {
                    id: account.into(),
                    label: "ana@outlook.com".into(),
                    free_bytes: None,
                    total_bytes: None,
                },
                tokens,
                at: Instant::now(),
            },
        );
        id
    }

    #[test]
    fn a_sign_in_is_adopted_only_by_a_target_of_its_account() {
        let _serial = keyring_lock();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(adopt_only_by_its_account());
    }

    async fn adopt_only_by_its_account() {
        let config = onedrive("drive-1", "Silo");
        let target = Scratch(config.target_id());

        let wrong = pending_for("drive-2");
        match adopt_cloud_sign_in(wrong, &config).await {
            Err(StoreError::Denied(message)) => assert!(message.contains("different")),
            other => panic!("another account must be refused, got {other:?}"),
        }
        assert!(load_cloud_token(target.0).is_none());

        let right = pending_for("drive-1");
        adopt_cloud_sign_in(right, &config).await.unwrap();
        assert_eq!(
            load_cloud_token(target.0).as_deref().map(|t| t.as_str()),
            Some("rt-new")
        );
        // Used up: the frontend cannot replay the id.
        assert!(adopt_cloud_sign_in(right, &config).await.is_err());
    }

    #[tokio::test]
    async fn an_old_sign_in_is_not_handed_out() {
        let id = pending_for("drive-1");
        let Some(long_ago) = Instant::now().checked_sub(PENDING_FOR + Duration::from_secs(1))
        else {
            return;
        };
        pending().lock().unwrap().get_mut(&id).unwrap().at = long_ago;
        assert!(matches!(
            cloud_silo_folders(id).await,
            Err(StoreError::Denied(_))
        ));
    }

    #[test]
    fn the_token_file_never_lands_in_a_silo_folder() {
        let path = token_path(Uuid::new_v4());
        assert!(path.starts_with(crate::workdir::work_base()));
    }

    #[test]
    fn a_target_without_a_token_asks_to_sign_in_again() {
        let target = Uuid::new_v4();
        match token_source(Provider::Dropbox, target) {
            Err(StoreError::Denied(message)) => assert!(message.contains("Dropbox")),
            other => panic!("expected a sign-in request, got {other:?}"),
        }
    }
}
