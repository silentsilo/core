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

use keyring::Entry;
use silentsilo_cloud::{OAuth, PersistToken, Provider, TokenSource};
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

fn load_cloud_token(target_id: Uuid) -> Option<Zeroizing<String>> {
    if let Ok(entry) = keyring_entry(target_id)
        && let Ok(token) = entry.get_password()
    {
        return Some(Zeroizing::new(token));
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
    if let Ok(entry) = keyring_entry(target_id) {
        let _ = entry.delete_credential();
    }
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

/// Writes a refresh token the provider rotated.
struct Keep(Uuid);

impl PersistToken for Keep {
    fn save(&self, refresh_token: &str) -> Result<(), String> {
        write_token(self.0, refresh_token).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
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
        assert!(load_cloud_token(target.0).is_none());
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
