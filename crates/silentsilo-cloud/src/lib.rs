//! Signing in to OneDrive, Dropbox and Google Drive, and keeping that
//! sign-in alive: OAuth 2.0 authorization code with PKCE and a loopback
//! redirect, then refresh tokens.
//!
//! The app is a public client at all three: nothing secret ships in it or in
//! this repository. PKCE is what makes an intercepted code worthless, and the
//! providers only ever redirect to this computer. The login itself happens in
//! the user's own browser, so the password and second factor never reach the
//! app.

pub mod dropbox;
#[cfg(test)]
mod fake;
#[cfg(test)]
mod fake_dropbox;
#[cfg(test)]
mod fake_gdrive;
pub mod gdrive;
mod http;
mod oauth;
pub mod onedrive;
mod pkce;
mod provider;
mod signin;
mod token;

pub use oauth::{AuthRequest, OAuth, Tokens};
pub use provider::Provider;
pub use signin::{Loopback, SIGN_IN_TIMEOUT, SignedIn, sign_in};
pub use token::{PersistToken, TokenSource};

use std::sync::Arc;

use silentsilo_store::{CloudConfig, ObjectStore, StoreError};

/// The store for one target, with the token source that signs its requests.
pub fn open(
    provider: Provider,
    config: CloudConfig,
    tokens: Arc<TokenSource>,
) -> Result<Box<dyn ObjectStore>, StoreError> {
    match provider {
        Provider::OneDrive => Ok(Box::new(onedrive::OneDriveStore::new(config, tokens)?)),
        Provider::Dropbox => Ok(Box::new(dropbox::DropboxStore::new(config, tokens)?)),
        Provider::GoogleDrive => Ok(Box::new(gdrive::GoogleDriveStore::new(config, tokens)?)),
    }
}

/// Who a sign-in belongs to, and the room left there.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    /// The same at every sign-in to that account: the drive id, the Dropbox
    /// account id, the Google permission id. A reconnect must match it.
    pub id: String,
    /// What the person recognises, usually the address.
    pub label: String,
    pub free_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
}

/// A store built only to ask about the account: the folder is never used.
fn probe(provider: Provider, tokens: Arc<TokenSource>) -> Result<Box<dyn Probe>, StoreError> {
    let config = CloudConfig {
        account_id: String::new(),
        account_label: String::new(),
        folder: "probe".into(),
    };
    Ok(match provider {
        Provider::OneDrive => Box::new(onedrive::OneDriveStore::new(config, tokens)?),
        Provider::Dropbox => Box::new(dropbox::DropboxStore::new(config, tokens)?),
        Provider::GoogleDrive => Box::new(gdrive::GoogleDriveStore::new(config, tokens)?),
    })
}

/// What every provider answers besides objects.
#[async_trait::async_trait]
pub(crate) trait Probe: Send + Sync {
    async fn account(&self) -> Result<Account, StoreError>;
    /// The silo folders already in the app's folder, sorted: what a second
    /// computer offers to join.
    async fn silo_folders(&self) -> Result<Vec<String>, StoreError>;
}

/// The account a sign-in reached.
pub async fn account(provider: Provider, tokens: Arc<TokenSource>) -> Result<Account, StoreError> {
    probe(provider, tokens)?.account().await
}

/// The silo folders in the app's folder at the provider.
pub async fn silo_folders(
    provider: Provider,
    tokens: Arc<TokenSource>,
) -> Result<Vec<String>, StoreError> {
    probe(provider, tokens)?.silo_folders().await
}

/// What can go wrong talking to a provider's sign-in service. The messages
/// are shown to the user, so they never carry a token or a response body.
#[derive(Debug, thiserror::Error)]
pub enum CloudError {
    /// The provider no longer honours the sign-in: access removed from the
    /// account, password changed, or unused for too long. Only signing in
    /// again fixes it.
    #[error("the sign-in is no longer valid; sign in again")]
    Revoked,
    #[error("could not reach {0}")]
    Unreachable(String),
    /// The provider answered with a refusal other than the above.
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    Other(String),
}
