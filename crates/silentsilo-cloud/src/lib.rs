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
mod http;
mod oauth;
pub mod onedrive;
mod pkce;
mod provider;
mod token;

pub use oauth::{AuthRequest, OAuth, Tokens};
pub use provider::Provider;
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
        other => Err(StoreError::Other(format!(
            "{} is not available in this build yet",
            other.name()
        ))),
    }
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
