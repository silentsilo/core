//! What differs between the three providers at sign-in.
//!
//! The client ids are public by design: registered as public clients, with
//! redirect addresses on this computer only, so an app that copies an id
//! cannot receive a code. Never register a redirect that is not localhost.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    OneDrive,
    Dropbox,
    GoogleDrive,
}

impl Provider {
    pub fn name(self) -> &'static str {
        match self {
            Provider::OneDrive => "OneDrive",
            Provider::Dropbox => "Dropbox",
            Provider::GoogleDrive => "Google Drive",
        }
    }

    /// Whether this build can sign in there. Google's token endpoint wants
    /// the client secret, so a build made without it leaves Google Drive out.
    pub fn available(self) -> bool {
        match self {
            Provider::GoogleDrive => self.client_secret().is_some(),
            _ => true,
        }
    }

    /// The storage kind this provider's targets carry (`StoreConfig`'s tag).
    pub fn kind(self) -> &'static str {
        match self {
            Provider::OneDrive => "onedrive",
            Provider::Dropbox => "dropbox",
            Provider::GoogleDrive => "google-drive",
        }
    }

    pub fn from_kind(kind: &str) -> Option<Self> {
        [Provider::OneDrive, Provider::Dropbox, Provider::GoogleDrive]
            .into_iter()
            .find(|p| p.kind() == kind)
    }

    pub(crate) fn client_id(self) -> &'static str {
        match self {
            // Microsoft Entra, tenant softwarehive.onmicrosoft.com.
            Provider::OneDrive => "faef1802-1c8f-4e5b-9165-fda99961785c",
            Provider::Dropbox => "w97d588dlssjw0u",
            Provider::GoogleDrive => {
                "312833683472-mpvnhhu9o150iasll012f4fphc90kjr9.apps.googleusercontent.com"
            }
        }
    }

    /// Google's desktop clients come with a secret its own documentation
    /// calls not confidential, and the token endpoint may ask for it. It is
    /// never in this repository: a build gets it from the environment, and a
    /// build without it simply sends none.
    pub(crate) fn client_secret(self) -> Option<&'static str> {
        match self {
            Provider::GoogleDrive => option_env!("SILENTSILO_GOOGLE_CLIENT_SECRET"),
            _ => None,
        }
    }

    pub(crate) fn authorize_url(self) -> &'static str {
        match self {
            // `consumers`: personal Microsoft accounts only. The app folder
            // permission exists for those; a work account would need access
            // to every file it holds.
            Provider::OneDrive => {
                "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
            }
            Provider::Dropbox => "https://www.dropbox.com/oauth2/authorize",
            Provider::GoogleDrive => "https://accounts.google.com/o/oauth2/v2/auth",
        }
    }

    pub(crate) fn token_url(self) -> &'static str {
        match self {
            Provider::OneDrive => "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
            Provider::Dropbox => "https://api.dropboxapi.com/oauth2/token",
            Provider::GoogleDrive => "https://oauth2.googleapis.com/token",
        }
    }

    /// Where a sign-in is ended at the provider. Only Dropbox: Microsoft
    /// has no revocation for a personal account's token, and Google's ends
    /// the whole grant, which would sign out every other computer on the
    /// same account.
    pub(crate) fn revoke_url(self) -> Option<&'static str> {
        match self {
            Provider::Dropbox => Some("https://api.dropboxapi.com/2/auth/token/revoke"),
            _ => None,
        }
    }

    /// Only the app's own folder, at each of them. Dropbox takes the scopes
    /// set on the app itself.
    pub(crate) fn scope(self) -> Option<&'static str> {
        match self {
            // `openid email` only for the address shown as the account:
            // Graph gives a personal drive's owner as a display name.
            Provider::OneDrive => Some("Files.ReadWrite.AppFolder offline_access openid email"),
            Provider::Dropbox => None,
            Provider::GoogleDrive => Some("https://www.googleapis.com/auth/drive.file"),
        }
    }

    /// What each needs to hand back a refresh token, and to let the person
    /// pick an account rather than reuse whichever is signed in.
    pub(crate) fn extra_authorize_params(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Provider::OneDrive => &[("prompt", "select_account")],
            Provider::Dropbox => &[("token_access_type", "offline")],
            Provider::GoogleDrive => &[
                ("access_type", "offline"),
                ("prompt", "consent select_account"),
            ],
        }
    }

    /// The address the browser is sent back to. Microsoft ignores the port
    /// of a localhost redirect and Google accepts any port on 127.0.0.1;
    /// Dropbox matches exactly, so it gets the ports in [`fixed_ports`].
    ///
    /// [`fixed_ports`]: Provider::fixed_ports
    pub fn redirect_uri(self, port: u16) -> String {
        match self {
            Provider::OneDrive => format!("http://localhost:{port}"),
            Provider::Dropbox => format!("http://localhost:{port}/"),
            Provider::GoogleDrive => format!("http://127.0.0.1:{port}"),
        }
    }

    /// Ports registered with the provider, tried in order. Empty means any
    /// free port will do.
    pub fn fixed_ports(self) -> &'static [u16] {
        match self {
            Provider::Dropbox => &[53682, 53683, 53684],
            _ => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kind_names_match_the_storage_config_tags() {
        for provider in [Provider::OneDrive, Provider::Dropbox, Provider::GoogleDrive] {
            assert_eq!(Provider::from_kind(provider.kind()), Some(provider));
        }
        let tag = |config: silentsilo_store::StoreConfig| {
            serde_json::to_value(config).unwrap()["kind"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let cloud = silentsilo_store::CloudConfig {
            account_id: "a".into(),
            account_label: String::new(),
            folder: "f".into(),
        };
        assert_eq!(
            tag(silentsilo_store::StoreConfig::OneDrive(cloud.clone())),
            "onedrive"
        );
        assert_eq!(
            tag(silentsilo_store::StoreConfig::Dropbox(cloud.clone())),
            "dropbox"
        );
        assert_eq!(
            tag(silentsilo_store::StoreConfig::GoogleDrive(cloud)),
            "google-drive"
        );
        assert_eq!(Provider::from_kind("s3"), None);
    }
}
