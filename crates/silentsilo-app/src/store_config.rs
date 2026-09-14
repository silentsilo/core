//! How a client's settings screen describes a storage target, and how that
//! becomes a [`StoreConfig`]. Moved from the desktop's `commands/storage.rs`.

use std::path::PathBuf;

use silentsilo_store::{SftpAuth, StoreConfig};

/// What the UI sends when saving. A tagged union rather than one struct
/// with optional fields, because a shape that could express "a folder with
/// a secret access key" would invite exactly that mistake. Field names are
/// the UI's: Tauri converts a command's own parameter names between
/// conventions but not the fields inside them.
#[derive(serde::Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum StoreConfigInput {
    S3 {
        endpoint: String,
        region: String,
        bucket: String,
        prefix: String,
        access_key_id: String,
        /// Optional so an edit that only changes the prefix doesn't require
        /// retyping it; empty means "keep the stored one".
        secret_access_key: Option<String>,
        path_style: bool,
    },
    Folder {
        path: String,
    },
    WebDav {
        url: String,
        username: String,
        /// Same "empty means keep the stored one" rule as the S3 secret.
        password: Option<String>,
    },
    Sftp {
        host: String,
        port: u16,
        username: String,
        path: String,
        auth: SftpAuthInput,
        /// The fingerprint the user was shown and accepted. Empty keeps the
        /// one already confirmed, so editing the path doesn't ask again.
        host_fingerprint: Option<String>,
    },
}

/// How to prove who we are to an SSH server.
///
/// Both secrets are optional for the same reason the S3 key is: an edit that
/// only changes the directory should not require pasting a private key back
/// in.
#[derive(serde::Deserialize)]
#[serde(
    tag = "method",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum SftpAuthInput {
    Password {
        password: Option<String>,
    },
    Key {
        private_key: Option<String>,
        passphrase: Option<String>,
    },
}

/// The stored value if the field was left blank, trimmed to nothing if not.
fn or_stored(given: Option<String>, stored: Option<String>) -> Option<String> {
    given
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or(stored)
}

impl StoreConfigInput {
    pub fn into_config(self, existing: Option<StoreConfig>) -> Result<StoreConfig, String> {
        match self {
            Self::S3 {
                endpoint,
                region,
                bucket,
                prefix,
                access_key_id,
                secret_access_key,
                path_style,
            } => {
                // Only an S3 config can supply a remembered secret. Switching
                // from a folder must not silently inherit one.
                let stored = match existing {
                    Some(StoreConfig::S3(c)) => Some(c.secret_access_key),
                    _ => None,
                };
                let secret = secret_access_key
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .or(stored)
                    .ok_or_else(|| "Secret access key is required".to_string())?;

                Ok(StoreConfig::S3(silentsilo_core::S3Config {
                    endpoint: endpoint.trim().trim_end_matches('/').to_string(),
                    region: region.trim().to_string(),
                    bucket: bucket.trim().to_string(),
                    prefix: prefix.trim().trim_matches('/').to_string(),
                    access_key_id: access_key_id.trim().to_string(),
                    secret_access_key: secret,
                    path_style,
                }))
            }
            Self::Folder { path } => {
                let path = path.trim();
                if path.is_empty() {
                    return Err("Choose a folder to back up to.".into());
                }
                Ok(StoreConfig::Folder {
                    path: PathBuf::from(path),
                })
            }
            Self::WebDav {
                url,
                username,
                password,
            } => {
                let stored = match existing {
                    Some(StoreConfig::WebDav(c)) => Some(c.password),
                    _ => None,
                };
                let password = password
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .or(stored)
                    .ok_or_else(|| "A password or app password is required".to_string())?;

                Ok(StoreConfig::WebDav(silentsilo_store::WebDavConfig {
                    url: url.trim().trim_end_matches('/').to_string(),
                    username: username.trim().to_string(),
                    password,
                }))
            }
            Self::Sftp {
                host,
                port,
                username,
                path,
                auth,
                host_fingerprint,
            } => {
                let stored = match existing {
                    Some(StoreConfig::Sftp(c)) => Some(c),
                    _ => None,
                };

                let auth = match auth {
                    SftpAuthInput::Password { password } => {
                        let stored = match stored.as_ref().map(|c| &c.auth) {
                            Some(SftpAuth::Password { password }) => Some(password.clone()),
                            _ => None,
                        };
                        SftpAuth::Password {
                            password: or_stored(password, stored)
                                .ok_or_else(|| "A password is required".to_string())?,
                        }
                    }
                    SftpAuthInput::Key {
                        private_key,
                        passphrase,
                    } => {
                        let stored = match stored.as_ref().map(|c| &c.auth) {
                            Some(SftpAuth::Key {
                                private_key,
                                passphrase,
                            }) => (Some(private_key.clone()), passphrase.clone()),
                            _ => (None, None),
                        };
                        SftpAuth::Key {
                            private_key: or_stored(private_key, stored.0)
                                .ok_or_else(|| "A private key is required".to_string())?,
                            passphrase: or_stored(passphrase, stored.1),
                        }
                    }
                };

                // Refusing here rather than at connection time, so the
                // message names the missing step instead of describing a
                // failed handshake.
                let host_fingerprint =
                    or_stored(host_fingerprint, stored.and_then(|c| c.host_fingerprint))
                        .ok_or_else(|| {
                            "Check the server's fingerprint before connecting to it.".to_string()
                        })?;

                Ok(StoreConfig::Sftp(silentsilo_store::SftpConfig {
                    host: host.trim().to_string(),
                    port,
                    username: username.trim().to_string(),
                    auth,
                    path: path.trim().trim_end_matches('/').to_string(),
                    host_fingerprint: Some(host_fingerprint),
                }))
            }
        }
    }
}

/// The stored settings as the UI may see them, never the secret key.
#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StoreConfigView {
    S3 {
        endpoint: String,
        region: String,
        bucket: String,
        prefix: String,
        access_key_id: String,
        path_style: bool,
    },
    Folder {
        path: String,
    },
    WebDav {
        url: String,
        username: String,
    },
    Sftp {
        host: String,
        port: u16,
        username: String,
        path: String,
        /// `password` or `key`, so the form comes back on the right tab.
        auth_method: String,
        /// Not a secret, the point of a fingerprint is to be shown, so the
        /// user can compare it against what their server reports.
        host_fingerprint: Option<String>,
    },
}

impl From<&StoreConfig> for StoreConfigView {
    fn from(config: &StoreConfig) -> Self {
        match config {
            StoreConfig::S3(c) => Self::S3 {
                endpoint: c.endpoint.clone(),
                region: c.region.clone(),
                bucket: c.bucket.clone(),
                prefix: c.prefix.clone(),
                access_key_id: c.access_key_id.clone(),
                path_style: c.path_style,
            },
            StoreConfig::Folder { path } => Self::Folder {
                path: path.to_string_lossy().to_string(),
            },
            StoreConfig::WebDav(c) => Self::WebDav {
                url: c.url.clone(),
                username: c.username.clone(),
            },
            StoreConfig::Sftp(c) => Self::Sftp {
                host: c.host.clone(),
                port: c.port,
                username: c.username.clone(),
                path: c.path.clone(),
                auth_method: match c.auth {
                    SftpAuth::Password { .. } => "password".into(),
                    SftpAuth::Key { .. } => "key".into(),
                },
                host_fingerprint: c.host_fingerprint.clone(),
            },
        }
    }
}

#[cfg(test)]
mod deserialisation_tests {
    use super::*;

    /// The exact JSON `storeDraftPayload` produces, for every kind.
    ///
    /// This is the seam where a rename on either side goes unnoticed until a
    /// user tries to save: the command still compiles, the form still
    /// submits, and the only symptom is an error naming a field the UI has
    /// never heard of.
    #[test]
    fn every_shape_the_ui_sends_is_a_shape_this_reads() {
        let payloads = [
            serde_json::json!({
                "kind": "s3",
                "endpoint": "http://127.0.0.1:9000",
                "region": "us-east-1",
                "bucket": "vault",
                "prefix": "",
                "accessKeyId": "silentsilo",
                "secretAccessKey": "silentsilo123",
                "pathStyle": true
            }),
            serde_json::json!({ "kind": "folder", "path": "/srv/backups/silo" }),
            serde_json::json!({
                "kind": "web-dav",
                "url": "https://cloud.example.com/remote.php/dav/files/me/silo",
                "username": "me",
                "password": "app-password"
            }),
            serde_json::json!({
                "kind": "sftp",
                "host": "nas.example.com",
                "port": 22,
                "username": "alex",
                "path": "backups/silo",
                "auth": { "method": "password", "password": "hunter2" },
                "hostFingerprint": "SHA256:abc"
            }),
            serde_json::json!({
                "kind": "sftp",
                "host": "nas.example.com",
                "port": 22,
                "username": "alex",
                "path": "backups/silo",
                "auth": {
                    "method": "key",
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----",
                    "passphrase": null
                },
                "hostFingerprint": "SHA256:abc"
            }),
        ];

        for payload in payloads {
            let kind = payload["kind"].clone();
            serde_json::from_value::<StoreConfigInput>(payload)
                .unwrap_or_else(|e| panic!("the UI payload for {kind} must deserialise: {e}"));
        }
    }

    #[test]
    fn an_sftp_server_whose_fingerprint_was_never_confirmed_is_refused() {
        let json = serde_json::json!({
            "kind": "sftp",
            "host": "nas.example.com",
            "port": 22,
            "username": "alex",
            "path": "backups/silo",
            "auth": { "method": "password", "password": "hunter2" },
            "hostFingerprint": null
        });
        let input: StoreConfigInput = serde_json::from_value(json).unwrap();

        let Err(err) = input.into_config(None) else {
            panic!("a server nobody has vouched for must not be saved");
        };
        assert!(err.contains("fingerprint"), "got: {err}");
    }

    #[test]
    fn editing_an_sftp_connection_keeps_the_password_and_the_fingerprint() {
        // Blank secrets mean "unchanged", the same rule the other backends
        // follow; otherwise changing the directory would mean pasting a
        // private key back in.
        let stored = StoreConfig::Sftp(silentsilo_store::SftpConfig {
            host: "nas.example.com".into(),
            port: 22,
            username: "alex".into(),
            auth: SftpAuth::Password {
                password: "hunter2".into(),
            },
            path: "backups/silo".into(),
            host_fingerprint: Some("SHA256:abc".into()),
        });
        let json = serde_json::json!({
            "kind": "sftp",
            "host": "nas.example.com",
            "port": 22,
            "username": "alex",
            "path": "backups/silo-2",
            "auth": { "method": "password", "password": null },
            "hostFingerprint": null
        });
        let input: StoreConfigInput = serde_json::from_value(json).unwrap();

        let StoreConfig::Sftp(config) = input.into_config(Some(stored)).unwrap() else {
            panic!("kind changed");
        };
        assert_eq!(config.path, "backups/silo-2");
        assert_eq!(config.host_fingerprint.as_deref(), Some("SHA256:abc"));
        assert!(matches!(
            config.auth,
            SftpAuth::Password { password } if password == "hunter2"
        ));
    }

    #[test]
    fn switching_backends_does_not_inherit_the_other_ones_secret() {
        // A stored bucket secret must not stand in for a missing SFTP
        // password: the two are unrelated credentials that happen to sit in
        // the same slot.
        let stored = StoreConfig::S3(silentsilo_core::S3Config {
            endpoint: "http://127.0.0.1:9000".into(),
            region: "us-east-1".into(),
            bucket: "vault".into(),
            prefix: String::new(),
            access_key_id: "silentsilo".into(),
            secret_access_key: "silentsilo123".into(),
            path_style: true,
        });
        let json = serde_json::json!({
            "kind": "sftp",
            "host": "nas.example.com",
            "port": 22,
            "username": "alex",
            "path": "backups/silo",
            "auth": { "method": "password", "password": null },
            "hostFingerprint": "SHA256:abc"
        });
        let input: StoreConfigInput = serde_json::from_value(json).unwrap();

        assert!(input.into_config(Some(stored)).is_err());
    }
}
