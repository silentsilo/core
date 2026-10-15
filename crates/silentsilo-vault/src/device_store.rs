use std::path::PathBuf;

use keyring::Entry;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::dpapi;
use crate::error::VaultError;

const KEYRING_USER: &str = "vault-credentials";

/// Identifies this machine's vault and holds the secret that bootstraps it
/// before a security key is enrolled. `device_secret` is a real
/// cryptographic input, not an auth token, which is why it lives in the OS
/// keyring and is wiped on drop. The id beside it is not a secret and is
/// skipped: `Uuid` has no `Zeroize`.
///
/// Once a key opens the silo the secret is emptied
/// ([`retire_device_secret`]) and the record stays, saying the silo is set
/// up on this machine.
#[derive(Clone, Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
pub struct LocalVaultAuth {
    #[zeroize(skip)]
    pub vault_id: Uuid,
    pub device_secret: String,
}

/// Never prints the secret.
impl std::fmt::Debug for LocalVaultAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalVaultAuth")
            .field("vault_id", &self.vault_id)
            .finish_non_exhaustive()
    }
}

/// Machine-local, never inside the silo folder: the folder is made to be
/// carried around and may sit in OneDrive, and a device secret travelling
/// with it would mean whoever holds a copy of the folder holds the vault.
/// Keyed by silo id, so moving the folder does not lose the secret.
fn credentials_path(silo_id: Uuid) -> PathBuf {
    crate::workdir::secrets_dir_for(silo_id).join("credentials.json")
}

/// Whether this particular silo has credentials on this machine.
pub fn is_provisioned(silo_id: Uuid) -> bool {
    crate::keychain::get_password(&keyring_user(silo_id)).is_ok()
        || read_fallback_file(silo_id).is_some_and(|creds| creds.vault_id == silo_id)
}

/// Reads and unwraps the fallback credentials file, if there is one to read.
/// `None` covers absent, unreadable and unparseable alike: every caller
/// treats all three as "no credentials here".
fn read_fallback_file(silo_id: Uuid) -> Option<LocalVaultAuth> {
    let raw = std::fs::read(credentials_path(silo_id)).ok()?;
    crate::format::decode("credentials", &dpapi::open_sealed(raw)?).ok()
}

/// Write to the OS keyring, then immediately read it back with a fresh
/// handle to confirm the write actually persisted. Some Windows Credential
/// Manager configurations report `set_password` as successful without the
/// entry actually becoming readable afterward, which would otherwise leave
/// `is_provisioned`/`load_credentials` unable to find credentials that were
/// supposedly just saved.
fn keyring_roundtrips(silo_id: Uuid, json: &str) -> bool {
    if crate::keychain::set_password(crate::keychain::service(), &keyring_user(silo_id), json)
        .is_err()
    {
        crate::keychain::note(false);
        return false;
    }
    let kept = matches!(
        crate::keychain::get_password(&keyring_user(silo_id)).map(Zeroizing::new),
        Ok(stored) if *stored == json
    );
    crate::keychain::note(kept);
    kept
}

fn encoded(creds: &LocalVaultAuth) -> Result<Zeroizing<String>, VaultError> {
    String::from_utf8(crate::format::encode(creds)?)
        .map(Zeroizing::new)
        .map_err(|e| VaultError::Crypto(e.to_string()))
}

pub fn save_credentials(creds: &LocalVaultAuth) -> Result<(), VaultError> {
    let json = encoded(creds)?;

    if keyring_roundtrips(creds.vault_id, &json) {
        let stale = credentials_path(creds.vault_id);
        if stale.is_file() {
            let _ = std::fs::remove_file(stale);
        }
        return Ok(());
    }

    // Keyring write didn't verifiably persist on this machine — fall back to
    // a local file so provisioning still succeeds. `load_credentials` already
    // supports this path (and retries the keyring next time it's called).
    //
    // Whatever the entry still holds is then older than the file, and
    // `load_credentials` reads the entry first, so it goes: after the file
    // is written and never before. A device secret does not change once a
    // silo is provisioned, so nothing has come back stale this way yet, but
    // the shape is the one that lost a backup target in `s3_store`.
    write_fallback_file(creds.vault_id, &json)?;
    if let Ok(entry) = keyring_entry(creds.vault_id) {
        let _ = entry.delete_credential();
    }
    Ok(())
}

/// The keyring-unavailable fallback: seals and writes the credentials file.
/// Split out from `save_credentials` so it's directly testable without
/// depending on the real OS keyring's behavior on the test machine.
///
/// Sealed with DPAPI on Windows and the client's protector elsewhere, so the
/// file is useless off this device. Where there is neither, the write is
/// refused until the user agrees to a file only their account can read
/// (`dpapi::allow_unprotected_secrets`). A retired record holds no secret
/// and is written either way.
fn write_fallback_file(silo_id: Uuid, json: &str) -> Result<(), VaultError> {
    let to_write = if holds_a_secret(json) {
        dpapi::seal_secret(json.as_bytes())?
    } else {
        dpapi::seal_if_possible(json.as_bytes())?
    };
    crate::workdir::write_private(&credentials_path(silo_id), &to_write)?;
    Ok(())
}

/// Whether a credentials record still carries a device secret.
fn holds_a_secret(json: &str) -> bool {
    crate::format::decode::<LocalVaultAuth>("credentials", json.as_bytes())
        .map_or(true, |creds| !creds.device_secret.is_empty())
}

pub fn load_credentials(silo_id: Uuid) -> Result<LocalVaultAuth, VaultError> {
    if let Ok(json) = crate::keychain::get_password(&keyring_user(silo_id)) {
        let json = Zeroizing::new(json);
        return crate::format::decode("credentials", json.as_bytes());
    }

    let path = credentials_path(silo_id);
    if !path.is_file() {
        return Err(VaultError::NotProvisioned);
    }

    let raw = std::fs::read(&path)?;
    let json_bytes = dpapi::open_sealed(raw)
        .ok_or_else(|| VaultError::Crypto("failed to unwrap credential file".into()))?;
    let creds: LocalVaultAuth = crate::format::decode("credentials", &json_bytes)?;

    // Both lookups are keyed by silo id now, so a mismatch means the file
    // was tampered with or hand-edited rather than merely misfiled. Still
    // refused here rather than at unlock, which is where it used to surface:
    // after the person had already been asked to touch their key, and phrased
    // as a fact about their credentials rather than about the folder.
    if creds.vault_id != silo_id {
        return Err(VaultError::NotProvisioned);
    }

    // Try to migrate the fallback file into the keyring, but only remove it
    // if the keyring can actually be read back afterward — otherwise these
    // credentials would be silently lost on a machine where the keyring
    // write never verifiably persists (see `keyring_roundtrips`).
    let _ = save_credentials(&creds);
    if crate::keychain::get_password(&keyring_user(silo_id)).is_ok() {
        let _ = std::fs::remove_file(path);
    }
    Ok(creds)
}

/// Forgets this device's secret for a silo a key now opens, keeping the
/// record that the silo is set up here, so [`is_provisioned`] and
/// [`load_credentials`] answer as before with an empty `device_secret`.
///
/// Call it once the first key is enrolled and `master.dek.enc` is wrapped
/// under that key. Until then the secret is the only way in. After it, an
/// envelope under the secret that survives somewhere (a synced folder's
/// version history, a backup) opens nothing, because the secret is gone.
/// Opening a silo with a key ([`crate::VaultSession::open_with_fido_wrapped`])
/// calls it too, which retires the secrets earlier releases kept.
///
/// A silo with no credentials here is nothing to do. An error means the
/// secret may still be stored.
pub fn retire_device_secret(silo_id: Uuid) -> Result<(), VaultError> {
    let creds = match load_credentials(silo_id) {
        Ok(creds) => creds,
        Err(VaultError::NotProvisioned) => return Ok(()),
        Err(e) => return Err(e),
    };
    if creds.device_secret.is_empty() {
        return Ok(());
    }
    let retired = LocalVaultAuth {
        vault_id: silo_id,
        device_secret: String::new(),
    };
    let json = encoded(&retired)?;
    if keyring_roundtrips(silo_id, &json) {
        let _ = std::fs::remove_file(credentials_path(silo_id));
    } else {
        write_fallback_file(silo_id, &json)?;
        crate::s3_store::forget_keyring_entry(|| keyring_entry(silo_id));
    }
    match load_credentials(silo_id) {
        Ok(after) if after.device_secret.is_empty() => Ok(()),
        _ => Err(VaultError::Crypto(
            "this device's secret for the silo could not be removed".into(),
        )),
    }
}

/// Forget this vault's credentials entirely (keyring entry and fallback
/// file) — used when resetting the app back to an unprovisioned state.
/// Best-effort: a missing entry isn't an error.
pub fn clear_credentials(silo_id: Uuid) {
    if let Ok(entry) = keyring_entry(silo_id) {
        let _ = entry.delete_credential();
    }
    let _ = std::fs::remove_file(credentials_path(silo_id));
}

/// Keyed by silo, so several silos on one machine don't overwrite each
/// other's secret in the keyring — which is what a fixed entry name would
/// do, silently, leaving every silo but the last one unopenable.
fn keyring_entry(silo_id: Uuid) -> Result<Entry, keyring::Error> {
    Entry::new(crate::keychain::service(), &keyring_user(silo_id))
}

fn keyring_user(silo_id: Uuid) -> String {
    format!("{KEYRING_USER}:{silo_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fallback file lives under `work_base()`, which is a real directory
    /// on the machine running the tests rather than a temporary one. Each
    /// test therefore takes a fresh random id, so parallel runs cannot
    /// collide, and removes what it wrote even when an assertion fails.
    struct Scratch(Uuid);

    impl Scratch {
        fn new() -> Self {
            crate::dpapi::tests::test_protector();
            Scratch(Uuid::new_v4())
        }
        fn id(&self) -> Uuid {
            self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(crate::workdir::secrets_dir_for(self.0));
        }
    }

    fn encoded(creds: &LocalVaultAuth) -> String {
        String::from_utf8(crate::format::encode(creds).unwrap()).unwrap()
    }

    /// Taken from release 1.10.x and must never change: a change means the
    /// device secret is not found and the silo does not open on this machine.
    #[test]
    fn the_device_secret_is_looked_up_where_1_10_stored_it() {
        let id = Uuid::parse_str("0198b7e2-5a3c-7d10-9c1e-3f2a4b5c6d7e").unwrap();
        assert_eq!(
            keyring_user(id),
            "vault-credentials:0198b7e2-5a3c-7d10-9c1e-3f2a4b5c6d7e"
        );
        assert_eq!(
            credentials_path(id),
            crate::workdir::work_base()
                .join("secrets")
                .join("0198b7e2-5a3c-7d10-9c1e-3f2a4b5c6d7e")
                .join("credentials.json")
        );
    }

    /// The point of the whole file location. A silo folder is meant to be
    /// carried to another disk and may sit in OneDrive, and this secret
    /// unwraps `master.dek.enc` with the salt that lives in that same folder.
    #[test]
    fn the_fallback_file_never_lands_in_the_silo_folder() {
        let scratch = Scratch::new();
        let silo_root = std::path::Path::new(r"C:\Users\alex\OneDrive\Documents\Silo");

        let path = credentials_path(scratch.id());

        assert!(!path.starts_with(silo_root));
        assert!(path.starts_with(crate::workdir::work_base()));
    }

    /// Regression test: on a fresh install the parent directory does not
    /// exist yet, and the write failed with "path not found" even though
    /// nothing was actually wrong.
    #[test]
    fn creates_its_directory_before_writing() {
        let scratch = Scratch::new();
        assert!(!credentials_path(scratch.id()).exists());

        write_fallback_file(scratch.id(), r#"{"fake":"credentials"}"#).unwrap();

        assert!(credentials_path(scratch.id()).is_file());
    }

    #[test]
    fn writing_twice_replaces_rather_than_appends() {
        let scratch = Scratch::new();
        write_fallback_file(scratch.id(), r#"{"first":true}"#).unwrap();
        write_fallback_file(scratch.id(), r#"{"second":true}"#).unwrap();

        let raw = std::fs::read(credentials_path(scratch.id())).unwrap();
        let json = dpapi::open_sealed(raw).unwrap();
        assert_eq!(
            String::from_utf8(json.to_vec()).unwrap(),
            r#"{"second":true}"#
        );
    }

    /// Sealed wherever this device can seal: the file is the secret, and
    /// a copy of it off this device must open nothing.
    #[test]
    fn the_fallback_file_is_sealed() {
        let scratch = Scratch::new();
        write_fallback_file(scratch.id(), r#"{"fake":"credentials"}"#).unwrap();
        let raw = std::fs::read(credentials_path(scratch.id())).unwrap();
        assert!(raw.starts_with(dpapi::SEALED));
        assert!(!String::from_utf8_lossy(&raw).contains("credentials"));
    }

    /// Retiring keeps the record and drops the secret, through the same
    /// file the keyring falls back to.
    #[test]
    fn a_retired_record_keeps_the_silo_and_loses_the_secret() {
        let scratch = Scratch::new();
        let _serial = crate::s3_store::tests::keyring_lock();
        write_fallback_file(
            scratch.id(),
            &encoded(&LocalVaultAuth {
                vault_id: scratch.id(),
                device_secret: "aa".repeat(32),
            }),
        )
        .unwrap();

        retire_device_secret(scratch.id()).unwrap();

        let after = load_credentials(scratch.id()).unwrap();
        assert_eq!(after.vault_id, scratch.id());
        assert!(after.device_secret.is_empty());
        assert!(is_provisioned(scratch.id()));
        // Twice is nothing more.
        retire_device_secret(scratch.id()).unwrap();
        clear_credentials(scratch.id());
    }

    #[test]
    fn retiring_on_a_silo_not_set_up_here_does_nothing() {
        let scratch = Scratch::new();
        retire_device_secret(scratch.id()).unwrap();
        assert!(!is_provisioned(scratch.id()));
    }

    /// A record with no secret holds nothing worth sealing, so it is
    /// written even where secrets wait for the user's consent.
    #[test]
    fn a_retired_record_is_not_a_secret() {
        let id = Uuid::new_v4();
        let retired = encoded(&LocalVaultAuth {
            vault_id: id,
            device_secret: String::new(),
        });
        assert!(!holds_a_secret(&retired));
        assert!(holds_a_secret(&encoded(&LocalVaultAuth {
            vault_id: id,
            device_secret: "aa".into(),
        })));
        assert!(holds_a_secret("not json"));
    }

    #[cfg(unix)]
    #[test]
    fn the_fallback_file_is_readable_only_by_this_user() {
        // On Unix a fresh file under ~/.cache is world-readable by default,
        // and off Windows this file is the device secret in the clear.
        use std::os::unix::fs::PermissionsExt;
        let scratch = Scratch::new();
        write_fallback_file(scratch.id(), r#"{"fake":"credentials"}"#).unwrap();

        let mode = std::fs::metadata(credentials_path(scratch.id()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "got {:o}", mode & 0o777);
    }

    /// A file whose contents name a different vault has been tampered with
    /// and is refused before anyone touches a key. Only the rejecting
    /// direction is asserted: the matching one would write to the real OS
    /// keyring of the test machine.
    #[test]
    fn refuses_a_file_naming_another_silo() {
        let scratch = Scratch::new();
        let owner = Uuid::new_v4();

        write_fallback_file(
            scratch.id(),
            &encoded(&LocalVaultAuth {
                vault_id: owner,
                device_secret: "aa".repeat(32),
            }),
        )
        .unwrap();

        assert!(
            matches!(
                load_credentials(scratch.id()),
                Err(VaultError::NotProvisioned)
            ),
            "another silo's credentials must not be handed over"
        );
        assert_eq!(
            read_fallback_file(scratch.id()).map(|c| c.vault_id),
            Some(owner),
            "and the file itself must be left alone"
        );
    }

    #[test]
    fn a_newer_credentials_file_says_so_instead_of_looking_unprovisioned() {
        // The failure the envelope exists to prevent. Read as "absent", this
        // sends someone to set up a silo they already have, on a machine
        // where the real credentials are sitting in the file being ignored.
        let scratch = Scratch::new();

        write_fallback_file(
            scratch.id(),
            r#"{"version": 99, "data": {"vault_id": "00000000-0000-0000-0000-000000000001",
               "device_secret": "aa"}}"#,
        )
        .unwrap();

        let err = load_credentials(scratch.id()).unwrap_err();
        assert!(
            matches!(&err, VaultError::Corrupted(m) if m.contains("newer version")),
            "expected a version complaint, got {err:?}"
        );
        assert!(
            !matches!(err, VaultError::NotProvisioned),
            "the one answer that must never come back"
        );
    }

    /// Touches the real OS keyring on purpose, which the tests above avoid.
    ///
    /// Without a platform backend, keyring 3 silently substitutes `mock`,
    /// which builds an empty credential on every `Entry::new` and so can
    /// never round-trip. That shipped: every secret took the fallback-file
    /// path instead, in plaintext on Linux and macOS. Nothing but a real
    /// round-trip catches it, because the code compiles and runs either way.
    #[test]
    fn the_platform_keyring_is_real_and_persists_a_write() {
        let id = Uuid::new_v4();
        let json = encoded(&LocalVaultAuth {
            vault_id: id,
            device_secret: "aa".repeat(32),
        });

        assert!(
            keyring_roundtrips(id, &json),
            "the OS keyring did not hand back what was just written to it, \
             which is what the mock backend does"
        );
        // What the app reads to decide whether secrets need a file.
        assert_eq!(crate::keychain::keyring_keeps_secrets(), Some(true));

        if let Ok(entry) = keyring_entry(id) {
            let _ = entry.delete_credential();
        }
    }
}
