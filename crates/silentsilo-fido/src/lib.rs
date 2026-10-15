//! FIDO2 security-key integration.
//!
//! - **Windows**: OS WebAuthn API (`webauthn.dll`) — no administrator rights.
//! - **Linux / macOS**: CTAP2 over USB HID.

// A constant in place of a security key, for end-to-end tests. Never in a
// release build.
#[cfg(all(feature = "test-authenticator", not(debug_assertions)))]
compile_error!("the test authenticator is for debug builds only");

/// A message a client translates: see `silentsilo_core::coded`. Local,
/// since this crate does not depend on that one.
macro_rules! coded {
    ($code:literal, $english:literal) => {
        concat!($english, "\u{1f}", $code)
    };
}
pub(crate) use coded;

mod backend;
#[cfg(feature = "ctap2")]
pub mod ctap2;
#[cfg(feature = "enclave")]
pub mod enclave;

/// The Secure Enclave of an iPhone or iPad, for the mobile client's device
/// key: the same `secure-enclave` kind and derivation a Mac uses, behind
/// Face ID or Touch ID.
#[cfg(all(feature = "enclave", target_os = "ios"))]
pub mod device_enclave {
    pub use crate::backend::enclave_mac::{
        available, derive_unlock_material, enrol, holds_any, remove, status,
    };
}
#[cfg(feature = "passkey")]
pub mod passkey;
// Only the Windows backend builds client data: WebAuthn takes it whole. The
// CTAP2 path sends its hash and makes it in `ctap2`.
#[cfg(all(feature = "hardware", not(feature = "test-authenticator"), windows))]
mod client_data;
mod error;
// The salt and wrap key every hmac-secret backend shares.
#[cfg(feature = "ctap2")]
mod hmac_secret;
mod types;

pub use error::FidoError;

/// What a security key asks for before it answers: its PIN, the first time
/// or again after a wrong one, with the tries the key says are left. Only
/// keys reached over USB or NFC ask through this; Windows asks in its own
/// dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PinAsk {
    Enter { retries: Option<u8> },
    Wrong { retries: Option<u8> },
}

/// How the client asks for a PIN. Called on the ceremony's own thread, it
/// waits for the person; `None` is a cancel.
pub type PinPrompt = Box<dyn Fn(PinAsk) -> Option<zeroize::Zeroizing<String>> + Send + Sync>;

static PIN_PROMPT: std::sync::RwLock<Option<PinPrompt>> = std::sync::RwLock::new(None);

/// Sets how a PIN is asked for. Without one, a key with a PIN is refused as
/// cancelled.
pub fn set_pin_prompt(prompt: PinPrompt) {
    if let Ok(mut slot) = PIN_PROMPT.write() {
        *slot = Some(prompt);
    }
}

#[cfg_attr(
    any(windows, not(feature = "hardware"), feature = "test-authenticator"),
    allow(dead_code)
)]
pub(crate) fn ask_pin(question: PinAsk) -> Option<zeroize::Zeroizing<String>> {
    let slot = PIN_PROMPT.read().ok()?;
    slot.as_ref()?(question)
}
pub use types::{
    Authenticator, CredentialInfo, Enrollment, EnrollmentChallenge, FidoStatus, PlatformStatus,
    UnlockMaterial,
};

#[cfg(all(feature = "hardware", not(feature = "test-authenticator")))]
const RP_ID: &str = "silentsilo.com";

/// On Windows, bind the main app window HWND so WebAuthn can show its security-key UI.
#[cfg(all(windows, feature = "hardware"))]
pub fn set_parent_hwnd(hwnd: isize) {
    backend::set_parent_hwnd(hwnd);
}

#[cfg(not(all(windows, feature = "hardware")))]
pub fn set_parent_hwnd(_hwnd: isize) {}

pub fn status() -> FidoStatus {
    #[cfg(feature = "hardware")]
    {
        FidoStatus {
            key_present: backend::fido_key_present(),
            fido_accessible: backend::fido_interface_accessible(),
        }
    }
    #[cfg(not(feature = "hardware"))]
    {
        FidoStatus {
            key_present: false,
            fido_accessible: false,
        }
    }
}

pub fn is_available() -> bool {
    status().fido_accessible
}

pub fn require_fido_ready() -> Result<(), FidoError> {
    if !is_available() {
        return Err(FidoError::NoDevice);
    }
    Ok(())
}

pub fn begin_enrollment(
    vault_id: &str,
    key_slot: u8,
    authenticator: Authenticator,
) -> Result<EnrollmentChallenge, FidoError> {
    #[cfg(feature = "hardware")]
    {
        backend::begin_enrollment(vault_id, key_slot, authenticator)
    }
    #[cfg(not(feature = "hardware"))]
    {
        let _ = (vault_id, key_slot, authenticator);
        Err(FidoError::NotAvailable)
    }
}

/// Whether this machine has a built-in authenticator that can wrap the DEK.
///
/// Presence is not enough. On Windows the gate is `hmac-secret`/PRF support,
/// which is what produces the wrap key there; on macOS it is whether Touch
/// ID can answer, meaning a sensor exists, has fingerprints enrolled and is
/// not locked out. Offering the option on a machine that would fail halfway
/// through the ceremony is worse than not offering it.
pub fn platform_authenticator_available() -> bool {
    platform_status() == PlatformStatus::Ready
}

/// Whether this system can use a phone as the key (Android or iPhone, over
/// the QR code and Bluetooth). Windows 11 22H2 and later with WebAuthn API
/// 6; nowhere else, since no other backend runs the hybrid flow.
pub fn phone_available() -> bool {
    #[cfg(all(feature = "hardware", not(feature = "test-authenticator"), windows))]
    {
        backend::phone_available()
    }
    #[cfg(all(feature = "hardware", feature = "test-authenticator"))]
    {
        true
    }
    #[cfg(not(any(
        all(feature = "hardware", not(feature = "test-authenticator"), windows),
        all(feature = "hardware", feature = "test-authenticator")
    )))]
    {
        false
    }
}

/// The built-in authenticator's state, with the reason when it cannot be
/// used, so the app can say what to do rather than only hide the option.
pub fn platform_status() -> PlatformStatus {
    #[cfg(feature = "hardware")]
    {
        backend::platform_status()
    }
    #[cfg(not(feature = "hardware"))]
    {
        PlatformStatus::Absent
    }
}

/// Blocks until the platform is ready to be asked for another ceremony.
///
/// Enrolment runs two in a row, and on Windows the second one fails inside
/// the platform's own dialog when it starts too early. Call this between
/// them, on a blocking thread. `timeout_ms` caps the wait; the backends that
/// have nothing to wait for return at once.
pub fn wait_for_ceremony_teardown(timeout_ms: u64) {
    backend::wait_for_ceremony_teardown(timeout_ms);
}

pub fn complete_enrollment(challenge: &EnrollmentChallenge) -> Result<Enrollment, FidoError> {
    #[cfg(feature = "hardware")]
    {
        backend::complete_enrollment(challenge)
    }
    #[cfg(not(feature = "hardware"))]
    {
        let _ = challenge;
        Err(FidoError::NotAvailable)
    }
}

/// `on` pins which kind of authenticator to ask for.
///
/// `None` when unlocking, where any enrolled credential will do and the
/// allow-list already narrows it to this vault. Set during enrolment, where
/// the credential was created moments ago on a known authenticator: without
/// it Windows offers the whole menu a second time, so choosing Windows Hello
/// at step one leads to a security key and a QR code at step two.
pub fn derive_unlock_material(
    credential_ids: &[Vec<u8>],
    vault_id: &str,
    on: Option<Authenticator>,
) -> Result<UnlockMaterial, FidoError> {
    derive_unlock_material_opening(credential_ids, vault_id, on, None)
}

/// Says whether a secret opens the envelope of the credential it came from:
/// the silo's own check, which the ceremony cannot make itself.
pub type Opens<'a> = &'a (dyn Fn(&[u8], &[u8; 32]) -> bool + Sync);

/// [`derive_unlock_material`], told how to check a secret against the silo's
/// envelopes. When the verified secret opens nothing, a CTAP2 ceremony (Linux,
/// macOS) asks the key, in the same touch, for the secret it gives without
/// its PIN, which a silo enrolled before the key had a PIN is wrapped under
/// (`UnlockMaterial::unverified_wrap_key`). Without `opens` it never asks.
pub fn derive_unlock_material_opening(
    credential_ids: &[Vec<u8>],
    vault_id: &str,
    on: Option<Authenticator>,
    opens: Option<Opens>,
) -> Result<UnlockMaterial, FidoError> {
    #[cfg(feature = "hardware")]
    {
        backend::derive_unlock_material(credential_ids, vault_id, on, opens)
    }
    #[cfg(not(feature = "hardware"))]
    {
        let _ = (credential_ids, vault_id, on, opens);
        Err(FidoError::NotAvailable)
    }
}

/// The second ceremony of an enrolment, where the platform did not hand the
/// wrap key back with the credential (a security key on Windows).
///
/// Refuses a security key that was not verified, which on Windows means one
/// without a PIN. `hmac-secret` keeps a secret for verified assertions and
/// another for the rest, and Windows verifies every ceremony on a key with a
/// PIN: a silo wrapped under the unverified one stops opening the day the key
/// gets a PIN, and Windows 11 asks for one at the first passkey on any site.
pub fn derive_enrolment_material(
    credential_ids: &[Vec<u8>],
    vault_id: &str,
    on: Authenticator,
) -> Result<UnlockMaterial, FidoError> {
    let material = derive_unlock_material(credential_ids, vault_id, Some(on))?;
    refuse_unverified_key(material, on)
}

/// The check [`derive_enrolment_material`] makes, apart from the ceremony.
fn refuse_unverified_key(
    material: UnlockMaterial,
    on: Authenticator,
) -> Result<UnlockMaterial, FidoError> {
    if on != Authenticator::ThisDevice && !material.verified {
        return Err(FidoError::EnrollmentFailed(
            coded!(
                "err.key_needs_pin",
                "This key needs a PIN before it can open a silo. Set one with its maker's app or in Chrome's security key settings, then add it again."
            )
            .into(),
        ));
    }
    Ok(material)
}

/// Deletes this device's own platform key behind `credential_id`, once it
/// has been removed from its silo. Only a Mac's Touch ID key lives where
/// this can reach; any other id, and any other platform, is a no-op.
pub fn forget_platform_key(credential_id: &[u8]) -> Result<(), FidoError> {
    #[cfg(all(feature = "enclave", target_os = "macos"))]
    {
        backend::enclave_mac::remove(credential_id)
    }
    #[cfg(not(all(feature = "enclave", target_os = "macos")))]
    {
        let _ = credential_id;
        Ok(())
    }
}

pub fn dek_salt_for_vault(vault_id: &str) -> String {
    format!("silentsilo-dek-v1:{vault_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material(verified: bool) -> UnlockMaterial {
        UnlockMaterial {
            wrap_key: [7; 32],
            credential_id: vec![1, 2, 3],
            verified,
            unverified_wrap_key: None,
        }
    }

    #[test]
    fn a_security_key_that_did_not_verify_is_not_enrolled() {
        let Err(FidoError::EnrollmentFailed(why)) =
            refuse_unverified_key(material(false), Authenticator::SecurityKey)
        else {
            panic!("a security key without a PIN was enrolled");
        };
        assert!(why.contains("err.key_needs_pin"), "{why}");
    }

    #[test]
    fn a_security_key_that_verified_is_enrolled_as_derived() {
        let kept = refuse_unverified_key(material(true), Authenticator::SecurityKey).unwrap();
        assert_eq!(kept.wrap_key, [7; 32]);
        assert_eq!(kept.credential_id, vec![1, 2, 3]);
    }

    /// Taken from release 1.10.x and must never change: every key's wrap
    /// key is derived from this string, so a change means silos stop opening.
    #[test]
    fn the_dek_salt_string_is_the_one_every_silo_was_wrapped_under() {
        assert_eq!(
            dek_salt_for_vault("0198b7e2-5a3c-7d10-9c1e-3f2a4b5c6d7e"),
            "silentsilo-dek-v1:0198b7e2-5a3c-7d10-9c1e-3f2a4b5c6d7e"
        );
    }

    #[test]
    fn this_devices_authenticator_is_never_refused_for_it() {
        for verified in [true, false] {
            assert!(refuse_unverified_key(material(verified), Authenticator::ThisDevice).is_ok());
        }
    }

    #[test]
    fn a_phone_is_held_to_the_rule_for_a_security_key() {
        // A phone always verifies, so this only matters if one ever says it
        // did not: then its secret would change the day it does.
        assert!(refuse_unverified_key(material(false), Authenticator::Phone).is_err());
        assert!(refuse_unverified_key(material(true), Authenticator::Phone).is_ok());
    }

    #[test]
    fn a_phone_is_named_phone_on_the_wire() {
        assert_eq!(
            serde_json::to_string(&Authenticator::Phone).unwrap(),
            "\"phone\""
        );
        let parsed: Authenticator = serde_json::from_str("\"phone\"").unwrap();
        assert_eq!(parsed, Authenticator::Phone);
    }
}
