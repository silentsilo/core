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
        available, derive_unlock_material, enrol, holds_any, remove,
    };
}
#[cfg(feature = "passkey")]
pub mod passkey;
// Only the Windows backend builds client data: WebAuthn takes it whole. The
// CTAP2 path sends its hash and makes it in `ctap2`.
#[cfg(all(feature = "hardware", not(feature = "test-authenticator"), windows))]
mod client_data;
mod error;
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
    Authenticator, CredentialInfo, Enrollment, EnrollmentChallenge, FidoStatus, UnlockMaterial,
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
    #[cfg(feature = "hardware")]
    {
        backend::platform_authenticator_available()
    }
    #[cfg(not(feature = "hardware"))]
    {
        false
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
    #[cfg(feature = "hardware")]
    {
        backend::derive_unlock_material(credential_ids, vault_id, on)
    }
    #[cfg(not(feature = "hardware"))]
    {
        let _ = (credential_ids, vault_id, on);
        Err(FidoError::NotAvailable)
    }
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
