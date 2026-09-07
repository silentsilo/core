//! macOS: two authenticators behind the one backend interface. A removable
//! key goes over CTAP exactly as on Linux; "this device" is the Secure
//! Enclave behind Touch ID, in `enclave_mac`. The split is by credential
//! id shape: an enclave id is the tag-then-point layout `crate::enclave`
//! defines, a FIDO2 id is whatever the key minted, and a mixed allow-list
//! from a silo shared between a Mac and a YubiKey sorts itself out here.

use super::{ctap, enclave_mac};
use crate::enclave;
use crate::types::{
    Authenticator, CredentialInfo, Enrollment, EnrollmentChallenge, UnlockMaterial,
};
use crate::{FidoError, RP_ID};

pub(crate) fn fido_key_present() -> bool {
    ctap::fido_key_present()
}

pub(crate) fn fido_interface_accessible() -> bool {
    ctap::fido_interface_accessible()
}

pub fn probe_device() -> Result<(), FidoError> {
    ctap::probe_device()
}

pub(crate) fn platform_authenticator_available() -> bool {
    enclave_mac::available()
}

pub(crate) fn wait_for_ceremony_teardown(timeout_ms: u64) {
    ctap::wait_for_ceremony_teardown(timeout_ms)
}

pub fn begin_enrollment(
    vault_id: &str,
    key_slot: u8,
    authenticator: Authenticator,
) -> Result<EnrollmentChallenge, FidoError> {
    match authenticator {
        Authenticator::SecurityKey => ctap::begin_enrollment(vault_id, key_slot, authenticator),
        Authenticator::ThisDevice => {
            if !enclave_mac::available() {
                return Err(FidoError::NotAvailable);
            }
            // The enclave signs nothing at enrolment, so there is no
            // challenge to answer. The fields are filled so both paths
            // share one type and the vault id reaches `complete_enrollment`.
            Ok(EnrollmentChallenge {
                challenge: Vec::new(),
                rp_id: RP_ID.into(),
                user_id: vault_id.to_string(),
                key_slot,
                authenticator,
            })
        }
    }
}

pub fn complete_enrollment(challenge: &EnrollmentChallenge) -> Result<Enrollment, FidoError> {
    match challenge.authenticator {
        Authenticator::SecurityKey => ctap::complete_enrollment(challenge),
        Authenticator::ThisDevice => {
            let material = enclave_mac::enrol(&challenge.user_id)?;
            // One ceremony, like Hello: the wrap key is known at enrolment,
            // so the caller wraps the DEK now rather than asking again.
            Ok(Enrollment {
                credential: CredentialInfo {
                    credential_id: material.credential_id.clone(),
                    public_key: material.ephemeral_public.clone(),
                    key_slot: challenge.key_slot,
                    rp_id: challenge.rp_id.clone(),
                    authenticator: challenge.authenticator,
                },
                unlock: Some(UnlockMaterial {
                    wrap_key: *material.wrap_key,
                    credential_id: material.credential_id.clone(),
                }),
            })
        }
    }
}

/// `on` says which authenticator the user picked. Without it, Touch ID goes
/// first when this Mac holds one of the enclave keys and biometry can
/// actually answer: it prompts on the machine and needs nothing plugged in.
/// Anything else falls through to the security key.
///
/// The fall-through is the part that matters. Touch ID has more ways to be
/// unavailable than a security key does: the lid is closed on an external
/// display, biometry is locked out after five failed attempts, or the user
/// added a fingerprint and invalidated the enclave key for good. In every
/// one of those a key is plugged in and works, so refusing there would be a
/// lockout this code chose rather than one the silo requires.
pub fn derive_unlock_material(
    credential_ids: &[Vec<u8>],
    vault_id: &str,
    on: Option<Authenticator>,
) -> Result<UnlockMaterial, FidoError> {
    let (enclave_ids, fido2_ids): (Vec<Vec<u8>>, Vec<Vec<u8>>) = credential_ids
        .iter()
        .cloned()
        .partition(|id| enclave::split_credential_id(id).is_some());

    // Asked here rather than trusted from enrolment: whether the sensor can
    // answer is a property of this moment, not of this machine.
    let touch_id_ready = !enclave_ids.is_empty() && enclave_mac::available();

    if on == Some(Authenticator::SecurityKey) {
        return ctap::derive_unlock_material(&fido2_ids, vault_id, on);
    }

    let enclave_err = if touch_id_ready
        && (on == Some(Authenticator::ThisDevice) || enclave_mac::holds_any(&enclave_ids))
    {
        match enclave_mac::derive_unlock_material(&enclave_ids, vault_id) {
            Ok(material) => return Ok(material),
            Err(e) => Some(e),
        }
    } else {
        None
    };

    // The user named Touch ID, so a security key is not what they were
    // asked for. Say why it did not work rather than sending them to a
    // drawer for hardware they did not mention.
    if on == Some(Authenticator::ThisDevice) {
        return Err(enclave_err.unwrap_or_else(|| {
            FidoError::UnlockFailed(
                "Touch ID cannot answer right now, and this Mac holds no Touch ID key for this \
                 silo. Use an enrolled security key."
                    .into(),
            )
        }));
    }

    if fido2_ids.is_empty() {
        return Err(enclave_err.unwrap_or_else(|| {
            FidoError::UnlockFailed(
                "No Touch ID key for this silo on this Mac, and no security key enrolled".into(),
            )
        }));
    }
    ctap::derive_unlock_material(&fido2_ids, vault_id, on)
}
