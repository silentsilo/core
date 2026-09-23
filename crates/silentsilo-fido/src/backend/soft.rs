//! A security key made of a constant, for end-to-end tests of the real app:
//! a runner cannot touch a key or answer Windows Hello. Every ceremony
//! succeeds at once, and the wrap key is derived from a secret written
//! below, so a silo made with it is readable by anyone with this source.
//!
//! Debug builds only: the crate refuses to compile the feature without
//! `debug_assertions`, so a release build cannot carry it by accident.

use crate::{
    Authenticator, CredentialInfo, Enrollment, EnrollmentChallenge, FidoError, UnlockMaterial,
};

const SECRET: &[u8; 32] = b"silentsilo-test-authenticator-01";
const PREFIX: &[u8] = b"soft-";

pub fn set_parent_hwnd(_hwnd: isize) {}

pub(crate) fn wait_for_ceremony_teardown(_timeout_ms: u64) {}

pub(crate) fn fido_key_present() -> bool {
    true
}

pub(crate) fn fido_interface_accessible() -> bool {
    true
}

pub(crate) fn platform_authenticator_available() -> bool {
    true
}

pub fn begin_enrollment(
    vault_id: &str,
    key_slot: u8,
    authenticator: Authenticator,
) -> Result<EnrollmentChallenge, FidoError> {
    Ok(EnrollmentChallenge {
        challenge: vec![0; 32],
        rp_id: "silentsilo.com".into(),
        user_id: vault_id.into(),
        key_slot,
        authenticator,
    })
}

fn credential_id(challenge: &EnrollmentChallenge) -> Vec<u8> {
    let kind = match challenge.authenticator {
        Authenticator::SecurityKey => "key",
        Authenticator::ThisDevice => "device",
    };
    [PREFIX, format!("{kind}-{}", challenge.key_slot).as_bytes()].concat()
}

fn wrap_key(credential_id: &[u8], vault_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(SECRET);
    hasher.update(credential_id);
    hasher.update(crate::dek_salt_for_vault(vault_id).as_bytes());
    *hasher.finalize().as_bytes()
}

pub fn complete_enrollment(challenge: &EnrollmentChallenge) -> Result<Enrollment, FidoError> {
    let id = credential_id(challenge);
    Ok(Enrollment {
        unlock: Some(UnlockMaterial {
            wrap_key: wrap_key(&id, &challenge.user_id),
            credential_id: id.clone(),
        }),
        credential: CredentialInfo {
            credential_id: id,
            public_key: Vec::new(),
            key_slot: challenge.key_slot,
            rp_id: challenge.rp_id.clone(),
            authenticator: challenge.authenticator,
        },
    })
}

pub fn derive_unlock_material(
    credential_ids: &[Vec<u8>],
    vault_id: &str,
    _on: Option<Authenticator>,
) -> Result<UnlockMaterial, FidoError> {
    let id = credential_ids
        .iter()
        .find(|id| id.starts_with(PREFIX))
        .ok_or(FidoError::NoDevice)?;
    Ok(UnlockMaterial {
        wrap_key: wrap_key(id, vault_id),
        credential_id: id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlocking_gives_the_wrap_key_enrolment_gave() {
        let challenge = begin_enrollment("vault", 0, Authenticator::SecurityKey).unwrap();
        let enrolled = complete_enrollment(&challenge).unwrap();
        let unlocked = derive_unlock_material(
            std::slice::from_ref(&enrolled.credential.credential_id),
            "vault",
            None,
        )
        .unwrap();
        assert_eq!(enrolled.unlock.unwrap().wrap_key, unlocked.wrap_key);
        let other = derive_unlock_material(&[enrolled.credential.credential_id], "other", None);
        assert_ne!(other.unwrap().wrap_key, unlocked.wrap_key);
    }
}
