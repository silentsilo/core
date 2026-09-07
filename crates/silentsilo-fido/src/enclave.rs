//! The key derivation behind a Secure Enclave envelope, with nothing
//! platform-specific in it.
//!
//! A FIDO2 key hands back an `hmac-secret`, and that output is the wrap key.
//! The enclave has no such extension; what it has is a P-256 private key
//! that never leaves the chip and whose use is gated on Touch ID. The wrap
//! key therefore comes from a Diffie-Hellman agreement between that key and
//! an ephemeral one made at enrolment:
//!
//! - **Enrol:** generate an ephemeral P-256 pair, agree with the enclave's
//!   public key, run the shared secret through HKDF, wrap the DEK under the
//!   result, keep the ephemeral *public* half and throw the private half
//!   away.
//! - **Unlock:** hand the ephemeral public half back to the enclave, which
//!   agrees with its private key after Touch ID, and run the same HKDF.
//!
//! Knowing both public keys gives nobody the shared secret; that is the
//! computational Diffie-Hellman assumption and the whole point of the
//! scheme. The enclave's private key is the only thing that can reproduce
//! it, and the enclave will not use it without a fingerprint.
//!
//! The ephemeral public key has to be available at unlock, and unlock only
//! receives credential ids. So the id carries it: sixteen random bytes that
//! name the enclave key in this machine's keychain, followed by the
//! sixty-five bytes of the uncompressed point. Every client stores a
//! credential id verbatim whether it understands the kind or not, which is
//! what lets a Windows build carry a Mac's key across a shared silo
//! untouched.
//!
//! Everything here runs on every platform and is tested on every platform;
//! the enclave itself only enters in `backend/enclave_mac.rs`.

use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{FidoError, dek_salt_for_vault};

/// The random prefix of a credential id, which names the enclave key in
/// the keychain. Sixteen bytes: not a secret, just unguessable enough that
/// two enrolments on one machine never collide.
pub const TAG_LEN: usize = 16;

/// An uncompressed SEC1 P-256 point: `0x04`, then X, then Y.
pub const POINT_LEN: usize = 65;

/// What a Secure Enclave credential id is: the keychain tag, then the
/// ephemeral public key.
pub const CREDENTIAL_ID_LEN: usize = TAG_LEN + POINT_LEN;

/// Domain separation for the HKDF expand. Changing this is a new derivation
/// and therefore a new `derivation` value on the envelope, never a silent
/// edit.
const HKDF_INFO: &[u8] = b"silentsilo secure-enclave wrap key v1";

/// What enrolling against an enclave key produces.
pub struct EnrolMaterial {
    /// Tag, then ephemeral public key. What the envelope stores as
    /// `credential_id`, hex-encoded.
    pub credential_id: Vec<u8>,
    /// The ephemeral public key alone, for the envelope's `public_key`
    /// field. The same bytes as the tail of `credential_id`.
    pub ephemeral_public: Vec<u8>,
    /// Wraps the DEK. Wiped when this is dropped.
    pub wrap_key: Zeroizing<[u8; 32]>,
}

/// Agrees with `enclave_public_sec1`, the enclave key's public half as
/// `SecKeyCopyExternalRepresentation` hands it out, and derives the wrap key
/// for `vault_id`.
pub fn enrol(
    enclave_public_sec1: &[u8],
    vault_id: &str,
    tag: &[u8; TAG_LEN],
) -> Result<EnrolMaterial, FidoError> {
    let enclave_public = PublicKey::from_sec1_bytes(enclave_public_sec1).map_err(|_| {
        FidoError::EnrollmentFailed("the enclave returned a public key that is not P-256".into())
    })?;

    let ephemeral = random_secret();
    let ephemeral_public = ephemeral.public_key().to_sec1_bytes().to_vec();
    debug_assert_eq!(ephemeral_public.len(), POINT_LEN);

    let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), enclave_public.as_affine());
    let wrap_key = wrap_key_from_shared(shared.raw_secret_bytes(), vault_id);

    let mut credential_id = Vec::with_capacity(CREDENTIAL_ID_LEN);
    credential_id.extend_from_slice(tag);
    credential_id.extend_from_slice(&ephemeral_public);

    Ok(EnrolMaterial {
        credential_id,
        ephemeral_public,
        wrap_key,
    })
}

/// The keychain tag for a new enrolment. The backend draws it before it
/// generates the enclave key, because the tag is what the key is filed
/// under and a key's attributes are fixed at creation.
pub fn random_tag() -> [u8; TAG_LEN] {
    let mut tag = [0u8; TAG_LEN];
    rand::rng().fill_bytes(&mut tag);
    tag
}

/// A fresh P-256 private key from the process's own generator.
///
/// Not `SecretKey::random`: that wants the `rand_core` the curve crate was
/// built against, which is a major behind the one this workspace uses, and
/// bridging the two is more code than drawing thirty-two bytes and asking
/// the curve whether they are a valid scalar. All but two values in that
/// range are, so the loop runs once.
fn random_secret() -> SecretKey {
    loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(bytes.as_mut());
        if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
            return secret;
        }
    }
}

/// HKDF-SHA256 over the raw shared secret, salted by the same per-vault
/// string the FIDO2 path feeds its `hmac-secret`, so two silos on one
/// machine never share a wrap key even if they shared an enclave key.
pub fn wrap_key_from_shared(shared_x: &[u8], vault_id: &str) -> Zeroizing<[u8; 32]> {
    let salt = dek_salt_for_vault(vault_id);
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), shared_x);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, out.as_mut())
        .expect("32 bytes is within HKDF-SHA256's output limit");
    out
}

/// Takes a credential id apart, or says it is not one of ours.
///
/// `None` is the answer for a FIDO2 id on the same allow-list, which is
/// shorter, and for anything that does not start a valid point. The caller
/// skips it; a Secure Enclave backend has nothing to say about a YubiKey.
pub fn split_credential_id(id: &[u8]) -> Option<(&[u8], &[u8])> {
    if id.len() != CREDENTIAL_ID_LEN {
        return None;
    }
    let (tag, point) = id.split_at(TAG_LEN);
    PublicKey::from_sec1_bytes(point).ok()?;
    Some((tag, point))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An "enclave" in software, for the half of the protocol the chip runs.
    fn software_enclave() -> (SecretKey, Vec<u8>) {
        let secret = random_secret();
        let public = secret.public_key().to_sec1_bytes().to_vec();
        (secret, public)
    }

    #[test]
    fn the_enclave_side_derives_the_same_wrap_key() {
        // The property everything rests on: what enrolment wrapped the DEK
        // under, the enclave can reproduce from the ephemeral public key
        // alone, and nothing else is needed at unlock.
        let (enclave_secret, enclave_public) = software_enclave();
        let enrolled = enrol(&enclave_public, "vault-1", &random_tag()).expect("enrol");

        let (_, ephemeral) = split_credential_id(&enrolled.credential_id).expect("our own id");
        let ephemeral = PublicKey::from_sec1_bytes(ephemeral).expect("a point we just made");
        let shared = diffie_hellman(enclave_secret.to_nonzero_scalar(), ephemeral.as_affine());
        let at_unlock = wrap_key_from_shared(shared.raw_secret_bytes(), "vault-1");

        assert_eq!(*enrolled.wrap_key, *at_unlock);
    }

    #[test]
    fn the_credential_id_is_the_tag_then_the_point() {
        let (_, enclave_public) = software_enclave();
        let tag = random_tag();
        let enrolled = enrol(&enclave_public, "vault-1", &tag).expect("enrol");

        assert_eq!(enrolled.credential_id.len(), CREDENTIAL_ID_LEN);
        assert_eq!(&enrolled.credential_id[..TAG_LEN], &tag[..]);
        assert_eq!(
            &enrolled.credential_id[TAG_LEN..],
            &enrolled.ephemeral_public[..]
        );
        assert_eq!(enrolled.ephemeral_public[0], 0x04, "uncompressed SEC1");
    }

    #[test]
    fn two_silos_on_one_enclave_key_get_different_wrap_keys() {
        // The salt is the vault id, so sharing an enclave key across silos
        // (which the backend does not do, but could) would still not share
        // a wrap key.
        let shared = [7u8; 32];
        assert_ne!(
            *wrap_key_from_shared(&shared, "vault-a"),
            *wrap_key_from_shared(&shared, "vault-b")
        );
    }

    #[test]
    fn a_fido2_id_on_the_same_list_is_not_mistaken_for_ours() {
        assert!(split_credential_id(&[0xaa, 0x11]).is_none(), "too short");
        assert!(
            split_credential_id(&[0u8; CREDENTIAL_ID_LEN]).is_none(),
            "right length, not a point"
        );
    }

    #[test]
    fn a_public_key_that_is_not_a_point_is_refused_at_enrolment() {
        // No `unwrap_err`: that needs `Debug` on the success type, and a
        // struct holding a wrap key is not something to make printable.
        match enrol(&[0x04; 65], "vault-1", &random_tag()) {
            Err(FidoError::EnrollmentFailed(_)) => {}
            Err(other) => panic!("wrong error: {other}"),
            Ok(_) => panic!("a byte string that is not a point was accepted"),
        }
    }
}
