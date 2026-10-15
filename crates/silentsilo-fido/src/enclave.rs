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
//! The point in the id is not signed, and the enclave agrees with any point
//! it is handed. Storage that put in a point of its own would know the
//! agreement (from the enclave's public key, published beside it) and could
//! wrap a DEK of its choosing under it. So each device binds the point it
//! enrolled with, in its own keychain beside the enclave key
//! ([`point_binding`]), and refuses any other before the enclave is asked.
//!
//! Everything here runs on every platform and is tested on every platform;
//! the enclave itself only enters in `backend/enclave_mac.rs`. The iOS
//! build uses the same scheme, with its own code reaching the enclave.

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
    /// The ephemeral public key alone. The same bytes as the tail of
    /// `credential_id`.
    pub ephemeral_public: Vec<u8>,
    /// The device key's public half, uncompressed, for the envelope's
    /// `public_key` field: what names the key that can reproduce the
    /// agreement, as a FIDO2 envelope names its credential's key.
    pub device_public: Vec<u8>,
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

    let device_public = enclave_public.to_sec1_bytes().to_vec();
    let ephemeral = random_secret();
    let ephemeral_public = ephemeral.public_key().to_sec1_bytes().to_vec();
    // Checked rather than asserted in debug only. `to_sec1_bytes` is
    // uncompressed for this curve today; if that ever changed, a release
    // build would mint an id `split_credential_id` rejects forever, and it
    // would do so after the DEK had been re-wrapped under a key nothing can
    // reproduce. An error here costs an enrolment, the alternative costs
    // the silo.
    if ephemeral_public.len() != POINT_LEN || device_public.len() != POINT_LEN {
        return Err(FidoError::EnrollmentFailed(
            "a public key in the agreement is not an uncompressed point".into(),
        ));
    }

    let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), enclave_public.as_affine());
    let wrap_key = wrap_key_from_shared(shared.raw_secret_bytes(), vault_id);

    let credential_id = join_credential_id(tag, &ephemeral_public);

    Ok(EnrolMaterial {
        credential_id,
        ephemeral_public,
        device_public,
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
/// built against, 0.10, which is a major ahead of the 0.9 this workspace
/// uses through `rand`. Bridging the two is more code than drawing
/// thirty-two bytes and asking the curve whether they are a valid scalar.
/// The values it rejects are zero and everything from the group order up,
/// about one draw in four billion, so a second iteration is something no
/// machine here will see.
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

/// What a device keeps beside its enclave key at enrolment: the SHA-256 of
/// the ephemeral point it enrolled with. The point travels unsigned in the
/// credential id, and the enclave agrees with any point it is handed, so a
/// point is used only when it matches this (see `backend/enclave_mac.rs`).
pub fn point_binding(point: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    Sha256::digest(point).into()
}

/// Whether `point` is the one a stored binding was made from.
pub fn binding_matches(binding: &[u8], point: &[u8]) -> bool {
    binding == point_binding(point).as_slice()
}

/// A credential id: the keychain tag, then the ephemeral point.
fn join_credential_id(tag: &[u8; TAG_LEN], point: &[u8]) -> Vec<u8> {
    let mut id = Vec::with_capacity(CREDENTIAL_ID_LEN);
    id.extend_from_slice(tag);
    id.extend_from_slice(point);
    id
}

/// The keychain label an enrolment's key is filed under, tag in hex. What
/// Keychain Access shows, so it says what it is. Unlock finds the key by it.
pub fn keychain_label(tag: &[u8]) -> String {
    format!("SilentSilo Touch ID {}", hex::encode(tag))
}

/// The keychain service the point bindings are filed under, one item per
/// key, named by the tag in hex.
pub const BINDING_SERVICE: &str = "com.silentsilo.enclave-point";

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
        assert_eq!(
            enrolled.device_public, enclave_public,
            "the device key, not the ephemeral one"
        );
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

    /// The forgery the binding stops: storage puts in a point of its own,
    /// for which it knows the agreement, and a DEK of its own under it.
    #[test]
    fn a_point_storage_replaced_does_not_match_the_binding() {
        let (_, enclave_public) = software_enclave();
        let enrolled = enrol(&enclave_public, "vault-1", &random_tag()).expect("enrol");
        let binding = point_binding(&enrolled.ephemeral_public);
        assert!(binding_matches(&binding, &enrolled.ephemeral_public));

        let (_, planted) = software_enclave();
        assert!(!binding_matches(&binding, &planted));
        assert!(!binding_matches(&[], &enrolled.ephemeral_public));
    }

    #[test]
    fn a_fido2_id_on_the_same_list_is_not_mistaken_for_ours() {
        assert!(split_credential_id(&[0xaa, 0x11]).is_none(), "too short");
        assert!(
            split_credential_id(&[0u8; CREDENTIAL_ID_LEN]).is_none(),
            "right length, not a point"
        );
    }

    // Known answers taken from release 1.10.x. They must never change: a
    // change means every silo enrolled with Touch ID or Face ID stops
    // opening.

    const VAULT: &str = "0198b7e2-5a3c-7d10-9c1e-3f2a4b5c6d7e";
    const TAG: &str = "000102030405060708090a0b0c0d0e0f";
    /// The P-256 base point, uncompressed, as the ephemeral key.
    const POINT: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    /// `TAG`, then `POINT`.
    const CREDENTIAL_ID: &str = "000102030405060708090a0b0c0d0e0f046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

    #[test]
    fn the_wrap_key_from_a_shared_secret_is_the_one_every_device_derives() {
        assert_eq!(HKDF_INFO, b"silentsilo secure-enclave wrap key v1");
        assert_eq!(
            hex::encode(*wrap_key_from_shared(&[0x11; 32], VAULT)),
            "5f0d25cde93fcdcd9b9dc283f901f8d2d416ee0aff8363a935b1f006f705f757"
        );
    }

    #[test]
    fn a_fixed_enclave_key_unlocks_a_literal_credential_id_to_a_fixed_wrap_key() {
        // The chip's half, with a fixed key standing in for the enclave's.
        let enclave = SecretKey::from_slice(&[0x42; 32]).expect("a valid scalar");
        let id = hex::decode(CREDENTIAL_ID).unwrap();
        let (_, point) = split_credential_id(&id).expect("our own id");
        let point = PublicKey::from_sec1_bytes(point).expect("the base point");
        let shared = diffie_hellman(enclave.to_nonzero_scalar(), point.as_affine());
        assert_eq!(
            hex::encode(*wrap_key_from_shared(shared.raw_secret_bytes(), VAULT)),
            "45b22ea18e4f561f4594b12c6e207cfd212b53c4965bb2befb6823bfdd1b6497"
        );
    }

    #[test]
    fn a_credential_id_is_the_sixteen_byte_tag_then_the_point() {
        assert_eq!((TAG_LEN, POINT_LEN, CREDENTIAL_ID_LEN), (16, 65, 81));
        let id = hex::decode(CREDENTIAL_ID).unwrap();
        let (tag, point) = split_credential_id(&id).expect("a literal id of ours");
        assert_eq!(hex::encode(tag), TAG);
        assert_eq!(hex::encode(point), POINT);

        let tag: [u8; TAG_LEN] = tag.try_into().unwrap();
        assert_eq!(hex::encode(join_credential_id(&tag, point)), CREDENTIAL_ID);
    }

    #[test]
    fn the_point_binding_is_the_sha256_of_the_point() {
        let point = hex::decode(POINT).unwrap();
        assert_eq!(
            hex::encode(point_binding(&point)),
            "698bea63dc44a344663ff1429aea10842df27b6b991ef25866b2c6c02cdcc5be"
        );
    }

    #[test]
    fn the_keychain_names_are_the_ones_enrolled_keys_are_filed_under() {
        let tag = hex::decode(TAG).unwrap();
        assert_eq!(
            keychain_label(&tag),
            "SilentSilo Touch ID 000102030405060708090a0b0c0d0e0f"
        );
        assert_eq!(BINDING_SERVICE, "com.silentsilo.enclave-point");
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
