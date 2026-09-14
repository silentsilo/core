//! The cryptography of the inbox: how a locked device hands content to a
//! silo it cannot open.
//!
//! A phone backing up photos in the background holds no key that opens the
//! silo, by design. What it holds is the silo's inbox *public* key, learned
//! while the silo was unlocked, and a signing key of its own. For each item
//! it:
//!
//! - encrypts the content as an ordinary `.sslo` blob under a fresh content
//!   key;
//! - seals that content key and the item's metadata to the inbox key: P-256
//!   Diffie-Hellman with a fresh ephemeral key, HKDF-SHA256 salted by the
//!   vault id, AES-256-GCM with the item header as associated data;
//! - signs the header and the sealed bytes with ECDSA P-256 over SHA-256.
//!
//! An unlocked device holds the inbox secret (sealed under the content KEK in
//! storage), checks the signature against the sender's registered key, opens
//! the item and records it as a normal file. Nothing here touches storage or
//! the file formats around it; see `silentsilo-sync`'s inbox module.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::{PublicKey, SecretKey};
use rand::RngCore;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// An uncompressed SEC1 P-256 point: `0x04`, then X, then Y.
pub const POINT_LEN: usize = 65;

/// A raw ECDSA P-256 signature: `r` then `s`, 32 bytes each, `s` low.
pub const SIGNATURE_LEN: usize = 64;

const NONCE_LEN: usize = 12;

/// Starts every item header. Names the version, so a header of another
/// version can never verify or open as this one.
const HEADER_DOMAIN: &[u8] = b"silentsilo inbox item v1\0";

/// Domain separation for the HKDF expand.
const HKDF_INFO: &[u8] = b"silentsilo inbox item key v1";

fn hkdf_salt(vault_id: Uuid) -> String {
    format!("silentsilo-inbox-v1:{vault_id}")
}

/// A P-256 private key: the inbox secret, or a software sender's signing key.
pub struct EcSecret(Zeroizing<[u8; 32]>);

impl EcSecret {
    /// A fresh key from the process's own generator.
    ///
    /// Drawn as bytes and checked rather than through `SecretKey::random`,
    /// which wants a newer `rand_core` than this workspace uses; the values
    /// rejected are zero and those at or above the group order, about one
    /// draw in four billion.
    pub fn generate() -> Self {
        loop {
            let mut bytes = Zeroizing::new([0u8; 32]);
            rand::rng().fill_bytes(bytes.as_mut());
            if SecretKey::from_slice(bytes.as_ref()).is_ok() {
                return Self(bytes);
            }
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        SecretKey::from_slice(&bytes)
            .map_err(|_| CryptoError::InvalidHeader("not a P-256 private key".into()))?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn secret(&self) -> SecretKey {
        SecretKey::from_slice(self.0.as_ref()).expect("checked when constructed")
    }

    /// The public half, uncompressed.
    pub fn public_key(&self) -> [u8; POINT_LEN] {
        point_bytes(&self.secret().public_key())
    }

    /// Signs `message` the way a sender does, for senders without a
    /// hardware key and for tests. Deterministic (RFC 6979), `s` low.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        let key = SigningKey::from(self.secret());
        let signature: Signature = key.sign(message);
        signature_bytes(&signature)
    }
}

fn point_bytes(key: &PublicKey) -> [u8; POINT_LEN] {
    key.to_sec1_bytes()
        .as_ref()
        .try_into()
        .expect("P-256 points serialise uncompressed")
}

fn parse_point(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
    if bytes.len() != POINT_LEN {
        return Err(CryptoError::InvalidHeader(
            "not an uncompressed P-256 point".into(),
        ));
    }
    PublicKey::from_sec1_bytes(bytes)
        .map_err(|_| CryptoError::InvalidHeader("not a P-256 point".into()))
}

fn signature_bytes(signature: &Signature) -> [u8; SIGNATURE_LEN] {
    let low = signature.normalize_s();
    low.to_bytes()
        .as_slice()
        .try_into()
        .expect("P-256 signatures are 64 bytes")
}

/// Whether `signature` is `sender_public`'s over `message`.
pub fn verify_signature(
    sender_public: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let key = VerifyingKey::from(parse_point(sender_public)?);
    let signature = Signature::from_slice(signature)
        .map_err(|_| CryptoError::InvalidHeader("not a P-256 signature".into()))?;
    key.verify(message, &signature)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// A DER-encoded ECDSA signature, as Android's Keystore and Apple's
/// Security framework return one, in the raw form an item stores.
pub fn signature_from_der(der: &[u8]) -> Result<[u8; SIGNATURE_LEN], CryptoError> {
    let bad = || CryptoError::InvalidHeader("not a DER ECDSA signature".into());

    // SEQUENCE { INTEGER r, INTEGER s }, short-form lengths only: the
    // largest P-256 signature is 72 bytes.
    let (&tag, rest) = der.split_first().ok_or_else(bad)?;
    let (&len, body) = rest.split_first().ok_or_else(bad)?;
    if tag != 0x30 || len & 0x80 != 0 || body.len() != len as usize {
        return Err(bad());
    }
    let (r, rest) = der_integer(body).ok_or_else(bad)?;
    let (s, rest) = der_integer(rest).ok_or_else(bad)?;
    if !rest.is_empty() {
        return Err(bad());
    }

    let mut raw = [0u8; SIGNATURE_LEN];
    raw[32 - r.len()..32].copy_from_slice(r);
    raw[64 - s.len()..].copy_from_slice(s);
    let signature = Signature::from_slice(&raw).map_err(|_| bad())?;
    Ok(signature_bytes(&signature))
}

/// One positive DER INTEGER, without its sign padding, and what follows it.
fn der_integer(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&len, rest) = rest.split_first()?;
    let len = len as usize;
    if tag != 0x02 || len == 0 || len > 33 || rest.len() < len {
        return None;
    }
    let (value, rest) = rest.split_at(len);
    let value = match value {
        [0, tail @ ..] if !tail.is_empty() => tail,
        _ => value,
    };
    (value.len() <= 32).then_some((value, rest))
}

/// What names and binds one item. Everything in it is authenticated twice:
/// as the associated data of the sealed bytes, and under the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemHeader {
    pub item_id: Uuid,
    pub blob_id: Uuid,
    /// The inbox key the item is sealed to.
    pub key_id: Uuid,
    pub sender_id: Uuid,
    /// Seconds since the epoch, as the sender's clock had it.
    pub sent_at: i64,
    /// The `.sslo` object's size in bytes, checked against storage before
    /// an import records anything.
    pub blob_size: u64,
    pub ephemeral: [u8; POINT_LEN],
}

impl ItemHeader {
    /// The domain string, then each field at a fixed width, big-endian.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_DOMAIN.len() + 16 * 4 + 16 + POINT_LEN);
        out.extend_from_slice(HEADER_DOMAIN);
        out.extend_from_slice(self.item_id.as_bytes());
        out.extend_from_slice(self.blob_id.as_bytes());
        out.extend_from_slice(self.key_id.as_bytes());
        out.extend_from_slice(self.sender_id.as_bytes());
        out.extend_from_slice(&self.sent_at.to_be_bytes());
        out.extend_from_slice(&self.blob_size.to_be_bytes());
        out.extend_from_slice(&self.ephemeral);
        out
    }

    /// What the sender signs: the header, then the sealed bytes.
    pub fn signed_message(&self, sealed: &[u8]) -> Vec<u8> {
        let mut out = self.to_bytes();
        out.extend_from_slice(sealed);
        out
    }
}

/// The identifying fields of an item, before an ephemeral key exists.
#[derive(Debug, Clone, Copy)]
pub struct ItemIds {
    pub item_id: Uuid,
    pub blob_id: Uuid,
    pub key_id: Uuid,
    pub sender_id: Uuid,
    pub sent_at: i64,
    pub blob_size: u64,
}

fn item_key(shared_x: &[u8], vault_id: Uuid) -> Zeroizing<[u8; 32]> {
    let salt = hkdf_salt(vault_id);
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), shared_x);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, out.as_mut())
        .expect("32 bytes is within HKDF-SHA256's output limit");
    out
}

/// Seals `plaintext` to the inbox key `inbox_public` of `vault_id`.
/// Returns the header and `nonce || ciphertext || tag`.
pub fn seal_item(
    inbox_public: &[u8],
    vault_id: Uuid,
    ids: ItemIds,
    plaintext: &[u8],
) -> Result<(ItemHeader, Vec<u8>), CryptoError> {
    let inbox = parse_point(inbox_public)?;
    let ephemeral = EcSecret::generate();
    let header = ItemHeader {
        item_id: ids.item_id,
        blob_id: ids.blob_id,
        key_id: ids.key_id,
        sender_id: ids.sender_id,
        sent_at: ids.sent_at,
        blob_size: ids.blob_size,
        ephemeral: ephemeral.public_key(),
    };

    let shared = diffie_hellman(ephemeral.secret().to_nonzero_scalar(), inbox.as_affine());
    let key = item_key(shared.raw_secret_bytes(), vault_id);

    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let aad = header.to_bytes();
    let ciphertext = Aes256Gcm::new_from_slice(key.as_ref())
        .expect("valid key length")
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::InvalidHeader("failed to seal inbox item".into()))?;

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok((header, sealed))
}

/// Reverses [`seal_item`] with the inbox secret. Fails on the wrong key, a
/// different vault, or any change to the header or the sealed bytes.
pub fn open_item(
    inbox_secret: &EcSecret,
    vault_id: Uuid,
    header: &ItemHeader,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if sealed.len() < NONCE_LEN {
        return Err(CryptoError::DecryptionFailed);
    }
    let ephemeral = parse_point(&header.ephemeral)?;
    let shared = diffie_hellman(
        inbox_secret.secret().to_nonzero_scalar(),
        ephemeral.as_affine(),
    );
    let key = item_key(shared.raw_secret_bytes(), vault_id);

    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let aad = header.to_bytes();
    Aes256Gcm::new_from_slice(key.as_ref())
        .expect("valid key length")
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> ItemIds {
        ItemIds {
            item_id: Uuid::from_u128(1),
            blob_id: Uuid::from_u128(2),
            key_id: Uuid::from_u128(3),
            sender_id: Uuid::from_u128(4),
            sent_at: 1_789_000_000,
            blob_size: 4096,
        }
    }

    const VAULT: Uuid = Uuid::from_u128(0xabc);

    #[test]
    fn the_inbox_secret_opens_what_was_sealed_to_its_public_key() {
        let inbox = EcSecret::generate();
        let (header, sealed) =
            seal_item(&inbox.public_key(), VAULT, ids(), b"photo metadata").unwrap();
        let opened = open_item(&inbox, VAULT, &header, &sealed).unwrap();
        assert_eq!(opened.as_slice(), b"photo metadata");
    }

    #[test]
    fn another_key_or_another_vault_opens_nothing() {
        let inbox = EcSecret::generate();
        let (header, sealed) = seal_item(&inbox.public_key(), VAULT, ids(), b"x").unwrap();
        assert!(open_item(&EcSecret::generate(), VAULT, &header, &sealed).is_err());
        assert!(open_item(&inbox, Uuid::from_u128(0xdef), &header, &sealed).is_err());
    }

    #[test]
    fn changing_any_header_field_breaks_the_seal() {
        // The header is the associated data, so an item cannot be re-labelled
        // as another item, blob, sender or size without failing to open.
        let inbox = EcSecret::generate();
        let (header, sealed) = seal_item(&inbox.public_key(), VAULT, ids(), b"x").unwrap();
        let variants = [
            ItemHeader {
                item_id: Uuid::from_u128(9),
                ..header.clone()
            },
            ItemHeader {
                blob_id: Uuid::from_u128(9),
                ..header.clone()
            },
            ItemHeader {
                key_id: Uuid::from_u128(9),
                ..header.clone()
            },
            ItemHeader {
                sender_id: Uuid::from_u128(9),
                ..header.clone()
            },
            ItemHeader {
                sent_at: 1,
                ..header.clone()
            },
            ItemHeader {
                blob_size: 1,
                ..header.clone()
            },
        ];
        for changed in variants {
            assert!(open_item(&inbox, VAULT, &changed, &sealed).is_err());
        }
    }

    #[test]
    fn a_signature_verifies_only_for_its_key_and_message() {
        let sender = EcSecret::generate();
        let signature = sender.sign(b"message");
        verify_signature(&sender.public_key(), b"message", &signature).unwrap();
        assert!(verify_signature(&sender.public_key(), b"other", &signature).is_err());
        assert!(
            verify_signature(&EcSecret::generate().public_key(), b"message", &signature).is_err()
        );
        assert!(verify_signature(&sender.public_key(), b"message", &[0u8; 10]).is_err());
    }

    #[test]
    fn a_der_signature_from_a_hardware_key_converts_and_verifies() {
        // What a Keystore hands back: DER, with a leading zero on any
        // integer whose top bit is set, and `s` possibly high.
        let sender = EcSecret::generate();
        let raw = sender.sign(b"message");
        let signature = Signature::from_slice(&raw).unwrap();
        let high = Signature::from_scalars(signature.r().to_bytes(), (-*signature.s()).to_bytes())
            .unwrap();
        for sig in [signature, high] {
            let der = to_der(&sig.to_bytes());
            let back = signature_from_der(&der).unwrap();
            assert_eq!(back, raw, "normalised to the same low-s form");
            verify_signature(&sender.public_key(), b"message", &back).unwrap();
        }
    }

    #[test]
    fn malformed_der_is_refused() {
        for bad in [
            &[][..],
            &[0x30, 0x02, 0x02, 0x00],
            &[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            &[0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00],
        ] {
            assert!(signature_from_der(bad).is_err(), "{bad:?}");
        }
    }

    /// A minimal DER encoder, the shape hardware keystores produce.
    fn to_der(raw: &[u8]) -> Vec<u8> {
        fn int(v: &[u8]) -> Vec<u8> {
            let mut v = v
                .iter()
                .skip_while(|b| **b == 0)
                .copied()
                .collect::<Vec<_>>();
            if v.first().is_none_or(|b| b & 0x80 != 0) {
                v.insert(0, 0);
            }
            let mut out = vec![0x02, v.len() as u8];
            out.extend(v);
            out
        }
        let mut body = int(&raw[..32]);
        body.extend(int(&raw[32..]));
        let mut out = vec![0x30, body.len() as u8];
        out.extend(body);
        out
    }
}
