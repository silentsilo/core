//! One event, sealed to the log's public key.
//!
//! Sealed on its own the moment it happens, with HPKE (RFC 9180): the device
//! that writes it holds only the public key, so on an organisation's silo it
//! cannot read back what it wrote, and nothing it queues is readable on its
//! disk. The suite is written into every record, so a later version can move
//! to another (a post-quantum KEM) and still read these.

use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{AuditError, Event};

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = AesGcm256;

/// The suite this build writes: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
/// AES-256-GCM, by their RFC 9180 identifiers.
pub const SUITE: [u16; 3] = [0x0020, 0x0001, 0x0002];

const RECORD_MAGIC: &[u8; 4] = b"SSAR";
const RECORD_VERSION: u8 = 1;
const INFO: &[u8] = b"silentsilo audit v1";

/// The largest event a record holds. Events are ids and short labels.
pub const MAX_EVENT_BYTES: usize = 16 * 1024;

/// Which key a record was sealed to: the first eight bytes of the BLAKE3 of
/// its public key.
pub type KeyId = [u8; 8];

pub fn key_id(public_key: &[u8]) -> KeyId {
    let hash = blake3::hash(public_key);
    let mut id = [0u8; 8];
    id.copy_from_slice(&hash.as_bytes()[..8]);
    id
}

/// A key pair for a log. The private half never leaves the holder of the
/// log, wrapped (`keyring`); devices get the public half only.
pub struct KeyPair {
    pub public: Vec<u8>,
    pub private: Zeroizing<Vec<u8>>,
}

impl KeyPair {
    pub fn generate() -> Self {
        let (private, public) = Kem::gen_keypair();
        Self {
            public: public.to_bytes().to_vec(),
            private: Zeroizing::new(private.to_bytes().to_vec()),
        }
    }

    pub fn id(&self) -> KeyId {
        key_id(&self.public)
    }
}

/// What the record is bound to besides its plaintext: the device that wrote
/// it and the key it was sealed to. A record moved under another device's
/// name does not open.
fn aad(device: Uuid, key: &KeyId) -> Vec<u8> {
    let mut out = b"silentsilo-audit-record-v1".to_vec();
    out.extend_from_slice(device.as_bytes());
    out.extend_from_slice(key);
    out
}

/// Seals `event` to `public_key` as written by `device`.
pub fn seal_event(public_key: &[u8], device: Uuid, event: &Event) -> Result<Vec<u8>, AuditError> {
    let plain = Zeroizing::new(serde_json::to_vec(event)?);
    if plain.len() > MAX_EVENT_BYTES {
        return Err(AuditError::TooLarge("event"));
    }
    let recipient =
        <Kem as hpke::Kem>::PublicKey::from_bytes(public_key).map_err(|_| AuditError::BadKey)?;
    let id = key_id(public_key);
    let (enc, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &recipient,
        INFO,
        &plain,
        &aad(device, &id),
    )
    .map_err(|_| AuditError::Crypto)?;
    let enc = enc.to_bytes();

    let mut out = Vec::with_capacity(4 + 1 + 6 + 8 + 2 + enc.len() + 4 + ciphertext.len());
    out.extend_from_slice(RECORD_MAGIC);
    out.push(RECORD_VERSION);
    for id in SUITE {
        out.extend_from_slice(&id.to_be_bytes());
    }
    out.extend_from_slice(&id);
    out.extend_from_slice(&(enc.len() as u16).to_be_bytes());
    out.extend_from_slice(&enc);
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// The key a record names, read without opening it.
pub fn record_key(record: &[u8]) -> Result<KeyId, AuditError> {
    Ok(parse(record)?.key)
}

struct Parsed<'a> {
    suite: [u16; 3],
    key: KeyId,
    enc: &'a [u8],
    ciphertext: &'a [u8],
}

fn parse(record: &[u8]) -> Result<Parsed<'_>, AuditError> {
    let mut r = crate::Reader::new(record);
    if r.take(4)? != RECORD_MAGIC {
        return Err(AuditError::Malformed("not an audit record"));
    }
    if r.u8()? != RECORD_VERSION {
        return Err(AuditError::Newer("record"));
    }
    let suite = [r.u16()?, r.u16()?, r.u16()?];
    let mut key = [0u8; 8];
    key.copy_from_slice(r.take(8)?);
    let enc_len = r.u16()? as usize;
    let enc = r.take(enc_len)?;
    let ct_len = r.u32()? as usize;
    if ct_len > MAX_EVENT_BYTES + 64 {
        return Err(AuditError::TooLarge("record"));
    }
    let ciphertext = r.take(ct_len)?;
    r.end()?;
    Ok(Parsed {
        suite,
        key,
        enc,
        ciphertext,
    })
}

/// Opens a record written by `device` with the log's private key.
pub fn open_event(private_key: &[u8], device: Uuid, record: &[u8]) -> Result<Event, AuditError> {
    let parsed = parse(record)?;
    if parsed.suite != SUITE {
        return Err(AuditError::Newer("cipher suite"));
    }
    let private =
        <Kem as hpke::Kem>::PrivateKey::from_bytes(private_key).map_err(|_| AuditError::BadKey)?;
    let enc =
        <Kem as hpke::Kem>::EncappedKey::from_bytes(parsed.enc).map_err(|_| AuditError::Crypto)?;
    let plain = Zeroizing::new(
        hpke::single_shot_open::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &private,
            &enc,
            INFO,
            parsed.ciphertext,
            &aad(device, &parsed.key),
        )
        .map_err(|_| AuditError::Crypto)?,
    );
    Ok(serde_json::from_slice(&plain)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codes;

    #[test]
    fn a_sealed_event_opens_with_the_private_key_only() {
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let event = Event::new(codes::SECRET_COPIED, 42).on("e1", "Bank");
        let record = seal_event(&keys.public, device, &event).unwrap();

        assert_eq!(record_key(&record).unwrap(), keys.id());
        assert_eq!(open_event(&keys.private, device, &record).unwrap(), event);

        let other = KeyPair::generate();
        assert!(open_event(&other.private, device, &record).is_err());
    }

    #[test]
    fn a_record_moved_under_another_device_does_not_open() {
        let keys = KeyPair::generate();
        let record = seal_event(&keys.public, Uuid::new_v4(), &Event::new(1, 1)).unwrap();
        assert!(matches!(
            open_event(&keys.private, Uuid::new_v4(), &record),
            Err(AuditError::Crypto)
        ));
    }

    #[test]
    fn a_changed_byte_does_not_open() {
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let mut record = seal_event(&keys.public, device, &Event::new(1, 1)).unwrap();
        let last = record.len() - 1;
        record[last] ^= 1;
        assert!(open_event(&keys.private, device, &record).is_err());
    }

    #[test]
    fn a_later_suite_is_named_not_misread() {
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let mut record = seal_event(&keys.public, device, &Event::new(1, 1)).unwrap();
        // The KEM id, just after the magic and the version.
        record[5] = 0x64;
        assert!(matches!(
            open_event(&keys.private, device, &record),
            Err(AuditError::Newer(_))
        ));
    }
}
