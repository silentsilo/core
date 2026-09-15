//! CTAP2 spoken directly, for a platform whose own security-key API cannot
//! reproduce the wrap key: Android's Credential Manager offers PRF, which
//! hashes the salt before the key sees it, so a key enrolled on a computer
//! would give the phone a different secret. Here the salt goes to the key
//! as `hmac-secret` receives it everywhere else, unverified, and the output
//! is the same one the desktop derives from.
//!
//! The phone's NFC or USB stack moves the bytes ([`nfc`], [`hid`]); what is
//! said over them is here. Only what a silo needs: the key's info, a PIN
//! token when enrolment requires one, a credential with `hmac-secret`, and
//! an assertion carrying its output.

pub mod hid;
pub mod nfc;

use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use ciborium::Value;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::dek_salt_for_vault;
use crate::types::UnlockMaterial;

/// What every silo credential is scoped to, on every platform.
pub const RP_ID: &str = "silentsilo.com";

const CMD_MAKE_CREDENTIAL: u8 = 0x01;
const CMD_GET_ASSERTION: u8 = 0x02;
const CMD_GET_INFO: u8 = 0x04;
const CMD_CLIENT_PIN: u8 = 0x06;

const PIN_GET_KEY_AGREEMENT: i64 = 0x02;
const PIN_GET_PIN_TOKEN: i64 = 0x05;

/// One command to a key and its CBOR answer, over whatever carries it.
pub trait Ctap {
    /// The authenticator's CBOR after a success status, or the status.
    fn command(&mut self, command: u8, cbor: &[u8]) -> Result<Vec<u8>, CtapError>;
}

#[derive(Debug, thiserror::Error)]
pub enum CtapError {
    /// The link to the key failed: taken away from the phone, unplugged.
    #[error("the security key was disconnected: {0}")]
    Transport(String),
    /// The key answered with something this code does not understand.
    #[error("the security key sent an answer that could not be read: {0}")]
    Protocol(String),
    #[error("this security key cannot open a silo: {0}")]
    Unsupported(String),
    #[error("this security key is not one of the silo's keys")]
    NoCredentials,
    #[error("this security key asks for its PIN")]
    PinRequired,
    #[error("wrong PIN")]
    PinInvalid,
    #[error("the security key's PIN is blocked; it needs a reset or the key's own tool")]
    PinBlocked,
    #[error("no touch was received in time")]
    Timeout,
    #[error("the security key refused (status 0x{0:02x})")]
    Status(u8),
}

impl CtapError {
    fn from_status(status: u8) -> Self {
        match status {
            0x2E => Self::NoCredentials,
            0x31 | 0x33 => Self::PinInvalid,
            0x32 | 0x34 => Self::PinBlocked,
            0x36 => Self::PinRequired,
            0x2F | 0x27 => Self::Timeout,
            other => Self::Status(other),
        }
    }
}

/// Turns a key's status byte and body into the body, or the error.
pub(crate) fn split_status(frame: Vec<u8>) -> Result<Vec<u8>, CtapError> {
    let Some((&status, body)) = frame.split_first() else {
        return Err(CtapError::Protocol("an empty answer".into()));
    };
    if status != 0 {
        return Err(CtapError::from_status(status));
    }
    Ok(body.to_vec())
}

// ── CBOR ────────────────────────────────────────────────────────────

fn int(i: i64) -> Value {
    Value::Integer(i.into())
}

fn text(s: &str) -> Value {
    Value::Text(s.into())
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

/// Entries must already be in CTAP's canonical order: keys do not get
/// sorted here, and a key refuses a map that is out of order.
fn map(entries: Vec<(Value, Value)>) -> Value {
    Value::Map(entries)
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("writing CBOR to memory does not fail");
    out
}

fn decode(raw: &[u8]) -> Result<Value, CtapError> {
    ciborium::from_reader(raw).map_err(|e| CtapError::Protocol(e.to_string()))
}

fn entry<'a>(value: &'a Value, key: &Value) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
}

fn int_entry(value: &Value, key: i64) -> Option<&Value> {
    entry(value, &int(key))
}

/// Bytes one CBOR item takes at the start of `raw`, definite lengths only,
/// which is all CTAP's canonical encoding allows. Needed to find where the
/// credential's public key ends inside authenticator data.
fn item_len(raw: &[u8]) -> Option<usize> {
    let first = *raw.first()?;
    let major = first >> 5;
    let info = first & 0x1f;
    let (arg, head) = match info {
        0..=23 => (info as u64, 1),
        24 => (*raw.get(1)? as u64, 2),
        25 => (
            u16::from_be_bytes(raw.get(1..3)?.try_into().ok()?) as u64,
            3,
        ),
        26 => (
            u32::from_be_bytes(raw.get(1..5)?.try_into().ok()?) as u64,
            5,
        ),
        27 => (u64::from_be_bytes(raw.get(1..9)?.try_into().ok()?), 9),
        _ => return None,
    };
    match major {
        0 | 1 | 7 => Some(head),
        2 | 3 => head
            .checked_add(usize::try_from(arg).ok()?)
            .filter(|&n| n <= raw.len()),
        4 | 5 => {
            let items = if major == 5 { arg.checked_mul(2)? } else { arg };
            let mut at = head;
            for _ in 0..items {
                at += item_len(raw.get(at..)?)?;
            }
            Some(at)
        }
        6 => Some(head + item_len(raw.get(head..)?)?),
        _ => None,
    }
}

// ── The shared secret of a PIN/UV auth protocol ─────────────────────

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rng().fill_bytes(&mut out);
    out
}

/// A fresh P-256 key; see `enclave::random_secret` for why not `random`.
fn random_secret() -> SecretKey {
    loop {
        let bytes = Zeroizing::new(random_bytes::<32>());
        if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
            return secret;
        }
    }
}

fn cose_public(key: &PublicKey) -> Value {
    let point = key.to_sec1_bytes();
    // Uncompressed: 0x04, x, y.
    map(vec![
        (int(1), int(2)),
        (int(3), int(-25)),
        (int(-1), int(1)),
        (int(-2), bytes(&point[1..33])),
        (int(-3), bytes(&point[33..65])),
    ])
}

fn public_from_cose(cose: &Value) -> Result<PublicKey, CtapError> {
    let coordinate = |label: i64| {
        int_entry(cose, label)
            .and_then(Value::as_bytes)
            .filter(|b| b.len() == 32)
            .ok_or_else(|| CtapError::Protocol("a public key that is not P-256".into()))
    };
    let mut point = vec![0x04];
    point.extend_from_slice(coordinate(-2)?);
    point.extend_from_slice(coordinate(-3)?);
    PublicKey::from_sec1_bytes(&point)
        .map_err(|_| CtapError::Protocol("a public key that is not on the curve".into()))
}

/// What one run of a PIN/UV auth protocol agreed on with the key.
struct Shared {
    protocol: u8,
    platform_key: Value,
    hmac_key: Zeroizing<[u8; 32]>,
    aes_key: Zeroizing<[u8; 32]>,
}

impl Shared {
    fn agree(dev: &mut dyn Ctap, protocol: u8) -> Result<Self, CtapError> {
        let request = map(vec![
            (int(1), int(protocol as i64)),
            (int(2), int(PIN_GET_KEY_AGREEMENT)),
        ]);
        let answer = decode(&dev.command(CMD_CLIENT_PIN, &encode(&request))?)?;
        let theirs = public_from_cose(
            int_entry(&answer, 1).ok_or_else(|| CtapError::Protocol("no key agreement".into()))?,
        )?;
        let ours = random_secret();
        let z = diffie_hellman(ours.to_nonzero_scalar(), theirs.as_affine());
        let z = z.raw_secret_bytes();
        let (hmac_key, aes_key) = if protocol == 1 {
            let key = Zeroizing::new(sha256(z));
            (key.clone(), key)
        } else {
            let derive = |info: &[u8]| {
                let mut out = Zeroizing::new([0u8; 32]);
                Hkdf::<Sha256>::new(Some(&[0u8; 32]), z)
                    .expand(info, out.as_mut())
                    .expect("32 bytes is within HKDF-SHA256's output limit");
                out
            };
            (derive(b"CTAP2 HMAC key"), derive(b"CTAP2 AES key"))
        };
        Ok(Self {
            protocol,
            platform_key: cose_public(&ours.public_key()),
            hmac_key,
            aes_key,
        })
    }

    fn encrypt(&self, plain: &[u8]) -> Vec<u8> {
        let iv = if self.protocol == 1 {
            [0u8; 16]
        } else {
            random_bytes::<16>()
        };
        let mut buf = plain.to_vec();
        let len = buf.len();
        cbc::Encryptor::<Aes256>::new(self.aes_key.as_ref().into(), &iv.into())
            .encrypt_padded_mut::<NoPadding>(&mut buf, len)
            .expect("inputs here are whole blocks");
        if self.protocol == 1 {
            buf
        } else {
            [iv.as_slice(), &buf].concat()
        }
    }

    fn decrypt(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, CtapError> {
        let (iv, body) = if self.protocol == 1 {
            ([0u8; 16], data)
        } else {
            let (iv, body) = data
                .split_at_checked(16)
                .ok_or_else(|| CtapError::Protocol("ciphertext too short".into()))?;
            (iv.try_into().expect("16 bytes"), body)
        };
        if body.is_empty() || body.len() % 16 != 0 {
            return Err(CtapError::Protocol("ciphertext not in whole blocks".into()));
        }
        let mut buf = Zeroizing::new(body.to_vec());
        cbc::Decryptor::<Aes256>::new(self.aes_key.as_ref().into(), &iv.into())
            .decrypt_padded_mut::<NoPadding>(buf.as_mut())
            .map_err(|_| CtapError::Protocol("ciphertext could not be decrypted".into()))?;
        Ok(buf)
    }

    /// Protocol one truncates to 16 bytes, two keeps all 32.
    fn authenticate(&self, key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
        mac.update(message);
        let full = mac.finalize().into_bytes();
        if self.protocol == 1 {
            full[..16].to_vec()
        } else {
            full.to_vec()
        }
    }
}

// ── Commands ────────────────────────────────────────────────────────

/// The parts of `authenticatorGetInfo` a silo cares about.
#[derive(Debug, Default)]
pub struct Info {
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub pin_protocols: Vec<u8>,
    /// `clientPin`: a PIN is set.
    pub pin_set: bool,
    /// Largest allow-list the key takes at once.
    pub max_credentials_in_list: usize,
    /// Longest credential id the key takes.
    pub max_credential_id_length: Option<usize>,
}

impl Info {
    pub fn hmac_secret(&self) -> bool {
        self.extensions.iter().any(|e| e == "hmac-secret")
    }

    /// The first protocol the key lists that this code speaks. A key that
    /// lists none predates the field and speaks one.
    fn protocol(&self) -> Result<u8, CtapError> {
        if self.pin_protocols.is_empty() {
            return Ok(1);
        }
        self.pin_protocols
            .iter()
            .copied()
            .find(|p| *p == 1 || *p == 2)
            .ok_or_else(|| CtapError::Unsupported("no PIN protocol in common".into()))
    }
}

pub fn get_info(dev: &mut dyn Ctap) -> Result<Info, CtapError> {
    let answer = decode(&dev.command(CMD_GET_INFO, &[])?)?;
    let strings = |key: i64| -> Vec<String> {
        int_entry(&answer, key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_text().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let option = |name: &str| {
        int_entry(&answer, 4)
            .and_then(|options| entry(options, &text(name)))
            .and_then(Value::as_bool)
    };
    let pin_protocols = int_entry(&answer, 6)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_integer().and_then(|i| u8::try_from(i).ok()))
                .collect()
        })
        .unwrap_or_default();
    let max_credentials_in_list = int_entry(&answer, 7)
        .and_then(Value::as_integer)
        .and_then(|i| usize::try_from(i).ok())
        .filter(|n| *n > 0)
        .unwrap_or(1);
    let max_credential_id_length = int_entry(&answer, 8)
        .and_then(Value::as_integer)
        .and_then(|i| usize::try_from(i).ok());
    Ok(Info {
        versions: strings(1),
        extensions: strings(2),
        pin_protocols,
        pin_set: option("clientPin") == Some(true),
        max_credentials_in_list,
        max_credential_id_length,
    })
}

/// The salt every platform feeds `hmac-secret` for this silo.
fn silo_salt(vault_id: &str) -> [u8; 32] {
    sha256(dek_salt_for_vault(vault_id).as_bytes())
}

/// What was given to `hmac-secret` as the salt when the silo was wrapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaltShape {
    /// SHA-256 of `silentsilo-dek-v1:{vault_id}`, as CTAP receives it.
    Raw,
    /// The same bytes as a WebAuthn PRF input, which a platform hashes again
    /// before the key sees them.
    Prf,
}

/// Wrap keys one assertion produced, one per salt shape, for the caller to
/// try against the silo's envelope.
pub struct UnlockCandidates {
    pub credential_id: Vec<u8>,
    /// Asserted with the PIN, which reaches the key's other secret.
    pub verified: bool,
    /// The key has a PIN, so a verified assertion is possible.
    pub pin_set: bool,
    pub wrap_keys: Vec<(SaltShape, Zeroizing<[u8; 32]>)>,
}

/// Touch or tap: the raw-salt, unverified wrap key of whichever of
/// `credential_ids` the key holds.
pub fn derive_unlock_material(
    dev: &mut dyn Ctap,
    credential_ids: &[Vec<u8>],
    vault_id: &str,
) -> Result<UnlockMaterial, CtapError> {
    let found = unlock_candidates(dev, credential_ids, vault_id, None)?;
    let (_, key) = found
        .wrap_keys
        .iter()
        .find(|(shape, _)| *shape == SaltShape::Raw)
        .ok_or_else(|| CtapError::Protocol("no raw hmac-secret output".into()))?;
    Ok(UnlockMaterial {
        wrap_key: **key,
        credential_id: found.credential_id,
    })
}

/// One assertion asking `hmac-secret` for both salt shapes at once.
///
/// `hmac-secret` keeps two secrets per credential, one for assertions with
/// user verification and one without, so a silo wrapped where the platform
/// verified (a computer that asked for the key's PIN) opens only with `pin`
/// given here too. Which shape and which secret the silo was wrapped under
/// is found by trying the candidates against its envelope.
pub fn unlock_candidates(
    dev: &mut dyn Ctap,
    credential_ids: &[Vec<u8>],
    vault_id: &str,
    pin: Option<&str>,
) -> Result<UnlockCandidates, CtapError> {
    if credential_ids.is_empty() {
        return Err(CtapError::NoCredentials);
    }
    let info = get_info(dev)?;
    if !info.hmac_secret() {
        return Err(CtapError::Unsupported("it has no hmac-secret".into()));
    }
    let protocol = info.protocol()?;
    let raw = silo_salt(vault_id);
    let prf = sha256(&[b"WebAuthn PRF\x00".as_slice(), &raw].concat());
    let salts = [raw.as_slice(), &prf].concat();
    // An id longer than the key takes cannot be one of its own.
    let fitting: Vec<Vec<u8>> = credential_ids
        .iter()
        .filter(|id| {
            info.max_credential_id_length
                .is_none_or(|max| id.len() <= max)
        })
        .cloned()
        .collect();
    let token = match pin {
        Some(pin) => Some(pin_token(dev, protocol, pin)?),
        None => None,
    };

    for batch in fitting.chunks(info.max_credentials_in_list) {
        let shared = Shared::agree(dev, protocol)?;
        let salt_enc = shared.encrypt(&salts);
        let salt_auth = shared.authenticate(shared.hmac_key.as_ref(), &salt_enc);
        let mut hmac_secret = vec![
            (int(1), shared.platform_key.clone()),
            (int(2), bytes(&salt_enc)),
            (int(3), bytes(&salt_auth)),
        ];
        if protocol != 1 {
            hmac_secret.push((int(4), int(protocol as i64)));
        }
        let allow = batch
            .iter()
            .map(|id| {
                map(vec![
                    (text("id"), bytes(id)),
                    (text("type"), text("public-key")),
                ])
            })
            .collect();
        let client_data_hash = sha256(&random_bytes::<32>());
        let mut request = vec![
            (int(1), text(RP_ID)),
            (int(2), bytes(&client_data_hash)),
            (int(3), Value::Array(allow)),
            (int(4), map(vec![(text("hmac-secret"), map(hmac_secret))])),
            (int(5), map(vec![(text("up"), Value::Bool(true))])),
        ];
        if let Some((token_run, token)) = &token {
            request.push((
                int(6),
                bytes(&token_run.authenticate(token, &client_data_hash)),
            ));
            request.push((int(7), int(protocol as i64)));
        }
        let answer = match dev.command(CMD_GET_ASSERTION, &encode(&map(request))) {
            Err(CtapError::NoCredentials) => continue,
            Err(e) => return Err(e),
            Ok(answer) => decode(&answer)?,
        };

        // The key may leave the credential out when the list named one.
        let credential_id = int_entry(&answer, 1)
            .and_then(|c| entry(c, &text("id")))
            .and_then(Value::as_bytes)
            .cloned()
            .or_else(|| (batch.len() == 1).then(|| batch[0].clone()))
            .ok_or_else(|| CtapError::Protocol("no credential in the assertion".into()))?;
        let auth_data = int_entry(&answer, 2)
            .and_then(Value::as_bytes)
            .ok_or_else(|| CtapError::Protocol("no authenticator data".into()))?;
        let missing =
            || CtapError::Unsupported("the key returned no hmac-secret for this credential".into());
        let extensions = parse_auth_data(auth_data)?.extensions.ok_or_else(missing)?;
        let sealed = entry(&extensions, &text("hmac-secret"))
            .and_then(Value::as_bytes)
            .ok_or_else(missing)?;
        let output = shared.decrypt(sealed)?;
        if output.len() < 64 {
            return Err(CtapError::Protocol("hmac-secret output too short".into()));
        }
        let wrap = |part: &[u8]| Zeroizing::new(*blake3::hash(part).as_bytes());
        return Ok(UnlockCandidates {
            credential_id,
            verified: token.is_some(),
            pin_set: info.pin_set,
            wrap_keys: vec![
                (SaltShape::Raw, wrap(&output[..32])),
                (SaltShape::Prf, wrap(&output[32..64])),
            ],
        });
    }
    Err(CtapError::NoCredentials)
}

/// A PIN token, and the protocol run that authenticates with it.
fn pin_token(
    dev: &mut dyn Ctap,
    protocol: u8,
    pin: &str,
) -> Result<(Shared, Zeroizing<Vec<u8>>), CtapError> {
    let shared = Shared::agree(dev, protocol)?;
    let pin_hash = sha256(pin.as_bytes());
    let request = map(vec![
        (int(1), int(protocol as i64)),
        (int(2), int(PIN_GET_PIN_TOKEN)),
        (int(3), shared.platform_key.clone()),
        (int(6), bytes(&shared.encrypt(&pin_hash[..16]))),
    ]);
    let answer = decode(&dev.command(CMD_CLIENT_PIN, &encode(&request))?)?;
    let sealed = int_entry(&answer, 2)
        .and_then(Value::as_bytes)
        .ok_or_else(|| CtapError::Protocol("no PIN token".into()))?;
    let token = shared.decrypt(sealed)?;
    Ok((shared, token))
}

/// A credential made for a silo.
#[derive(Debug, Clone)]
pub struct NewCredential {
    pub credential_id: Vec<u8>,
    /// SubjectPublicKeyInfo DER, as the desktop records it.
    pub public_key: Vec<u8>,
}

/// Makes a credential with `hmac-secret` for the silo. A key with a PIN
/// needs it: Windows verifies every ceremony on such a key, so the wrap key
/// must come from a verified assertion too, or the computer could not open
/// what the phone enrolled.
pub fn make_credential(
    dev: &mut dyn Ctap,
    vault_id: &str,
    pin: Option<&str>,
) -> Result<NewCredential, CtapError> {
    let info = get_info(dev)?;
    if !info.hmac_secret() {
        return Err(CtapError::Unsupported("it has no hmac-secret".into()));
    }
    if info.pin_set && pin.is_none() {
        return Err(CtapError::PinRequired);
    }
    let protocol = info.protocol()?;
    let client_data_hash = sha256(&random_bytes::<32>());

    let pin_auth = match pin {
        Some(pin) => {
            let (shared, token) = pin_token(dev, protocol, pin)?;
            Some(shared.authenticate(&token, &client_data_hash))
        }
        None => None,
    };

    // The same generic names the desktop sends: the silo's own name would
    // tell whoever reads the key what is on it.
    let mut request = vec![
        (int(1), bytes(&client_data_hash)),
        (
            int(2),
            map(vec![(text("id"), text(RP_ID)), (text("name"), text(RP_ID))]),
        ),
        (
            int(3),
            map(vec![
                (text("id"), bytes(vault_id.as_bytes())),
                (text("name"), text("silo")),
                (text("displayName"), text("SilentSilo")),
            ]),
        ),
        (
            int(4),
            Value::Array(vec![map(vec![
                (text("alg"), int(-7)),
                (text("type"), text("public-key")),
            ])]),
        ),
        (int(6), map(vec![(text("hmac-secret"), Value::Bool(true))])),
        (int(7), map(vec![(text("rk"), Value::Bool(false))])),
    ];
    if let Some(auth) = pin_auth {
        request.push((int(8), bytes(&auth)));
        request.push((int(9), int(protocol as i64)));
    }
    let answer = decode(&dev.command(CMD_MAKE_CREDENTIAL, &encode(&map(request)))?)?;
    let auth_data = int_entry(&answer, 2)
        .and_then(Value::as_bytes)
        .ok_or_else(|| CtapError::Protocol("no authenticator data".into()))?;
    let parsed = parse_auth_data(auth_data)?;
    let (credential_id, cose) = parsed
        .credential
        .ok_or_else(|| CtapError::Protocol("no credential in the attestation".into()))?;
    let enabled = parsed
        .extensions
        .as_ref()
        .and_then(|e| entry(e, &text("hmac-secret")))
        .and_then(Value::as_bool)
        == Some(true);
    if !enabled {
        return Err(CtapError::Unsupported(
            "it did not enable hmac-secret for the credential".into(),
        ));
    }
    let point = public_from_cose(&cose)?.to_sec1_bytes();
    Ok(NewCredential {
        credential_id,
        public_key: [P256_SPKI_PREFIX.as_slice(), &point].concat(),
    })
}

/// DER of a P-256 SubjectPublicKeyInfo up to the uncompressed point.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

struct AuthData {
    credential: Option<(Vec<u8>, Value)>,
    extensions: Option<Value>,
}

/// rpIdHash (32), flags (1), counter (4), then the attested credential when
/// flag AT is set and the extensions when ED is.
fn parse_auth_data(raw: &[u8]) -> Result<AuthData, CtapError> {
    let short = || CtapError::Protocol("authenticator data too short".into());
    let flags = *raw.get(32).ok_or_else(short)?;
    let mut at = 37;
    let mut credential = None;
    if flags & 0x40 != 0 {
        // aaguid (16), id length (2), id, public key.
        let len_bytes: [u8; 2] = raw
            .get(at + 16..at + 18)
            .ok_or_else(short)?
            .try_into()
            .unwrap();
        let id_len = u16::from_be_bytes(len_bytes) as usize;
        at += 18;
        let id = raw.get(at..at + id_len).ok_or_else(short)?.to_vec();
        at += id_len;
        let key_len = item_len(raw.get(at..).ok_or_else(short)?).ok_or_else(short)?;
        let key = decode(&raw[at..at + key_len])?;
        at += key_len;
        credential = Some((id, key));
    }
    let extensions = if flags & 0x80 != 0 {
        let rest = raw.get(at..).ok_or_else(short)?;
        let len = item_len(rest).ok_or_else(short)?;
        Some(decode(&rest[..len])?)
    } else {
        None
    };
    Ok(AuthData {
        credential,
        extensions,
    })
}

#[cfg(test)]
mod soft_key;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_lengths_cover_what_authenticator_data_holds() {
        let key = cose_public(&random_secret().public_key());
        let raw = encode(&key);
        let mut padded = raw.clone();
        padded.extend_from_slice(&[0xa1, 0x01, 0x02]);
        assert_eq!(item_len(&padded), Some(raw.len()));
        assert_eq!(item_len(&[0x58]), None, "a truncated item is not measured");
    }

    #[test]
    fn both_protocols_round_trip_whole_blocks() {
        for protocol in [1u8, 2] {
            let shared = Shared {
                protocol,
                platform_key: Value::Null,
                hmac_key: Zeroizing::new([1; 32]),
                aes_key: Zeroizing::new([2; 32]),
            };
            let sealed = shared.encrypt(&[7u8; 32]);
            assert_eq!(sealed.len(), if protocol == 1 { 32 } else { 48 });
            assert_eq!(shared.decrypt(&sealed).unwrap().as_slice(), &[7u8; 32]);
            assert_eq!(
                shared.authenticate(&[3; 32], b"m").len(),
                if protocol == 1 { 16 } else { 32 }
            );
        }
    }
}
