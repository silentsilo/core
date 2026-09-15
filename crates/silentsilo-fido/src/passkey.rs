//! Passkeys kept in a silo: the authenticator half of WebAuthn, for a phone
//! that answers passkey requests from its own password manager.
//!
//! A passkey is a P-256 key made here and stored inside a password entry
//! (the `passkey` field, see `FORMATS.md`), so it syncs, backs up and is
//! recovered the way the entry is. Inside the entry rather than as an
//! operation of its own because clients that do not know passkeys keep a
//! field they do not know, while their compaction drops records they do not
//! know.
//!
//! What goes in and out is the WebAuthn JSON the platform hands a provider:
//! creation and request options in, registration and authentication
//! responses out. The signature counter stays 0, as synced passkeys do: a
//! counter would turn every sign-in into a write that conflicts across
//! devices.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ciborium::Value;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::{PublicKey, SecretKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The version of the `passkey` field. A reader offers only passkeys of a
/// version it knows, and leaves the others where they are.
pub const PASSKEY_VERSION: u32 = 1;

/// COSE ES256, the only algorithm made here.
const ES256: i64 = -7;

/// Names this provider in attestation data. Random, fixed, and not
/// registered anywhere: attestation is "none", so nothing checks it.
const AAGUID: [u8; 16] = [
    0x5c, 0x1e, 0x7a, 0x3d, 0x9b, 0x42, 0x4f, 0x61, 0xa8, 0x0d, 0x2e, 0x93, 0x57, 0xc4, 0x11, 0xf6,
];

/// User present, user verified, backup eligible, backed up.
const FLAGS_ASSERT: u8 = 0x01 | 0x04 | 0x08 | 0x10;
/// The same plus attested credential data.
const FLAGS_CREATE: u8 = FLAGS_ASSERT | 0x40;

/// The `passkey` field of a password entry.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasskeyRecord {
    pub version: u32,
    pub rp_id: String,
    /// Base64url, no padding.
    pub credential_id: String,
    /// The relying party's user id, base64url.
    pub user_handle: String,
    pub user_name: String,
    #[serde(default)]
    pub user_display_name: String,
    pub algorithm: i64,
    /// The P-256 private scalar, base64url. Sealed with the silo like a
    /// password; never leaves this crate except inside the entry.
    pub private_key: String,
    /// Unix milliseconds.
    pub created_at: i64,
}

impl std::fmt::Debug for PasskeyRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyRecord")
            .field("rp_id", &self.rp_id)
            .field("credential_id", &self.credential_id)
            .field("user_name", &self.user_name)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PasskeyError {
    #[error("the request could not be read: {0}")]
    Invalid(String),
    #[error("this site asks for a key type SilentSilo does not make")]
    Unsupported,
    #[error("the site {origin} may not use passkeys for {rp_id}")]
    WrongOrigin { origin: String, rp_id: String },
    #[error("a passkey for this account is already in the silo")]
    Excluded,
}

/// Who is asking, as the platform vouches for it.
pub struct Caller<'a> {
    /// `https://site` for a browser the platform trusts, or
    /// `android:apk-key-hash:...` for an app.
    pub origin: &'a str,
    /// An app's package name, added to client data as Android does.
    pub package: Option<&'a str>,
    /// A browser computes client data itself and passes only its hash.
    pub client_data_hash: Option<[u8; 32]>,
}

/// A passkey made for a site, and the response the site receives.
pub struct Registration {
    pub record: PasskeyRecord,
    pub response_json: String,
    /// For the entry around the passkey.
    pub rp_name: String,
}

#[derive(Deserialize)]
struct CreationOptions {
    rp: Rp,
    user: User,
    challenge: String,
    #[serde(rename = "pubKeyCredParams", default)]
    params: Vec<Param>,
    #[serde(rename = "excludeCredentials", default)]
    exclude: Vec<Descriptor>,
}

#[derive(Deserialize)]
struct Rp {
    id: Option<String>,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct User {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(rename = "displayName", default)]
    display_name: String,
}

#[derive(Deserialize)]
struct Param {
    #[serde(rename = "type")]
    kind: String,
    alg: i64,
}

#[derive(Deserialize)]
struct Descriptor {
    id: String,
}

#[derive(Deserialize)]
struct RequestOptions {
    challenge: String,
    #[serde(rename = "rpId")]
    rp_id: Option<String>,
    #[serde(rename = "allowCredentials", default)]
    allow: Vec<Descriptor>,
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn decode_b64(raw: &str, what: &str) -> Result<Vec<u8>, PasskeyError> {
    B64.decode(raw.trim_end_matches('='))
        .map_err(|_| PasskeyError::Invalid(format!("{what} is not base64url")))
}

/// The host of an https origin.
fn origin_host(origin: &str) -> Option<&str> {
    let rest = origin.strip_prefix("https://")?;
    let host = rest.split(['/', ':']).next()?;
    (!host.is_empty()).then_some(host)
}

/// A browser origin must be the relying party's domain or below it. An app
/// origin names the app's signing key, which the relying party checks
/// against its own list, so it passes here.
fn check_origin(origin: &str, rp_id: &str) -> Result<(), PasskeyError> {
    if origin.starts_with("android:apk-key-hash:") {
        return Ok(());
    }
    let wrong = || PasskeyError::WrongOrigin {
        origin: origin.to_string(),
        rp_id: rp_id.to_string(),
    };
    let host = origin_host(origin).ok_or_else(wrong)?.to_ascii_lowercase();
    let rp = rp_id.to_ascii_lowercase();
    if host == rp || host.ends_with(&format!(".{rp}")) {
        Ok(())
    } else {
        Err(wrong())
    }
}

/// The client data to sign over, and its JSON when this side built it.
fn client_data(
    kind: &str,
    challenge: &str,
    caller: &Caller<'_>,
) -> Result<([u8; 32], Option<String>), PasskeyError> {
    if let Some(hash) = caller.client_data_hash {
        return Ok((hash, None));
    }
    decode_b64(challenge, "the challenge")?;
    let mut data = json!({
        "type": kind,
        "challenge": challenge.trim_end_matches('='),
        "origin": caller.origin,
        "crossOrigin": false,
    });
    if let Some(package) = caller.package {
        data["androidPackageName"] = package.into();
    }
    let text = data.to_string();
    Ok((sha256(text.as_bytes()), Some(text)))
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rng().fill_bytes(&mut out);
    out
}

fn random_secret() -> SecretKey {
    loop {
        let bytes = Zeroizing::new(random_bytes::<32>());
        if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
            return secret;
        }
    }
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("writing CBOR to memory does not fail");
    out
}

fn cose_key(public: &PublicKey) -> Vec<u8> {
    let point = public.to_sec1_bytes();
    let int = |i: i64| Value::Integer(i.into());
    encode(&Value::Map(vec![
        (int(1), int(2)),
        (int(3), int(ES256)),
        (int(-1), int(1)),
        (int(-2), Value::Bytes(point[1..33].to_vec())),
        (int(-3), Value::Bytes(point[33..65].to_vec())),
    ]))
}

const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// An ECDSA signature as DER, which WebAuthn expects for ES256.
fn der(signature: &Signature) -> Vec<u8> {
    fn integer(bytes: &[u8]) -> Vec<u8> {
        let trimmed: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
        let mut body = if trimmed.is_empty() { vec![0] } else { trimmed };
        if body[0] & 0x80 != 0 {
            body.insert(0, 0);
        }
        [vec![0x02, body.len() as u8], body].concat()
    }
    let (r, s) = signature.split_bytes();
    let body = [integer(&r), integer(&s)].concat();
    [vec![0x30, body.len() as u8], body].concat()
}

fn signing_key(record: &PasskeyRecord) -> Result<SigningKey, PasskeyError> {
    let raw = Zeroizing::new(decode_b64(&record.private_key, "the private key")?);
    let secret = SecretKey::from_slice(&raw)
        .map_err(|_| PasskeyError::Invalid("the private key is not a P-256 key".into()))?;
    Ok(SigningKey::from(secret))
}

/// Makes a passkey for `options_json` (WebAuthn creation options). `existing`
/// holds the silo's passkeys, for the site's exclude list.
pub fn register(
    options_json: &str,
    caller: &Caller<'_>,
    existing: &[PasskeyRecord],
    now_ms: i64,
) -> Result<Registration, PasskeyError> {
    let options: CreationOptions =
        serde_json::from_str(options_json).map_err(|e| PasskeyError::Invalid(e.to_string()))?;
    let rp_id = match options.rp.id {
        Some(id) if !id.is_empty() => id,
        _ => origin_host(caller.origin)
            .ok_or_else(|| PasskeyError::Invalid("no relying party id".into()))?
            .to_string(),
    };
    check_origin(caller.origin, &rp_id)?;
    if !options.params.is_empty()
        && !options
            .params
            .iter()
            .any(|p| p.kind == "public-key" && p.alg == ES256)
    {
        return Err(PasskeyError::Unsupported);
    }
    let user_handle = decode_b64(&options.user.id, "the user id")?;
    let held: Vec<&str> = existing
        .iter()
        .filter(|r| r.rp_id == rp_id)
        .map(|r| r.credential_id.as_str())
        .collect();
    if options
        .exclude
        .iter()
        .any(|d| held.contains(&d.id.trim_end_matches('=')))
    {
        return Err(PasskeyError::Excluded);
    }

    // Attestation is "none", so creation signs nothing with the client data.
    let (_, client_json) = client_data("webauthn.create", &options.challenge, caller)?;
    let secret = random_secret();
    let public = secret.public_key();
    let credential_id = random_bytes::<32>();

    let mut auth_data = sha256(rp_id.as_bytes()).to_vec();
    auth_data.push(FLAGS_CREATE);
    auth_data.extend_from_slice(&[0, 0, 0, 0]);
    auth_data.extend_from_slice(&AAGUID);
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(&credential_id);
    auth_data.extend_from_slice(&cose_key(&public));
    let text = |s: &str| Value::Text(s.into());
    let attestation = encode(&Value::Map(vec![
        (text("fmt"), text("none")),
        (text("attStmt"), Value::Map(vec![])),
        (text("authData"), Value::Bytes(auth_data.clone())),
    ]));

    let id = B64.encode(credential_id);
    let spki = [P256_SPKI_PREFIX.as_slice(), &public.to_sec1_bytes()].concat();
    let mut response = json!({
        "attestationObject": B64.encode(&attestation),
        "authenticatorData": B64.encode(&auth_data),
        "transports": ["internal", "hybrid"],
        "publicKey": B64.encode(&spki),
        "publicKeyAlgorithm": ES256,
    });
    if let Some(text) = client_json {
        response["clientDataJSON"] = B64.encode(text).into();
    }
    let response_json = json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": response,
        "clientExtensionResults": { "credProps": { "rk": true } },
    })
    .to_string();

    let record = PasskeyRecord {
        version: PASSKEY_VERSION,
        rp_id,
        credential_id: id,
        user_handle: B64.encode(user_handle),
        user_name: options.user.name,
        user_display_name: options.user.display_name,
        algorithm: ES256,
        private_key: B64.encode(secret.to_bytes()),
        created_at: now_ms,
    };
    Ok(Registration {
        record,
        response_json,
        rp_name: options.rp.name,
    })
}

/// The relying party a request names, falling back to the caller's host.
pub fn request_rp_id(options_json: &str, origin: &str) -> Result<String, PasskeyError> {
    let options: RequestOptions =
        serde_json::from_str(options_json).map_err(|e| PasskeyError::Invalid(e.to_string()))?;
    match options.rp_id {
        Some(id) if !id.is_empty() => Ok(id),
        _ => origin_host(origin)
            .map(str::to_string)
            .ok_or_else(|| PasskeyError::Invalid("no relying party id".into())),
    }
}

/// Which of `records` a request may be answered with: the site's, narrowed
/// to its allow list when it sent one, of a version this build knows.
pub fn usable_for<'a>(
    options_json: &str,
    origin: &str,
    records: &'a [PasskeyRecord],
) -> Result<Vec<&'a PasskeyRecord>, PasskeyError> {
    let options: RequestOptions =
        serde_json::from_str(options_json).map_err(|e| PasskeyError::Invalid(e.to_string()))?;
    let rp_id = request_rp_id(options_json, origin)?;
    check_origin(origin, &rp_id)?;
    let allowed: Vec<&str> = options
        .allow
        .iter()
        .map(|d| d.id.trim_end_matches('='))
        .collect();
    Ok(records
        .iter()
        .filter(|r| r.version == PASSKEY_VERSION && r.rp_id == rp_id)
        .filter(|r| allowed.is_empty() || allowed.contains(&r.credential_id.as_str()))
        .collect())
}

/// Signs a sign-in request with `record`.
pub fn assert(
    record: &PasskeyRecord,
    options_json: &str,
    caller: &Caller<'_>,
) -> Result<String, PasskeyError> {
    let options: RequestOptions =
        serde_json::from_str(options_json).map_err(|e| PasskeyError::Invalid(e.to_string()))?;
    let rp_id = request_rp_id(options_json, caller.origin)?;
    if rp_id != record.rp_id {
        return Err(PasskeyError::WrongOrigin {
            origin: caller.origin.to_string(),
            rp_id,
        });
    }
    check_origin(caller.origin, &rp_id)?;
    let (hash, client_json) = client_data("webauthn.get", &options.challenge, caller)?;

    let mut auth_data = sha256(rp_id.as_bytes()).to_vec();
    auth_data.push(FLAGS_ASSERT);
    auth_data.extend_from_slice(&[0, 0, 0, 0]);
    let signed = [auth_data.as_slice(), &hash].concat();
    let signature: Signature = signing_key(record)?.sign(&signed);

    let mut response = json!({
        "authenticatorData": B64.encode(&auth_data),
        "signature": B64.encode(der(&signature)),
        "userHandle": record.user_handle,
    });
    if let Some(text) = client_json {
        response["clientDataJSON"] = B64.encode(text).into();
    }
    Ok(json!({
        "id": record.credential_id,
        "rawId": record.credential_id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": response,
        "clientExtensionResults": {},
    })
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;

    const CREATE: &str = r#"{
        "rp": {"id": "example.com", "name": "Example"},
        "user": {"id": "dXNlci0x", "name": "alice", "displayName": "Alice"},
        "challenge": "Y2hhbGxlbmdlLTE",
        "pubKeyCredParams": [{"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -7}],
        "excludeCredentials": []
    }"#;
    const GET: &str =
        r#"{"challenge": "Y2hhbGxlbmdlLTI", "rpId": "example.com", "allowCredentials": []}"#;

    fn browser() -> Caller<'static> {
        Caller {
            origin: "https://login.example.com",
            package: None,
            client_data_hash: None,
        }
    }

    fn b64(v: &serde_json::Value) -> Vec<u8> {
        B64.decode(v.as_str().unwrap()).unwrap()
    }

    /// Verifies the way a relying party does: signature over authenticator
    /// data and the hash of client data, with the key from registration.
    #[test]
    fn a_passkey_made_here_signs_in_and_the_site_can_check_it() {
        let made = register(CREATE, &browser(), &[], 1).unwrap();
        let reg: serde_json::Value = serde_json::from_str(&made.response_json).unwrap();
        let spki = b64(&reg["response"]["publicKey"]);
        assert_eq!(&spki[..26], &P256_SPKI_PREFIX);
        let verifying = VerifyingKey::from_sec1_bytes(&spki[26..]).unwrap();
        let client: serde_json::Value =
            serde_json::from_slice(&b64(&reg["response"]["clientDataJSON"])).unwrap();
        assert_eq!(client["type"], "webauthn.create");
        assert_eq!(client["origin"], "https://login.example.com");
        let auth = b64(&reg["response"]["authenticatorData"]);
        assert_eq!(&auth[..32], &sha256(b"example.com"));
        assert_eq!(auth[32], FLAGS_CREATE);
        assert_eq!(made.record.user_handle, "dXNlci0x");

        assert_eq!(
            usable_for(GET, "https://example.com", &[made.record.clone()])
                .unwrap()
                .len(),
            1
        );
        let signed_in: serde_json::Value =
            serde_json::from_str(&assert(&made.record, GET, &browser()).unwrap()).unwrap();
        let auth = b64(&signed_in["response"]["authenticatorData"]);
        assert_eq!(auth[32], FLAGS_ASSERT);
        let client = b64(&signed_in["response"]["clientDataJSON"]);
        let message = [auth.as_slice(), &sha256(&client)].concat();
        let signature = Signature::from_der(&b64(&signed_in["response"]["signature"])).unwrap();
        verifying.verify(&message, &signature).unwrap();
        assert_eq!(signed_in["id"], reg["id"]);
    }

    #[test]
    fn a_browser_hash_is_signed_as_given_and_no_client_data_is_invented() {
        let made = register(CREATE, &browser(), &[], 1).unwrap();
        let caller = Caller {
            client_data_hash: Some([9; 32]),
            ..browser()
        };
        let out: serde_json::Value =
            serde_json::from_str(&assert(&made.record, GET, &caller).unwrap()).unwrap();
        assert!(out["response"].get("clientDataJSON").is_none());
        let reg: serde_json::Value = serde_json::from_str(&made.response_json).unwrap();
        let verifying =
            VerifyingKey::from_sec1_bytes(&b64(&reg["response"]["publicKey"])[26..]).unwrap();
        let auth = b64(&out["response"]["authenticatorData"]);
        let signature = Signature::from_der(&b64(&out["response"]["signature"])).unwrap();
        verifying
            .verify(&[auth.as_slice(), &[9; 32]].concat(), &signature)
            .unwrap();
    }

    #[test]
    fn another_site_an_excluded_account_and_an_unknown_algorithm_are_refused() {
        let evil = Caller {
            origin: "https://example.com.evil.net",
            ..browser()
        };
        assert!(matches!(
            register(CREATE, &evil, &[], 1),
            Err(PasskeyError::WrongOrigin { .. })
        ));

        let made = register(CREATE, &browser(), &[], 1).unwrap();
        let exclude = CREATE.replace(
            r#""excludeCredentials": []"#,
            &format!(
                r#""excludeCredentials": [{{"type": "public-key", "id": "{}"}}]"#,
                made.record.credential_id
            ),
        );
        assert_eq!(
            register(&exclude, &browser(), &[made.record.clone()], 1).err(),
            Some(PasskeyError::Excluded)
        );

        let rsa = CREATE.replace(
            r#"{"type": "public-key", "alg": -7}"#,
            r#"{"type": "public-key", "alg": -257}"#,
        );
        assert_eq!(
            register(&rsa, &browser(), &[], 1).err(),
            Some(PasskeyError::Unsupported)
        );
        assert!(usable_for(GET, "https://other.org", &[made.record]).is_err());
    }

    #[test]
    fn an_app_caller_gets_its_package_in_client_data_and_a_newer_record_is_left_alone() {
        let app = Caller {
            origin: "android:apk-key-hash:abc",
            package: Some("com.example.app"),
            client_data_hash: None,
        };
        let made = register(CREATE, &app, &[], 1).unwrap();
        let reg: serde_json::Value = serde_json::from_str(&made.response_json).unwrap();
        let client: serde_json::Value =
            serde_json::from_slice(&b64(&reg["response"]["clientDataJSON"])).unwrap();
        assert_eq!(client["androidPackageName"], "com.example.app");

        let mut newer = made.record.clone();
        newer.version = PASSKEY_VERSION + 1;
        assert!(
            usable_for(GET, "android:apk-key-hash:abc", &[newer])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn signatures_are_der_with_positive_integers() {
        let secret = random_secret();
        for _ in 0..20 {
            let sig: Signature = SigningKey::from(secret.clone()).sign(&random_bytes::<16>());
            let encoded = der(&sig);
            assert_eq!(Signature::from_der(&encoded).unwrap(), sig);
        }
    }
}
