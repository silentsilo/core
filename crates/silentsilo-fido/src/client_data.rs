use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub const ORIGIN: &str = "https://silentsilo.com";

fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// WebAuthn client data JSON for `makeCredential`.
pub fn create_client_data_json(challenge: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        b64url(challenge),
        ORIGIN,
    )
    .into_bytes()
}

/// WebAuthn client data JSON for `getAssertion` (DMS check-in).
pub fn get_client_data_json(challenge: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        b64url(challenge),
        ORIGIN,
    )
    .into_bytes()
}
