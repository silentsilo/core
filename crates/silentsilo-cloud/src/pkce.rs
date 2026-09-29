//! PKCE (RFC 7636, S256) and the `state` value of a sign-in.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The verifier stays in this process; only its hash goes to the browser. A
/// code caught on its way back, by anything else on this computer, cannot be
/// exchanged without it.
pub(crate) struct Pkce {
    pub verifier: Zeroizing<String>,
    pub challenge: String,
}

impl Pkce {
    pub fn new() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(bytes.as_mut());
        Self::from_verifier(URL_SAFE_NO_PAD.encode(bytes.as_ref()))
    }

    fn from_verifier(verifier: String) -> Self {
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Self {
            verifier: Zeroizing::new(verifier),
            challenge,
        }
    }
}

/// Unguessable, so a redirect this sign-in did not start is refused.
pub(crate) fn random_state() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_is_the_one_rfc_7636_gives() {
        // Appendix B of the RFC.
        let pkce = Pkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into());
        assert_eq!(
            pkce.challenge,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_verifier_is_long_enough_and_never_repeats() {
        let a = Pkce::new();
        let b = Pkce::new();
        // 43 to 128 characters of the unreserved set.
        assert_eq!(a.verifier.len(), 43);
        assert!(
            a.verifier
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_ne!(*a.verifier, *b.verifier);
        assert_ne!(random_state(), random_state());
    }
}
