//! What the Windows calls send to get the wrap key back, decided apart from
//! them so every platform's tests cover it. `win.rs` builds the structs;
//! this says what goes in them.

use super::win_answers::API_VERSION_8;
use crate::hmac_secret::silo_salt;

/// `WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG`: the salts are raw
/// `hmac-secret` salts, not PRF inputs for Windows to hash first. `win.rs`
/// checks it against the `windows` crate when it builds.
pub(super) const HMAC_SECRET_VALUES_FLAG: u32 = 0x0010_0000;

/// The get-assertion options version that carries `pHmacSecretSaltValues`.
pub(super) const GET_ASSERTION_OPTIONS_VERSION_6: u32 = 6;

/// The `hmac-secret` part of a make-credential call.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Enrolment {
    /// The CTAP `hmac-secret` extension: how a removable key is asked.
    pub hmac_secret_extension: bool,
    /// `bEnablePrf`.
    pub enable_prf: bool,
    /// The salt evaluated at creation (`pPRFGlobalEval`): how Windows Hello
    /// is asked, from API version 8.
    pub prf_global_eval: Option<[u8; 32]>,
    /// `dwFlags`.
    pub flags: u32,
}

/// What a make-credential call for `vault_id` sends. A removable key gets
/// the CTAP extension; Hello gets the salt at creation, flagged as raw.
pub(super) fn enrolment(vault_id: &str, platform: bool, api_version: u32) -> Enrolment {
    let hello_salt = platform && api_version >= API_VERSION_8;
    Enrolment {
        hmac_secret_extension: !platform,
        enable_prf: true,
        prf_global_eval: hello_salt.then(|| silo_salt(vault_id)),
        flags: if hello_salt {
            HMAC_SECRET_VALUES_FLAG
        } else {
            0
        },
    }
}

/// The `hmac-secret` part of an unlock's get-assertion call.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Unlock {
    /// Sent as `pGlobalHmacSalt`, for whichever credential answers.
    pub salt: [u8; 32],
    /// `dwFlags`.
    pub flags: u32,
    /// `dwVersion` of the options.
    pub options_version: u32,
}

/// What an unlock of `vault_id` sends.
pub(super) fn unlock(vault_id: &str) -> Unlock {
    Unlock {
        salt: silo_salt(vault_id),
        flags: HMAC_SECRET_VALUES_FLAG,
        options_version: GET_ASSERTION_OPTIONS_VERSION_6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: &str = "0198b7e2-5a3c-7d10-9c1e-3f2a4b5c6d7e";

    /// `silo_salt(VAULT)`, taken from release 1.10.x. It must never change:
    /// a change means silos wrapped on Windows stop opening.
    const SILO_SALT: &str = "9654b6e475a900dc160c23e741377e41db21e4146487f5c7dfe1b7f8f33ee369";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_raw_salt_flag_is_the_value_webauthn_h_gives_it() {
        assert_eq!(HMAC_SECRET_VALUES_FLAG, 0x0010_0000);
        assert_eq!(GET_ASSERTION_OPTIONS_VERSION_6, 6);
    }

    /// Without the flag Windows hashes the salt as a PRF input first, and the
    /// key answers for a salt no silo was wrapped under.
    #[test]
    fn an_unlock_sends_the_silo_salt_flagged_as_raw() {
        let unlock = unlock(VAULT);
        assert_eq!(hex(&unlock.salt), SILO_SALT);
        assert_eq!(unlock.flags, HMAC_SECRET_VALUES_FLAG);
        assert_eq!(unlock.options_version, 6);
    }

    #[test]
    fn hello_is_asked_for_the_silo_salt_at_creation_flagged_as_raw() {
        for api in [8, 9] {
            let hello = enrolment(VAULT, true, api);
            assert!(!hello.hmac_secret_extension, "API {api}");
            assert!(hello.enable_prf, "API {api}");
            assert_eq!(
                hello.prf_global_eval.map(|s| hex(&s)).as_deref(),
                Some(SILO_SALT)
            );
            assert_eq!(hello.flags, HMAC_SECRET_VALUES_FLAG, "API {api}");
        }
    }

    #[test]
    fn a_security_key_is_asked_through_the_ctap_extension() {
        for api in [4, 7, 8, 9] {
            let key = enrolment(VAULT, false, api);
            assert!(key.hmac_secret_extension, "API {api}");
            assert!(key.enable_prf, "API {api}");
            assert_eq!(key.prf_global_eval, None, "API {api}");
            assert_eq!(key.flags, 0, "API {api}");
        }
    }

    #[test]
    fn the_raw_salt_flag_goes_with_every_salt_sent() {
        for platform in [true, false] {
            for api in 1..=10 {
                let sent = enrolment(VAULT, platform, api);
                assert_eq!(
                    sent.flags == HMAC_SECRET_VALUES_FLAG,
                    sent.prf_global_eval.is_some(),
                    "platform {platform}, API {api}"
                );
            }
        }
    }
}
