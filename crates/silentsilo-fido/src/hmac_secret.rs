//! What every platform feeds a key's `hmac-secret` for a silo, and how its
//! answer becomes the wrap key. Windows and CTAP2 both call this, so the
//! derivation lives once and is tested on every platform.

use sha2::{Digest, Sha256};

use crate::dek_salt_for_vault;

/// SHA-256 of UTF-8 `message`: CTAP hmac-secret salt for string inputs.
pub(crate) fn hmac_salt_from_string(message: &str) -> [u8; 32] {
    Sha256::digest(message.as_bytes()).into()
}

/// The salt every platform feeds `hmac-secret` for this silo.
pub(crate) fn silo_salt(vault_id: &str) -> [u8; 32] {
    hmac_salt_from_string(&dek_salt_for_vault(vault_id))
}

/// `salt` as a WebAuthn PRF input reaches the key: hashed again by the
/// platform, under the PRF label.
pub(crate) fn prf_salt(salt: &[u8; 32]) -> [u8; 32] {
    Sha256::digest([b"WebAuthn PRF\x00".as_slice(), salt].concat()).into()
}

/// The wrap key from one 32-byte `hmac-secret` output.
pub(crate) fn wrap_key_from_hmac(output: &[u8]) -> [u8; 32] {
    *blake3::hash(output).as_bytes()
}

// Known answers taken from release 1.10.x. They must never change: a change
// means every silo wrapped by a security key or Windows Hello stops opening.
#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: &str = "0198b7e2-5a3c-7d10-9c1e-3f2a4b5c6d7e";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_silo_salt_is_the_sha256_of_the_dek_salt_string() {
        assert_eq!(
            hex(&hmac_salt_from_string(
                "silentsilo-dek-v1:0198b7e2-5a3c-7d10-9c1e-3f2a4b5c6d7e"
            )),
            "9654b6e475a900dc160c23e741377e41db21e4146487f5c7dfe1b7f8f33ee369"
        );
        assert_eq!(
            hex(&silo_salt(VAULT)),
            "9654b6e475a900dc160c23e741377e41db21e4146487f5c7dfe1b7f8f33ee369"
        );
    }

    #[test]
    fn the_prf_salt_is_the_silo_salt_hashed_under_the_prf_label() {
        assert_eq!(
            hex(&prf_salt(&silo_salt(VAULT))),
            "39d45c4412e8411e0f31d8cffc05f1985ff3de240276e74891148fa72adba39e"
        );
    }

    #[test]
    fn the_wrap_key_is_the_blake3_of_the_hmac_secret_output() {
        assert_eq!(
            hex(&wrap_key_from_hmac(&[0x5a; 32])),
            "4f56ba952f3e404b05e66f4c353e87159f912df32b131fc0c297d52ceb7fb5ee"
        );
    }

    /// HMAC-SHA256 under a `CredRandom` of 32 bytes of `0x5a` (unverified)
    /// and under its `uv` derivative (verified), over the raw and the PRF
    /// salt of `VAULT`, as a key computes it; then the wrap key each gives.
    /// The same four keys `soft_key` gets through the whole protocol.
    #[test]
    fn each_of_a_keys_four_outputs_gives_its_own_wrap_key() {
        for (output, wrap) in [
            (
                "00e88e5da5ae02e8d3aa755ff49cd0e29c1e6cb98f977a956b8ec845c5d0cfcd",
                "faafe786fdcdf5c2d0fbcfabc854da21cd465ee7ab16d0eda606e7107d8b9b11",
            ),
            (
                "2a3eeb9219ee62b632cd6bd989aa8441d622a4cc8fc6a253a07f645fa990c5b1",
                "545639bbacd7ad8dae8464f66c6a42a50bcb131f5bd3752ac83eee7e75c4cf16",
            ),
            (
                "fc9d13a4b18db268118a663bdc1c1bac1bde681b9c39d9b90ebf81a181e1d7f1",
                "fabaadd5b9318fa2155a72802abfa164a351190b6591e73f11acaee6ee12909b",
            ),
            (
                "08db562e8462d5b1264a3bffe679fb71e874d71a0a85fc93ce018cd5d0c656c9",
                "a1f703122cf2322d8db8c0f3b6161edc63dade7db72789e7c9c83dbe12d97d9a",
            ),
        ] {
            let output: Vec<u8> = (0..64)
                .step_by(2)
                .map(|i| u8::from_str_radix(&output[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(hex(&wrap_key_from_hmac(&output)), wrap);
        }
    }
}
