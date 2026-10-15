//! The `android-keystore` key kind (derivation `keystore-aes-256-gcm-v1`),
//! as `FORMATS.md` describes it. The phone's own code (`PhoneKey.kt` in the
//! mobile repository) does the encryption with a Keystore key no software
//! can read; this module fixes the layout it writes and does the same
//! operation with a key held in memory, so the format is tested here, on
//! every platform, and a change to it fails a test before it reaches a phone.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

/// Random bytes naming the Keystore key, alias `silentsilo-{hex}`.
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
/// The 32-byte wrap key and the 16-byte GCM tag.
pub const SEALED_LEN: usize = 48;
pub const CREDENTIAL_ID_LEN: usize = TAG_LEN + NONCE_LEN + SEALED_LEN;

/// The Keystore alias of the key a credential id names.
pub fn alias(tag: &[u8]) -> String {
    format!("silentsilo-{}", hex::encode(tag))
}

/// The per-vault string the wrap is bound to.
pub fn associated_data(vault_id: &str) -> Vec<u8> {
    format!("silentsilo-dek-v1:{vault_id}").into_bytes()
}

/// Tag, nonce and sealed wrap key, or `None` for an id of another length.
pub fn split_credential_id(id: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    if id.len() != CREDENTIAL_ID_LEN {
        return None;
    }
    let (tag, rest) = id.split_at(TAG_LEN);
    let (nonce, sealed) = rest.split_at(NONCE_LEN);
    Some((tag, nonce, sealed))
}

/// The credential id the phone writes at enrolment, with `aes_key` in place
/// of its Keystore key.
pub fn seal_with_key(
    aes_key: &[u8; 32],
    tag: &[u8; TAG_LEN],
    nonce: &[u8; NONCE_LEN],
    wrap_key: &[u8; 32],
    vault_id: &str,
) -> Vec<u8> {
    let aad = associated_data(vault_id);
    let sealed = Aes256Gcm::new(aes_key.into())
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: wrap_key,
                aad: &aad,
            },
        )
        .expect("AES-GCM over 32 bytes cannot fail");
    [&tag[..], &nonce[..], &sealed].concat()
}

/// The wrap key the phone hands back at unlock, with `aes_key` in place of
/// its Keystore key. `None` when the id is malformed or does not open under
/// this key and vault.
pub fn open_with_key(
    aes_key: &[u8; 32],
    credential_id: &[u8],
    vault_id: &str,
) -> Option<Zeroizing<[u8; 32]>> {
    let (_, nonce, sealed) = split_credential_id(credential_id)?;
    let aad = associated_data(vault_id);
    let plain = Zeroizing::new(
        Aes256Gcm::new(aes_key.into())
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: &aad,
                },
            )
            .ok()?,
    );
    let key: [u8; 32] = plain.as_slice().try_into().ok()?;
    Some(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: &str = "6f1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f7";

    fn tag() -> [u8; TAG_LEN] {
        std::array::from_fn(|i| i as u8)
    }

    fn wrap_key() -> [u8; 32] {
        std::array::from_fn(|i| 0x40 + i as u8)
    }

    /// Computed apart from this code (Python `cryptography`, AESGCM), so a
    /// change of layout, associated data or cipher here fails.
    const EXPECTED_ID: &str = "000102030405060708090a0b0c0d0e0f333333333333333333333333\
        c4c210058ed7336bfaf1a126eb66ad6756995d67de8cd3fba01353deffd3d475\
        1f9b3b7a21308f1f0c3f098aa0ff05bb";

    #[test]
    fn the_layout_phones_write_is_fixed() {
        let id = seal_with_key(&[0x11; 32], &tag(), &[0x33; NONCE_LEN], &wrap_key(), VAULT);
        assert_eq!(hex::encode(&id), EXPECTED_ID);
        assert_eq!(id.len(), 76);
        assert_eq!(
            alias(&id[..TAG_LEN]),
            "silentsilo-000102030405060708090a0b0c0d0e0f"
        );
        assert_eq!(
            associated_data(VAULT),
            b"silentsilo-dek-v1:6f1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f7"
        );
    }

    #[test]
    fn a_written_id_opens_to_its_wrap_key_and_nothing_else() {
        let id = hex::decode(EXPECTED_ID).unwrap();
        assert_eq!(*open_with_key(&[0x11; 32], &id, VAULT).unwrap(), wrap_key());
        // Another silo, another Keystore key, a flipped byte, a short id.
        assert!(open_with_key(&[0x11; 32], &id, "00000000-0000-4000-8000-000000000000").is_none());
        assert!(open_with_key(&[0x12; 32], &id, VAULT).is_none());
        let mut bent = id.clone();
        bent[CREDENTIAL_ID_LEN - 1] ^= 1;
        assert!(open_with_key(&[0x11; 32], &bent, VAULT).is_none());
        assert!(open_with_key(&[0x11; 32], &id[..CREDENTIAL_ID_LEN - 1], VAULT).is_none());
    }

    #[test]
    fn split_gives_tag_nonce_and_sealed_key() {
        let id = hex::decode(EXPECTED_ID).unwrap();
        let (t, n, s) = split_credential_id(&id).unwrap();
        assert_eq!(t, tag());
        assert_eq!(n, [0x33; NONCE_LEN]);
        assert_eq!(s.len(), SEALED_LEN);
    }
}
