//! At-rest encryption for `vault.db`, using the same sealed envelope as
//! everything else, keyed by the Master DEK. `vault.db.enc` holds a whole
//! plain SQLite file image and is the durable artifact read back on unlock.
//! The image only ever exists in memory: the working copy on disk is
//! ciphered by SQLCipher (see `session`).

use std::path::Path;

use silentsilo_crypto::{MasterDek, seal, unseal};
use zeroize::Zeroizing;

use crate::error::VaultError;

/// Seals a database image under the vault DEK into `enc_path`.
/// Written via a temp file + rename so a crash mid-write can't corrupt the
/// previously-encrypted snapshot.
///
/// The envelope comes from `silentsilo_crypto::seal`, so this file carries
/// the same magic and version byte as an operation record: one format to
/// version, one place to change the algorithm.
///
/// Returns the BLAKE3 of the sealed bytes, which names this snapshot.
pub fn encrypt_vault_bytes(
    plaintext: &[u8],
    enc_path: &Path,
    dek: &MasterDek,
) -> Result<[u8; 32], VaultError> {
    let out = seal(plaintext, dek).map_err(|e| VaultError::Crypto(e.to_string()))?;

    // Written to a sibling and renamed, synced first: this file is what
    // unlock reads after a clean lock, and renamed-but-unwritten survives a
    // power cut as an empty snapshot. A scanner holding the old snapshot
    // open cannot fail the save; see `silentsilo_core::durable`.
    silentsilo_core::write_replacing(enc_path, &out, |at| std::fs::File::create(at))?;
    Ok(*blake3::hash(&out).as_bytes())
}

/// Opens `enc_path` (written by [`encrypt_vault_bytes`]) into memory.
///
/// The whole index in the clear: every folder and file name in the silo.
/// Held in a buffer that is wiped when dropped, and never written to disk.
pub fn decrypt_vault_bytes(
    enc_path: &Path,
    dek: &MasterDek,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let data = std::fs::read(enc_path)?;
    Ok(Zeroizing::new(unseal(&data, dek).map_err(|e| {
        VaultError::Corrupted(format!("vault snapshot: {e}"))
    })?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use silentsilo_crypto::generate_dek;
    use tempfile::tempdir;

    #[test]
    fn roundtrip() {
        let dir = tempdir().unwrap();
        let enc = dir.path().join("vault.db.enc");
        let dek = generate_dek();

        encrypt_vault_bytes(b"pretend sqlite bytes", &enc, &dek).unwrap();
        assert_ne!(std::fs::read(&enc).unwrap(), b"pretend sqlite bytes");

        let out = decrypt_vault_bytes(&enc, &dek).unwrap();
        assert_eq!(out.as_slice(), b"pretend sqlite bytes");
    }

    #[test]
    fn a_write_that_never_finished_leaves_the_last_good_snapshot_alone() {
        // The reason for the temp file and rename. A crash, a kill or a power
        // cut during the write must not be able to leave a half-encrypted
        // snapshot where the vault used to be.
        let dir = tempdir().unwrap();
        let enc = dir.path().join("vault.db.enc");
        let dek = generate_dek();

        encrypt_vault_bytes(b"the good snapshot", &enc, &dek).unwrap();

        // What a killed process leaves behind: a partial temp file next to an
        // intact snapshot, under the name `write_replacing` uses.
        let mut temp = enc.as_os_str().to_os_string();
        temp.push(".tmp");
        std::fs::write(std::path::PathBuf::from(temp), b"half-written junk").unwrap();

        let out = decrypt_vault_bytes(&enc, &dek).unwrap();
        assert_eq!(out.as_slice(), b"the good snapshot");
    }

    #[test]
    fn a_snapshot_from_an_unknown_format_says_so() {
        let dir = tempdir().unwrap();
        let enc = dir.path().join("vault.db.enc");

        // A valid envelope, relabelled as a version this build does not know.
        let dek = generate_dek();
        encrypt_vault_bytes(b"content", &enc, &dek).unwrap();
        let mut bytes = std::fs::read(&enc).unwrap();
        bytes[4] = 99;
        std::fs::write(&enc, &bytes).unwrap();

        let err = decrypt_vault_bytes(&enc, &dek).unwrap_err();
        assert!(matches!(err, VaultError::Corrupted(_)), "got {err:?}");
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let dir = tempdir().unwrap();
        let enc = dir.path().join("vault.db.enc");

        encrypt_vault_bytes(b"secret metadata", &enc, &generate_dek()).unwrap();

        let err = decrypt_vault_bytes(&enc, &generate_dek()).unwrap_err();
        assert!(matches!(err, VaultError::Corrupted(_)));
    }
}
