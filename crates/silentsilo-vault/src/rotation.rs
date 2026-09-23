//! Staging a vault key rotation so a crash in the middle cannot lose a
//! silo. The order is forced: re-sealing storage before the new key is
//! durable on disk risks every object sealed under a key that existed only
//! in memory. So: stage the new key and re-wrapped KEK under `.next`
//! names, re-seal storage (interruptible, re-runnable), then commit in one
//! step. A crash before commit leaves the silo opening under the old key
//! and the resume path takes it forward; going backwards is not always
//! possible, so it is never attempted.

use std::path::{Path, PathBuf};

use silentsilo_crypto::{ContentKek, MasterDek, seal, unseal};
use zeroize::Zeroizing;

use crate::dek_store::dek_path;
use crate::error::VaultError;
use crate::kek_store::{kek_path, wrap_kek_bytes};

/// Suffix for a key that is written but not yet in force.
const STAGED: &str = ".next";

fn staged(path: PathBuf) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(STAGED);
    PathBuf::from(name)
}

pub fn staged_dek_path(root: &Path) -> PathBuf {
    staged(dek_path(root))
}

pub fn staged_kek_path(root: &Path) -> PathBuf {
    staged(kek_path(root))
}

/// Whether a rotation was started and never finished.
///
/// Checked on unlock. The answer being yes is not an error: it means the last
/// attempt stopped somewhere, and the work in front of it is well defined.
/// A commit that got past its point of no return is finished first, so it
/// is not reported as a rotation still to resume.
pub fn rotation_pending(root: &Path) -> bool {
    let _ = finish_interrupted_commit(root);
    staged_dek_path(root).exists()
}

fn staged_keys_path(root: &Path) -> PathBuf {
    staged(crate::fido_store::fido_keys_path(root))
}

fn staged_recovery_path(root: &Path) -> PathBuf {
    staged(crate::recovery::recovery_path(root))
}

/// Puts a staged rotation in force together with the files that go with it:
/// the enrolled keys re-wrapped under the new key, and the recovery envelope
/// made for it.
///
/// These used to be written after [`commit_rotation`], by the caller. An
/// error or a crash in between (a sync client holding a file was enough)
/// left the new KEK in force, the staged key deleted, and every key and
/// recovery code still opening the old one: a silo nothing could open again.
///
/// Now they are written beside their targets first, as `.next`. Moving the
/// KEK is the point of no return; everything after it is renames, and a
/// crash anywhere in them is finished by [`finish_interrupted_commit`], which
/// needs no key. A crash before it leaves the silo as it was, still pending.
pub fn commit_rotation_with(
    root: &Path,
    keys: &crate::StoredFidoKeys,
    authority: crate::Authority<'_>,
    recovery: Option<&crate::RecoveryEnvelope>,
) -> Result<(), VaultError> {
    if !staged_kek_path(root).is_file() || !staged_dek_path(root).is_file() {
        return Err(VaultError::Corrupted("no key change is staged".into()));
    }
    crate::fido_store::check_authority(root, keys, authority)?;
    crate::workdir::write_private(&staged_keys_path(root), &crate::format::encode(keys)?)?;
    match recovery {
        Some(envelope) => {
            let json = serde_json::to_vec_pretty(envelope)
                .map_err(|e| VaultError::Crypto(e.to_string()))?;
            crate::workdir::write_private(&staged_recovery_path(root), &json)?;
        }
        None => {
            let _ = std::fs::remove_file(staged_recovery_path(root));
        }
    }
    // The point of no return.
    silentsilo_core::rename_with_retry(&staged_kek_path(root), &kek_path(root))?;
    finish_committed(root)
}

/// Finishes a commit that got past moving the KEK. The staged key is still
/// on disk while the staged KEK is gone only in that window: staging writes
/// the KEK first and the key second.
///
/// Returns whether there was anything to finish.
pub fn finish_interrupted_commit(root: &Path) -> Result<bool, VaultError> {
    if staged_dek_path(root).exists() && !staged_kek_path(root).exists() {
        finish_committed(root)?;
        return Ok(true);
    }
    Ok(false)
}

fn finish_committed(root: &Path) -> Result<(), VaultError> {
    for (staged, target) in [
        (
            staged_keys_path(root),
            crate::fido_store::fido_keys_path(root),
        ),
        (
            staged_recovery_path(root),
            crate::recovery::recovery_path(root),
        ),
    ] {
        if staged.is_file() {
            silentsilo_core::rename_with_retry(&staged, &target)?;
        }
    }
    // Last, because its absence is what says the rotation is over.
    match std::fs::remove_file(staged_dek_path(root)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    retire_page_key(root);
    Ok(())
}

/// Writes the new key and the re-wrapped KEK without putting either in
/// force. KEK first, DEK second, because the DEK's presence is what marks
/// a rotation as pending. The new key is wrapped under the **old** one
/// rather than a security key, so an interrupted rotation is resumable
/// from any credential the silo has.
///
/// Refuses outright when a rotation is already staged. Writing a second key
/// over the first strands every object the first attempt re-sealed: they
/// have moved past the old key and the second staged key never saw them, so
/// nothing that survives opens them. A caller that really means to abandon
/// an attempt calls [`discard_staged`], which is only correct while storage
/// is still untouched.
pub fn stage_rotation(
    root: &Path,
    new_dek: &MasterDek,
    kek: &ContentKek,
    old_dek: &MasterDek,
) -> Result<(), VaultError> {
    if rotation_pending(root) {
        return Err(VaultError::RotationPending);
    }
    crate::workdir::write_private(&staged_kek_path(root), &wrap_kek_bytes(kek, new_dek)?)?;
    let wrapped =
        seal(new_dek.as_bytes(), old_dek).map_err(|e| VaultError::Crypto(e.to_string()))?;
    crate::workdir::write_private(&staged_dek_path(root), &wrapped)?;
    Ok(())
}

/// The staged key, for a rotation that has to be carried on.
///
/// Read with the key the silo currently opens under, which is the old one:
/// committing has not happened, or there would be nothing staged.
pub fn load_staged_dek(root: &Path, old_dek: &MasterDek) -> Result<MasterDek, VaultError> {
    let data = std::fs::read(staged_dek_path(root))?;
    let plain = Zeroizing::new(unseal(&data, old_dek).map_err(|_| VaultError::InvalidCredentials)?);
    let key: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::InvalidCredentials)?;
    Ok(MasterDek::from_bytes(key))
}

/// Puts the staged KEK in force and clears the pending marker, and nothing
/// else. A client with enrolled keys uses [`commit_rotation_with`] instead:
/// writing `keys/fido.json` after this leaves a window in which no key and
/// no recovery code opens the silo. Rotation does not touch `master.dek.enc`:
/// once a security key is enrolled, unlock reads each key's envelope from
/// `keys/fido.json` and that file is never consulted.
pub fn commit_rotation(root: &Path) -> Result<(), VaultError> {
    silentsilo_core::rename_with_retry(&staged_kek_path(root), &kek_path(root))?;
    // Last, because its absence is what says the rotation is over. Removing
    // it before the KEK above is in place would report a finished rotation
    // over a half-applied one.
    std::fs::remove_file(staged_dek_path(root))?;
    retire_page_key(root);
    Ok(())
}

/// The working copy's `vault.key` is sealed under the retired DEK, which must
/// not open anything here once the rotation is over. The key staged under the
/// new DEK takes its place; without one it just goes, and the next unlock
/// exports a fresh copy. Best effort: unlock promotes a staged key anyway.
fn retire_page_key(root: &Path) {
    let paths = crate::VaultPaths::new(root.to_path_buf());
    let staged = paths.db_key_staged_path();
    if staged.is_file() && silentsilo_core::rename_with_retry(&staged, &paths.db_key_path()).is_ok()
    {
        return;
    }
    let _ = std::fs::remove_file(paths.db_key_path());
}

/// Throws a staged rotation away.
///
/// Only ever correct before storage has been touched. Once an object has been
/// re-sealed, the staged key is the only thing that can open it, and
/// discarding it is the loss this whole module exists to prevent.
pub fn discard_staged(root: &Path) {
    let _ = std::fs::remove_file(staged_dek_path(root));
    let _ = std::fs::remove_file(staged_kek_path(root));
    let _ = std::fs::remove_file(staged_keys_path(root));
    let _ = std::fs::remove_file(staged_recovery_path(root));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dek_store::{load_dek, save_dek};
    use crate::kek_store::{load_kek, save_kek};
    use silentsilo_crypto::{generate_content_kek, generate_dek};

    /// A silo as it stands before a rotation: a key, a KEK under it.
    fn silo(dir: &Path, wrap_key: &[u8; 32]) -> (MasterDek, ContentKek) {
        let dek = generate_dek();
        let kek = generate_content_kek();
        save_dek(dir, &dek, wrap_key).unwrap();
        save_kek(dir, &kek, &dek).unwrap();
        (dek, kek)
    }

    fn keys(id: &str, wrapped: &str, policy: &str) -> crate::StoredFidoKeys {
        crate::StoredFidoKeys {
            keys: vec![crate::StoredFidoCredential {
                kind: crate::KIND_FIDO2.to_string(),
                derivation: crate::DERIVATION_HMAC_V1.to_string(),
                policy: policy.into(),
                credential_id: id.into(),
                public_key: "3059".into(),
                key_slot: 0,
                rp_id: "silentsilo.com".into(),
                label: "Key".into(),
                wrapped_dek: wrapped.into(),
                platform: false,
                revoked: false,
            }],
        }
    }

    #[test]
    fn committing_with_the_keys_puts_all_of_it_in_force_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let (old, kek) = silo(dir.path(), &[3u8; 32]);
        crate::save_fido_keys(dir.path(), &keys("aa", "01", ""), crate::Authority::Machine)
            .unwrap();
        let new = generate_dek();
        stage_rotation(dir.path(), &new, &kek, &old).unwrap();
        let (_code, envelope) = crate::create_recovery_envelope(&new, &kek).unwrap();

        commit_rotation_with(
            dir.path(),
            &keys("aa", "02", ""),
            crate::Authority::Machine,
            Some(&envelope),
        )
        .unwrap();

        assert!(!rotation_pending(dir.path()));
        assert_eq!(
            load_kek(dir.path(), &new).unwrap().as_bytes(),
            kek.as_bytes()
        );
        assert_eq!(
            crate::load_fido_keys(dir.path()).unwrap().keys[0].wrapped_dek,
            "02"
        );
        assert_eq!(
            crate::load_recovery_envelope(dir.path())
                .unwrap()
                .wrapped_dek,
            envelope.wrapped_dek
        );
        assert!(!staged_keys_path(dir.path()).exists());
        assert!(!staged_recovery_path(dir.path()).exists());
    }

    /// The crash this exists for: past the point of no return, before the
    /// keys moved. The next read of the keys finishes the job, with no key.
    #[test]
    fn a_commit_stopped_after_the_kek_moved_finishes_on_the_next_read() {
        let dir = tempfile::tempdir().unwrap();
        let (old, kek) = silo(dir.path(), &[3u8; 32]);
        crate::save_fido_keys(dir.path(), &keys("aa", "01", ""), crate::Authority::Machine)
            .unwrap();
        let new = generate_dek();
        stage_rotation(dir.path(), &new, &kek, &old).unwrap();
        let (_code, envelope) = crate::create_recovery_envelope(&new, &kek).unwrap();

        // What commit_rotation_with does up to its point of no return.
        crate::workdir::write_private(
            &staged_keys_path(dir.path()),
            &crate::format::encode(&keys("aa", "02", "")).unwrap(),
        )
        .unwrap();
        crate::workdir::write_private(
            &staged_recovery_path(dir.path()),
            &serde_json::to_vec_pretty(&envelope).unwrap(),
        )
        .unwrap();
        silentsilo_core::rename_with_retry(&staged_kek_path(dir.path()), &kek_path(dir.path()))
            .unwrap();

        assert_eq!(
            crate::load_fido_keys(dir.path()).unwrap().keys[0].wrapped_dek,
            "02"
        );
        assert!(
            !rotation_pending(dir.path()),
            "finished, not left to resume"
        );
        assert_eq!(
            crate::load_recovery_envelope(dir.path())
                .unwrap()
                .wrapped_dek,
            envelope.wrapped_dek
        );
        assert_eq!(
            load_kek(dir.path(), &new).unwrap().as_bytes(),
            kek.as_bytes()
        );
    }

    /// Before the KEK moves nothing has changed, and staged files from that
    /// attempt are not promoted by anyone reading the keys.
    #[test]
    fn a_commit_stopped_before_the_kek_moved_leaves_the_old_silo() {
        let dir = tempfile::tempdir().unwrap();
        let (old, kek) = silo(dir.path(), &[3u8; 32]);
        crate::save_fido_keys(dir.path(), &keys("aa", "01", ""), crate::Authority::Machine)
            .unwrap();
        stage_rotation(dir.path(), &generate_dek(), &kek, &old).unwrap();
        crate::workdir::write_private(
            &staged_keys_path(dir.path()),
            &crate::format::encode(&keys("aa", "02", "")).unwrap(),
        )
        .unwrap();

        assert_eq!(
            crate::load_fido_keys(dir.path()).unwrap().keys[0].wrapped_dek,
            "01"
        );
        assert!(rotation_pending(dir.path()));
        assert_eq!(
            load_kek(dir.path(), &old).unwrap().as_bytes(),
            kek.as_bytes()
        );

        discard_staged(dir.path());
        assert!(!staged_keys_path(dir.path()).exists());
    }

    #[test]
    fn committing_cannot_drop_an_organisation_key_without_its_proof() {
        let dir = tempfile::tempdir().unwrap();
        let (old, kek) = silo(dir.path(), &[3u8; 32]);
        crate::save_fido_keys(
            dir.path(),
            &keys("aa", "01", crate::POLICY_ORG),
            crate::Authority::Machine,
        )
        .unwrap();
        stage_rotation(dir.path(), &generate_dek(), &kek, &old).unwrap();

        let refused = commit_rotation_with(
            dir.path(),
            &keys("bb", "02", ""),
            crate::Authority::Machine,
            None,
        );
        assert!(matches!(refused, Err(VaultError::OrganisationKeyRequired)));
        assert!(rotation_pending(dir.path()), "nothing moved");
        assert_eq!(
            load_kek(dir.path(), &old).unwrap().as_bytes(),
            kek.as_bytes()
        );
    }

    #[test]
    fn staging_leaves_the_silo_opening_under_the_old_key() {
        // The whole point of staging: until it is committed, nothing has
        // changed for anyone opening the silo.
        let dir = tempfile::tempdir().unwrap();
        let wrap_key = [3u8; 32];
        let (old, kek) = silo(dir.path(), &wrap_key);

        stage_rotation(dir.path(), &generate_dek(), &kek, &old).unwrap();

        assert!(rotation_pending(dir.path()));
        let opened = load_dek(dir.path(), &wrap_key).unwrap();
        assert_eq!(opened.as_bytes(), old.as_bytes());
        assert_eq!(
            load_kek(dir.path(), &old).unwrap().as_bytes(),
            kek.as_bytes()
        );
    }

    #[test]
    fn committing_puts_the_new_key_in_force_and_keeps_the_kek_readable() {
        let dir = tempfile::tempdir().unwrap();
        let wrap_key = [3u8; 32];
        let (old, kek) = silo(dir.path(), &wrap_key);
        let new = generate_dek();

        stage_rotation(dir.path(), &new, &kek, &old).unwrap();
        commit_rotation(dir.path()).unwrap();

        assert!(!rotation_pending(dir.path()), "nothing is left staged");
        // The KEK is the same key, reachable under the new DEK and not the
        // old. That is what leaves every content key working while closing
        // them to whoever holds only the old one, and it is what commit puts
        // in force: the new DEK's own envelopes are the caller's to write.
        assert_eq!(
            load_kek(dir.path(), &new).unwrap().as_bytes(),
            kek.as_bytes()
        );
        assert!(load_kek(dir.path(), &old).is_err());
    }

    #[test]
    fn the_staged_key_survives_to_be_carried_on() {
        // What the resume path reads after a crash: the key storage was
        // being re-sealed under, still openable with the device's wrap key.
        let dir = tempfile::tempdir().unwrap();
        let wrap_key = [3u8; 32];
        let (old, kek) = silo(dir.path(), &wrap_key);
        let new = generate_dek();

        stage_rotation(dir.path(), &new, &kek, &old).unwrap();

        assert_eq!(
            load_staged_dek(dir.path(), &old).unwrap().as_bytes(),
            new.as_bytes()
        );
    }

    #[test]
    fn discarding_leaves_the_silo_exactly_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let wrap_key = [3u8; 32];
        let (old, kek) = silo(dir.path(), &wrap_key);

        stage_rotation(dir.path(), &generate_dek(), &kek, &old).unwrap();
        discard_staged(dir.path());

        assert!(!rotation_pending(dir.path()));
        assert_eq!(
            load_dek(dir.path(), &wrap_key).unwrap().as_bytes(),
            old.as_bytes()
        );
        assert_eq!(
            load_kek(dir.path(), &old).unwrap().as_bytes(),
            kek.as_bytes()
        );
    }

    /// Resuming has to work from any key the silo has, not only the one that
    /// started the rotation. Wrapping the staged key under the old vault key
    /// is what buys that: every successful unlock produces it.
    #[test]
    fn the_staged_key_reads_back_from_any_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let (old, kek) = silo(dir.path(), &[3u8; 32]);
        let new = generate_dek();

        stage_rotation(dir.path(), &new, &kek, &old).unwrap();

        // A second credential unlocks the same silo and so holds the same
        // old key, with no knowledge of how the rotation was started.
        assert_eq!(
            load_staged_dek(dir.path(), &old).unwrap().as_bytes(),
            new.as_bytes()
        );
        assert!(
            load_staged_dek(dir.path(), &generate_dek()).is_err(),
            "and a key that does not open this silo reads nothing"
        );
    }

    /// Finishing a rotation has to leave a recovery code somebody holds.
    ///
    /// The commit puts a new key in force, which kills the old code: it
    /// unwraps the key that just stopped being current. So the resume path
    /// mints a fresh envelope, and the code it was minted from has to reach
    /// the caller. It once did not, and the silo then reported a recovery
    /// code that had never been shown to anyone.
    #[test]
    fn finishing_a_rotation_leaves_a_recovery_code_that_opens_the_new_key() {
        let dir = tempfile::tempdir().unwrap();
        let wrap_key = [3u8; 32];
        let (old, kek) = silo(dir.path(), &wrap_key);
        let new = generate_dek();

        let (old_code, old_envelope) = crate::create_recovery_envelope(&old, &kek).unwrap();
        crate::save_recovery_envelope(dir.path(), &old_envelope).unwrap();

        stage_rotation(dir.path(), &new, &kek, &old).unwrap();
        commit_rotation(dir.path()).unwrap();

        // What the resume path does once the keys are in force.
        let (new_code, new_envelope) = crate::create_recovery_envelope(&new, &kek).unwrap();
        crate::save_recovery_envelope(dir.path(), &new_envelope).unwrap();

        let stored = crate::load_recovery_envelope(dir.path()).unwrap();
        assert_eq!(
            crate::unwrap_with_code(&stored, &new_code)
                .expect("the code the resume returned must open the silo")
                .as_bytes(),
            new.as_bytes(),
        );
        assert!(
            crate::unwrap_with_code(&stored, &old_code).is_err(),
            "the code written down before the change must stop working"
        );
    }

    #[test]
    fn a_second_rotation_cannot_be_staged_over_the_first() {
        // The dangerous shape. By the time an attempt can be abandoned it has
        // usually re-sealed objects in storage, and those have moved past the
        // old key. Writing a second staged key over the first leaves them
        // opening under nothing that still exists: not the old key, not the
        // key that commits. Unrecoverable, so the answer is to refuse and
        // send the caller to the resume path.
        let dir = tempfile::tempdir().unwrap();
        let wrap_key = [3u8; 32];
        let (old, kek) = silo(dir.path(), &wrap_key);
        let first = generate_dek();

        stage_rotation(dir.path(), &first, &kek, &old).unwrap();

        assert!(matches!(
            stage_rotation(dir.path(), &generate_dek(), &kek, &old),
            Err(VaultError::RotationPending)
        ));
        // And the refusal changed nothing: the first attempt is still the one
        // waiting to be finished.
        assert_eq!(
            load_staged_dek(dir.path(), &old).unwrap().as_bytes(),
            first.as_bytes()
        );
    }

    #[test]
    fn discarding_an_untouched_attempt_makes_room_for_another() {
        // The one way out that is not forward, and the reason `discard_staged`
        // exists: nothing in storage has been re-sealed yet, so the staged key
        // is holding nothing and can be dropped.
        let dir = tempfile::tempdir().unwrap();
        let wrap_key = [3u8; 32];
        let (old, kek) = silo(dir.path(), &wrap_key);

        stage_rotation(dir.path(), &generate_dek(), &kek, &old).unwrap();
        discard_staged(dir.path());
        let second = generate_dek();
        stage_rotation(dir.path(), &second, &kek, &old).unwrap();
        commit_rotation(dir.path()).unwrap();

        assert_eq!(
            load_kek(dir.path(), &second).unwrap().as_bytes(),
            kek.as_bytes()
        );
    }
}
