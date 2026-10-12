//! A key change staged by one release and carried on by another. From core
//! 1.10 the staged key stays on the machine that started the change and the
//! silo folder names it; 1.9 and earlier kept it in the folder, sealed under
//! the old key. Each release's own code answers for what it does with the
//! other's file.

use std::path::Path;

use silentsilo_crypto::{ContentKek, MasterDek, generate_content_kek, generate_dek};
use silentsilo_crypto_v1_6_1 as crypto_old;
use silentsilo_vault::rotation;
use silentsilo_vault_v1_6_1 as vault_old;

fn old_dek(dek: &MasterDek) -> crypto_old::MasterDek {
    crypto_old::MasterDek::from_bytes(*dek.as_bytes())
}

fn old_kek(kek: &ContentKek) -> crypto_old::ContentKek {
    crypto_old::ContentKek::from_bytes(*kek.as_bytes())
}

/// The part of a silo folder a key change touches: the KEK under the key.
fn silo(dir: &Path) -> (MasterDek, ContentKek) {
    let dek = generate_dek();
    let kek = generate_content_kek();
    silentsilo_vault::save_kek(dir, &kek, &dek).unwrap();
    (dek, kek)
}

#[test]
fn a_change_an_earlier_release_staged_is_carried_on_and_finished_here() {
    let dir = tempfile::tempdir().unwrap();
    let (old, kek) = silo(dir.path());
    let new = generate_dek();
    vault_old::rotation::stage_rotation(dir.path(), &old_dek(&new), &old_kek(&kek), &old_dek(&old))
        .unwrap();

    assert!(rotation::rotation_pending(dir.path()));
    assert_eq!(
        rotation::load_staged_dek(dir.path(), &old)
            .unwrap()
            .as_bytes(),
        new.as_bytes()
    );
    rotation::commit_rotation(dir.path()).unwrap();
    assert!(!rotation::rotation_pending(dir.path()));
    assert_eq!(
        silentsilo_vault::load_kek(dir.path(), &new)
            .unwrap()
            .as_bytes(),
        kek.as_bytes()
    );
}

/// An earlier release that meets a change staged here sees it pending, so
/// it never stages a second key over the first, and reads no key out of the
/// folder. It cannot finish it: back on this release, it finishes.
#[test]
fn an_earlier_release_neither_restarts_nor_reads_a_change_staged_here() {
    let dir = tempfile::tempdir().unwrap();
    let (old, kek) = silo(dir.path());
    let new = generate_dek();
    rotation::stage_rotation(dir.path(), &new, &kek, &old).unwrap();

    assert!(vault_old::rotation::rotation_pending(dir.path()));
    assert!(vault_old::rotation::load_staged_dek(dir.path(), &old_dek(&old)).is_err());
    assert!(
        vault_old::rotation::stage_rotation(
            dir.path(),
            &old_dek(&generate_dek()),
            &old_kek(&kek),
            &old_dek(&old)
        )
        .is_err()
    );

    assert_eq!(
        rotation::load_staged_dek(dir.path(), &old)
            .unwrap()
            .as_bytes(),
        new.as_bytes()
    );
    rotation::commit_rotation(dir.path()).unwrap();
    assert_eq!(
        silentsilo_vault::load_kek(dir.path(), &new)
            .unwrap()
            .as_bytes(),
        kek.as_bytes()
    );
}
