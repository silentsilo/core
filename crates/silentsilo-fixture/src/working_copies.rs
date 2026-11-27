//! Working copies as a release leaves them on a machine, written once by the
//! SQLCipher that release builds, so a later SQLCipher has to open them.
//!
//! The working copy is not a format (FORMATS.md): one that does not open is
//! rebuilt from the snapshot. A rebuild after a crash still loses what was
//! only in the WAL, and after an update every working copy on every machine
//! goes through the new library at once. The old tags in the fixture's
//! dev-dependencies run on this build's SQLite, so they cannot answer this.
//!
//! Each directory under `working-copies/` is named for the SQLCipher that
//! wrote it and holds two cases, each a `silo/` and its `work/` files:
//!
//! - `crashed`: copied while the session was open, with a change made after
//!   the last snapshot that only the WAL holds;
//! - `locked`: what a lock keeps, the copy and its sealed page key.
//!
//! Both open with [`crate::FIXTURE_DEVICE_SECRET`]. They are pinned by
//! `working-copies/SHA256SUMS`, like the silos in `fixtures/`.

use std::path::{Path, PathBuf};

use silentsilo_vault::{KEPT_ACROSS_LOCKS, VaultSession, wipe_plaintext_working_copy};
use silentsilo_vfs::Vfs;
use uuid::Uuid;

use crate::FIXTURE_DEVICE_SECRET;

/// The working copies directory of this crate.
pub fn working_copies_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("working-copies")
}

/// In the snapshot of both cases.
pub const SNAPSHOTTED: &str = "snapshotted.pdf";
/// Written after the snapshot: only the crashed copy's WAL holds it.
pub const ONLY_IN_THE_WAL: &str = "after the snapshot.pdf";

/// Files of the work directory a case keeps. The `-shm` index is left out:
/// SQLite rebuilds it from the WAL.
fn kept(name: &str) -> bool {
    KEPT_ACROSS_LOCKS.contains(&name) && !name.ends_with("-shm")
}

fn add(vfs: &Vfs, name: &str) -> Result<(), String> {
    let root = vfs.root_folder_id().map_err(|e| e.to_string())?;
    vfs.add_file(root, name, Uuid::new_v4(), 1, "hash", None, "key")
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn copy_dir(from: &Path, to: &Path) -> Result<(), String> {
    std::fs::create_dir_all(to).map_err(|e| e.to_string())?;
    for entry in std::fs::read_dir(from).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        let target = to.join(path.file_name().unwrap());
        if path.is_dir() {
            copy_dir(&path, &target)?;
        } else {
            std::fs::copy(&path, &target).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn copy_work(work: &Path, to: &Path) -> Result<(), String> {
    std::fs::create_dir_all(to).map_err(|e| e.to_string())?;
    for name in KEPT_ACROSS_LOCKS.iter().filter(|n| kept(n)) {
        let from = work.join(name);
        if from.is_file() {
            std::fs::copy(&from, to.join(name)).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// A silo with one file in its snapshot, at `scratch/silo`.
fn snapshotted_session(scratch: &Path, vault_id: Uuid) -> Result<VaultSession, String> {
    let session = VaultSession::provision(scratch.join("silo"), vault_id, FIXTURE_DEVICE_SECRET)
        .map_err(|e| e.to_string())?;
    let vfs = Vfs::new(&session);
    vfs.ensure_initialized().map_err(|e| e.to_string())?;
    add(&vfs, SNAPSHOTTED)?;
    session.backup_locally().map_err(|e| e.to_string())?;
    Ok(session)
}

/// Writes both cases under `dir`, which must not exist.
pub fn create_working_copies(dir: &Path) -> Result<(), String> {
    let scratch = tempfile::tempdir().map_err(|e| e.to_string())?;

    // Crashed: everything copied while the session is open, since closing
    // checkpoints the WAL away.
    let crashed = scratch.path().join("crashed");
    let session = snapshotted_session(
        &crashed,
        Uuid::from_u128(0x5117_0000_0000_0000_0000_0000_0000_0c01),
    )?;
    add(&Vfs::new(&session), ONLY_IN_THE_WAL)?;
    let work = session.paths.work_dir();
    if !work.join("vault.sqlcipher-wal").is_file() {
        return Err("the crashed copy has no WAL".into());
    }
    copy_dir(&crashed.join("silo"), &dir.join("crashed").join("silo"))?;
    copy_work(&work, &dir.join("crashed").join("work"))?;
    let root = session.paths.root.clone();
    drop(session);
    silentsilo_vault::wipe_work_dir(&root);

    // Locked: sealed, the plaintext gone, the copy and its key kept.
    let locked = scratch.path().join("locked");
    let session = snapshotted_session(
        &locked,
        Uuid::from_u128(0x5117_0000_0000_0000_0000_0000_0000_0c02),
    )?;
    session.seal_for_lock().map_err(|e| e.to_string())?;
    let paths = session.paths.clone();
    drop(session);
    wipe_plaintext_working_copy(&paths);
    copy_dir(&paths.root, &dir.join("locked").join("silo"))?;
    copy_work(&paths.work_dir(), &dir.join("locked").join("work"))?;
    silentsilo_vault::wipe_work_dir(&paths.root);
    Ok(())
}
