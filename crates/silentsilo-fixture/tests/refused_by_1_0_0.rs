//! Records this build writes that 1.0.0 cannot apply.
//!
//! Both are states where 1.0.0's own `Vfs` refuses the change with the same
//! error, so a 1.0.0-only fleet reaches them only when two devices change
//! things at once. This build accepts the change and writes a record, and a
//! 1.0.0 device that receives it stops applying records at it on every pass
//! until it updates: it keeps pushing its own changes and receives nothing
//! after that record. Nothing is lost, and the update rebuilds its tables.
//! `mixed_fleet.rs` meets both. These tests pin the behaviour so that
//! changing it is a decision.

use std::path::PathBuf;

use rusqlite::Connection;
use silentsilo_crypto_v1_0_0 as crypto_v1;
use silentsilo_vault::VaultSession;
use silentsilo_vault_v1_0_0 as vault_v1;
use silentsilo_vfs::Vfs;
use silentsilo_vfs_v1_0_0 as vfs_v1;
use uuid::Uuid;

/// A 1.0.0 session and one on this build, both over empty in-memory
/// databases of the same silo.
fn side_by_side() -> (vault_v1::VaultSession, VaultSession) {
    let vault_id = Uuid::new_v4();
    let db = || {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        conn
    };
    let old = vault_v1::VaultSession {
        paths: vault_v1::VaultPaths::new(PathBuf::from("unused")),
        conn: db(),
        vault_id,
        dek: crypto_v1::generate_dek(),
        kek: crypto_v1::generate_content_kek(),
    };
    let new = VaultSession {
        paths: silentsilo_vault::VaultPaths::new(PathBuf::from("unused")),
        conn: db(),
        vault_id,
        dek: silentsilo_crypto::MasterDek::from_bytes(*old.dek.as_bytes()),
        kek: silentsilo_crypto::ContentKek::from_bytes(*old.kek.as_bytes()),
    };
    vfs_v1::Vfs::new(&old).ensure_initialized().unwrap();
    Vfs::new(&new).ensure_initialized().unwrap();
    (old, new)
}

fn as_1_0_0(records: Vec<silentsilo_vfs::OpRecord>) -> Vec<vfs_v1::OpRecord> {
    records
        .iter()
        .map(|r| vfs_v1::OpRecord::from_bytes(&r.to_bytes().unwrap()).unwrap())
        .collect()
}

#[test]
fn known_1_0_0_stops_at_a_name_its_ranking_gives_to_a_file_already_called_that() {
    let (old, new) = side_by_side();
    let vfs = Vfs::new(&new);
    let root = vfs.root_folder_id().unwrap();
    vfs.add_file(root, "a (2).txt", Uuid::new_v4(), 1, "h", None, "k")
        .unwrap();
    vfs.add_file(root, "A.txt", Uuid::new_v4(), 1, "h", None, "k")
        .unwrap();

    // This build skips the suffix another file asked for outright.
    let added = vfs
        .add_file(root, "a.txt", Uuid::new_v4(), 1, "h", None, "k")
        .unwrap();
    assert_eq!(added.name, "a (3).txt");

    // 1.0.0 ranks it "a (2).txt", which is taken.
    let refused = vfs_v1::replay(
        &old.conn,
        as_1_0_0(silentsilo_vfs::all_ops(&new.conn).unwrap()),
    );
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("UNIQUE constraint failed: files.folder_id, files.name")
    );
    // The same change made on 1.0.0 is refused there.
    let (old, _) = side_by_side();
    let vfs = vfs_v1::Vfs::new(&old);
    let root = vfs.root_folder_id().unwrap();
    for name in ["a (2).txt", "A.txt"] {
        vfs.add_file(root, name, Uuid::new_v4(), 1, "h", None, "k")
            .unwrap();
    }
    assert!(
        vfs.add_file(root, "a.txt", Uuid::new_v4(), 1, "h", None, "k")
            .is_err()
    );
}

#[test]
fn known_1_0_0_stops_at_a_purge_of_a_folder_that_still_holds_a_restored_file() {
    let (old, new) = side_by_side();
    let vfs = Vfs::new(&new);
    let root = vfs.root_folder_id().unwrap();
    let folder = vfs.create_folder(root, "F").unwrap();
    let file = vfs
        .add_file(folder.id, "f.txt", Uuid::new_v4(), 1, "h", None, "k")
        .unwrap();
    vfs.trash_folder(folder.id).unwrap();
    vfs.restore_file(file.id).unwrap();
    vfs.empty_trash().unwrap();

    // This build purges the folder and keeps the file, at the top.
    assert_eq!(vfs.get_file(file.id).unwrap().folder_id, root);

    // 1.0.0 deletes the folder under the file.
    let refused = vfs_v1::replay(
        &old.conn,
        as_1_0_0(silentsilo_vfs::all_ops(&new.conn).unwrap()),
    );
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("FOREIGN KEY constraint failed")
    );
    // The same change made on 1.0.0 is refused there.
    let (old, _) = side_by_side();
    let vfs = vfs_v1::Vfs::new(&old);
    let root = vfs.root_folder_id().unwrap();
    let folder = vfs.create_folder(root, "F").unwrap();
    let file = vfs
        .add_file(folder.id, "f.txt", Uuid::new_v4(), 1, "h", None, "k")
        .unwrap();
    vfs.trash_folder(folder.id).unwrap();
    vfs.restore_file(file.id).unwrap();
    assert!(vfs.empty_trash().is_err());
}
