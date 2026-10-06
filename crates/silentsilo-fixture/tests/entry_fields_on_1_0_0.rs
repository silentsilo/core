//! Custom fields, history and the SSH agent flag live inside the password
//! entry, as fields 1.0.0 never heard of. What 1.0.0 does with them, by its own code: applies the
//! record, keeps the entry byte for byte, and carries it through its own
//! snapshot, its compaction, and a device restored from that snapshot.

use std::path::PathBuf;

use rusqlite::Connection;
use silentsilo_crypto_v1_0_0 as crypto_v1;
use silentsilo_vault::VaultSession;
use silentsilo_vault_v1_0_0 as vault_v1;
use silentsilo_vfs::{MAX_ENTRY_BYTES, Vfs};
use silentsilo_vfs_v1_0_0 as vfs_v1;
use uuid::Uuid;

/// An entry as 1.4 writes it: two custom fields, one hidden, a version in
/// its history, and an SSH key offered to the agent.
const ENTRY: &str = r#"{"id":"0190a0a0-0000-7000-8000-00000000e001","service":"Bank","username":"ana","password":"new-pass","url":"https://bank.example","notes":"","category":"","created_at":1789000000000,"updated_at":1789000500000,"type":"login","ssh_agent":true,"fields":[{"name":"Customer number","value":"40021","hidden":false},{"name":"Card PIN","value":"1234","hidden":true}],"history":[{"saved_at":1789000000000,"service":"Bank","username":"ana","password":"old-pass","url":"https://bank.example","notes":"","type":"login","fields":[]}]}"#;

fn db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    conn
}

fn v1_session(vault_id: Uuid, dek: [u8; 32], kek: [u8; 32]) -> vault_v1::VaultSession {
    let session = vault_v1::VaultSession {
        paths: vault_v1::VaultPaths::new(PathBuf::from("unused")),
        conn: db(),
        vault_id,
        dek: crypto_v1::MasterDek::from_bytes(dek),
        kek: crypto_v1::ContentKek::from_bytes(kek),
    };
    vfs_v1::Vfs::new(&session).ensure_initialized().unwrap();
    session
}

fn session(vault_id: Uuid, dek: [u8; 32], kek: [u8; 32]) -> VaultSession {
    let session = VaultSession {
        paths: silentsilo_vault::VaultPaths::new(PathBuf::from("unused")),
        conn: db(),
        vault_id,
        dek: silentsilo_crypto::MasterDek::from_bytes(dek),
        kek: silentsilo_crypto::ContentKek::from_bytes(kek),
    };
    Vfs::new(&session).ensure_initialized().unwrap();
    session
}

/// The entry under test, out of whatever else the list holds.
fn held(entries: Vec<String>) -> String {
    entries
        .into_iter()
        .find(|e| e.contains("Customer number"))
        .expect("the entry is there")
}

fn as_1_0_0(records: Vec<silentsilo_vfs::OpRecord>) -> Vec<vfs_v1::OpRecord> {
    records
        .iter()
        .map(|r| vfs_v1::OpRecord::from_bytes(&r.to_bytes().unwrap()).unwrap())
        .collect()
}

#[test]
fn version_1_0_0_keeps_fields_and_history_through_replay_snapshot_and_rebuild() {
    let vault_id = Uuid::new_v4();
    let (dek, kek) = ([7u8; 32], [9u8; 32]);
    let new = session(vault_id, dek, kek);
    let id = Uuid::parse_str("0190a0a0-0000-7000-8000-00000000e001").unwrap();
    Vfs::new(&new).upsert_password(id, ENTRY).unwrap();
    let horizon = silentsilo_vfs::all_ops(&new.conn)
        .unwrap()
        .iter()
        .map(|r| r.lamport)
        .max()
        .unwrap();
    // Something above the horizon, or there is nothing to snapshot below.
    Vfs::new(&new)
        .upsert_password(Uuid::new_v4(), r#"{"id":"later"}"#)
        .unwrap();
    let records = silentsilo_vfs::all_ops(&new.conn).unwrap();

    // Replayed on 1.0.0: the entry comes back exactly as written.
    let old = v1_session(vault_id, dek, kek);
    vfs_v1::replay(&old.conn, as_1_0_0(records)).expect("1.0.0 applies it");
    assert_eq!(
        held(vfs_v1::Vfs::new(&old).list_passwords().unwrap()),
        ENTRY
    );

    // 1.0.0's own snapshot and compaction, and a 1.0.0 device rebuilt from
    // the snapshot.
    let mut old = old;
    let snapshot = vfs_v1::capture_at(&old.conn, vault_id, horizon).unwrap();
    vfs_v1::compact_local(&mut old.conn, &snapshot).expect("1.0.0 compacts");
    assert_eq!(
        held(vfs_v1::Vfs::new(&old).list_passwords().unwrap()),
        ENTRY
    );
    let bytes = snapshot.to_bytes().unwrap();
    let rebuilt = v1_session(vault_id, dek, kek);
    let read = vfs_v1::Snapshot::from_bytes(&bytes).unwrap();
    vfs_v1::restore_snapshot(&rebuilt.conn, &read).expect("1.0.0 restores it");
    assert_eq!(
        held(vfs_v1::Vfs::new(&rebuilt).list_passwords().unwrap()),
        ENTRY
    );

    // And this build reading what 1.0.0 wrote.
    let current = session(vault_id, dek, kek);
    let read = silentsilo_vfs::Snapshot::from_bytes(&bytes).unwrap();
    silentsilo_vfs::restore_snapshot(&current.conn, &read).unwrap();
    assert_eq!(held(Vfs::new(&current).list_passwords().unwrap()), ENTRY);
}

#[test]
fn the_largest_entry_this_build_saves_is_a_record_1_0_0_reads() {
    let vault_id = Uuid::new_v4();
    let new = session(vault_id, [7; 32], [9; 32]);
    let vfs = Vfs::new(&new);
    let pad = "x".repeat(MAX_ENTRY_BYTES - 40);
    let entry = format!(r#"{{"id":"e","notes":"{pad}"}}"#);
    assert!(entry.len() <= MAX_ENTRY_BYTES);
    vfs.upsert_password(Uuid::new_v4(), &entry).unwrap();

    // The record as it goes to storage: sealed again under the DEK, which
    // adds a header and a tag. 1.0.0 refuses anything over 1 MiB.
    let record = silentsilo_vfs::all_ops(&new.conn).unwrap().pop().unwrap();
    let sealed = silentsilo_crypto::seal(&record.to_bytes().unwrap(), &new.dek).unwrap();
    assert!(sealed.len() < 1024 * 1024, "{} bytes", sealed.len());

    let over = format!(r#"{{"id":"e","notes":"{}"}}"#, "x".repeat(MAX_ENTRY_BYTES));
    assert!(vfs.upsert_password(Uuid::new_v4(), &over).is_err());
}
