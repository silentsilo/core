//! Two edits of one file made at once, received one pass apart.
//!
//! 1.0.0 builds the conflict copy for an edit that loses and arrives after
//! the winner from the winner's row, and takes the key from there: the copy
//! names the losing content under the winning content's key, and opening it
//! fails with "decryption failed". Nothing is lost, the records carry the
//! right key, but a 1.0.0 device cannot open that copy until it updates.
//! `mixed_fleet.rs` met it. This build pairs every row with its own key in
//! either order.

use rusqlite::Connection;
use silentsilo_vfs::{OpRecord, VaultOp};
use silentsilo_vfs_v1_0_0 as vfs_v1;
use uuid::Uuid;

fn records(vault_root: Uuid) -> (OpRecord, OpRecord, OpRecord) {
    let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
    let (file, original) = (Uuid::from_u128(10), Uuid::from_u128(20));
    let add = OpRecord::authored(
        Uuid::from_u128(100),
        1,
        a,
        0,
        0,
        None,
        VaultOp::AddFile {
            id: file,
            folder_id: vault_root,
            name: "report.txt".into(),
            blob_id: original,
            size_bytes: 1,
            content_hash: "h".into(),
            mime_type: None,
            blob_key: format!("key-{original}"),
        },
    );
    let edit = |op: u128, device: Uuid, seq: u64, blob: u128| {
        let blob = Uuid::from_u128(blob);
        OpRecord::authored(
            Uuid::from_u128(op),
            2,
            device,
            0,
            seq,
            None,
            VaultOp::ReplaceFileContent {
                id: file,
                blob_id: blob,
                size_bytes: 2,
                content_hash: format!("h{blob}"),
                mime_type: None,
                blob_key: format!("key-{blob}"),
                replaces: Some(original),
            },
        )
    };
    // Same Lamport value: B's edit sorts last and wins.
    (add, edit(101, a, 1, 21), edit(102, b, 0, 22))
}

fn db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    conn
}

/// Rows whose key is not their own blob's.
fn mismatched(conn: &Connection) -> Vec<String> {
    conn.prepare("SELECT name, blob_id, blob_key FROM files")
        .unwrap()
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .filter(|(_, blob, key)| *key != format!("key-{blob}"))
        .map(|(name, blob, key)| format!("{name}: blob {blob} under {key}"))
        .collect()
}

#[test]
fn a_losing_edit_received_after_the_winner_keeps_its_own_key() {
    let vault_id = Uuid::new_v4();
    let root = silentsilo_vfs::root_folder_id_for(vault_id);

    for loser_last in [true, false] {
        let (add, loser, winner) = records(root);
        let order = if loser_last {
            [add, winner, loser]
        } else {
            [add, loser, winner]
        };

        let new = db();
        silentsilo_vfs::init_schema(&new, vault_id).unwrap();
        let old = db();
        vfs_v1::init_schema(&old, vault_id).unwrap();
        for record in &order {
            silentsilo_vfs::apply_op(&new, record).unwrap();
            let bytes = record.to_bytes().unwrap();
            vfs_v1::apply_op(&old, &vfs_v1::OpRecord::from_bytes(&bytes).unwrap()).unwrap();
        }

        let count = |conn: &Connection| -> i64 {
            conn.query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(count(&new), 2, "the file and one conflict copy");
        assert_eq!(count(&old), 2);
        assert!(mismatched(&new).is_empty(), "{:?}", mismatched(&new));
        // Pinned, so this stays a statement about 1.0.0 and not a guess.
        assert_eq!(
            mismatched(&old).len(),
            usize::from(loser_last),
            "loser last {loser_last}: {:?}",
            mismatched(&old)
        );
    }
}
