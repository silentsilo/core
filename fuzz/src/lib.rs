//! What the targets share: a valid object to start from, and a way to turn
//! the input into either raw bytes or edits to that object. Raw bytes rarely
//! get past a magic number or a JSON key; edits reach the code behind them.

use std::sync::OnceLock;

use silentsilo_crypto::{ContentKey, MasterDek};
use uuid::Uuid;

pub const DEK: [u8; 32] = [7; 32];
pub const CONTENT_KEY: [u8; 32] = [3; 32];
pub const BLOB_ID: Uuid = Uuid::from_u128(1);

/// An odd first byte makes the rest edits to `valid`: each three bytes
/// overwrite one byte at a little-endian offset, and one or two bytes left
/// over cut the result to that length. Otherwise the rest is used as is.
pub fn shaped(valid: &[u8], data: &[u8]) -> Vec<u8> {
    let Some((mode, rest)) = data.split_first() else {
        return Vec::new();
    };
    if mode & 1 == 0 {
        return rest.to_vec();
    }
    let mut out = valid.to_vec();
    let edits = rest.chunks_exact(3);
    let tail = edits.remainder();
    for edit in edits {
        if !out.is_empty() {
            let at = u16::from_le_bytes([edit[0], edit[1]]) as usize % out.len();
            out[at] = edit[2];
        }
    }
    if !tail.is_empty() {
        let len = tail.iter().fold(0usize, |n, b| n << 8 | *b as usize);
        out.truncate(len % (out.len() + 1));
    }
    out
}

pub fn dek() -> MasterDek {
    MasterDek::from_bytes(DEK)
}

pub fn content_key() -> ContentKey {
    ContentKey::from_bytes(CONTENT_KEY)
}

/// A scratch folder for the life of the process.
pub fn scratch() -> &'static std::path::Path {
    static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    DIR.get_or_init(|| tempfile::tempdir().unwrap()).path()
}

/// A real `.sslo` blob of a little over two chunks.
pub fn valid_blob() -> &'static [u8] {
    static BLOB: OnceLock<Vec<u8>> = OnceLock::new();
    BLOB.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        let sealed = dir.path().join("sealed");
        std::fs::write(&plain, vec![0x5a; 2 * silentsilo_crypto::CHUNK_SIZE + 100]).unwrap();
        silentsilo_crypto::encrypt_file(&plain, &sealed, &content_key(), Uuid::from_u128(2), BLOB_ID)
            .unwrap();
        std::fs::read(sealed).unwrap()
    })
}

/// Records and a snapshot from a silo with a folder, a file and a password.
pub struct Silo {
    pub records: Vec<Vec<u8>>,
    pub snapshot: Vec<u8>,
}

pub fn valid_silo() -> &'static Silo {
    static SILO: OnceLock<Silo> = OnceLock::new();
    SILO.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let vault_id = Uuid::from_u128(0x5170);
        let session =
            silentsilo_vault::VaultSession::provision(dir.path().join("silo"), vault_id, "fuzz")
                .unwrap();
        let vfs = silentsilo_vfs::Vfs::new(&session);
        vfs.ensure_initialized().unwrap();
        let root = silentsilo_vfs::root_folder_id_for(vault_id);
        let folder = vfs.create_folder(root, "Docs").unwrap();
        vfs.rename_folder(folder.id, "Papers").unwrap();
        vfs.upsert_password(
            Uuid::from_u128(9),
            r#"{"id":"00000000-0000-0000-0000-000000000009","service":"site","username":"a","password":"b","url":"","notes":"","category":"General","created_at":0,"updated_at":0,"type":"login"}"#,
        )
        .unwrap();
        vfs.trash_folder(folder.id).unwrap();
        let ops = silentsilo_vfs::all_ops(&session.conn).unwrap();
        let records = ops.iter().map(|r| r.to_bytes().unwrap()).collect();
        // Below the last record: a snapshot needs something left above it.
        let highest = ops.iter().map(|r| r.lamport).max().unwrap();
        let snapshot = silentsilo_vfs::snapshot::capture_at(&session.conn, vault_id, highest - 1)
            .unwrap()
            .to_bytes()
            .unwrap();
        Silo { records, snapshot }
    })
}
