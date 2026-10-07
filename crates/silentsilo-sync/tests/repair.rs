//! Repairing a copy from a good one: what a content check found missing or
//! damaged is put back from another copy, only once that copy proves it
//! holds the object whole, and nothing that is sound is rewritten.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use silentsilo_crypto::{ContentKey, MasterDek, encrypt_file, generate_content_key, generate_dek};
use silentsilo_store::{FolderStore, ObjectStore};
use silentsilo_sync::{
    BLOBS_PREFIX, OPS_PREFIX, VerifyDepth, VerifyReport, push_ops, repair_from, verify_against,
};
use silentsilo_vfs::{OpRecord, VaultOp};
use uuid::Uuid;

fn record(lamport: u64, device_id: Uuid) -> OpRecord {
    OpRecord::authored(
        Uuid::new_v4(),
        lamport,
        device_id,
        1_700_000_000,
        lamport,
        None,
        VaultOp::CreateFolder {
            id: Uuid::new_v4(),
            parent_id: Uuid::new_v4(),
            name: format!("folder-{lamport}"),
        },
    )
}

struct Silo {
    dek: MasterDek,
    expected: HashSet<Uuid>,
    keys: HashMap<Uuid, ContentKey>,
    blobs: Vec<Uuid>,
}

/// Three records and three blobs, written to `dir`.
async fn populate(dir: &Path) -> Silo {
    let store = FolderStore::new(dir.to_path_buf());
    let dek = generate_dek();
    let device = Uuid::new_v4();
    let records: Vec<OpRecord> = (1..=3).map(|l| record(l, device)).collect();
    push_ops(&store, &dek, &records).await.unwrap();
    let mut silo = Silo {
        dek,
        expected: HashSet::new(),
        keys: HashMap::new(),
        blobs: Vec::new(),
    };
    for i in 0..3u8 {
        let blob_id = Uuid::new_v4();
        let scratch = tempfile::tempdir().unwrap();
        let plain = scratch.path().join("p.bin");
        let enc = scratch.path().join("b.sslo");
        std::fs::write(&plain, vec![i; 70_000]).unwrap();
        let key = generate_content_key();
        encrypt_file(&plain, &enc, &key, Uuid::new_v4(), blob_id).unwrap();
        store
            .put(&blob_key(blob_id), std::fs::read(&enc).unwrap())
            .await
            .unwrap();
        silo.expected.insert(blob_id);
        silo.keys.insert(blob_id, key);
        silo.blobs.push(blob_id);
    }
    silo
}

fn blob_key(id: Uuid) -> String {
    format!("{BLOBS_PREFIX}{id}.sslo")
}

/// A second copy holding the same objects, byte for byte.
fn copy_dir(from: &Path, to: &Path) {
    for entry in walk(from) {
        let rel = entry.strip_prefix(from).unwrap();
        let dest = to.join(rel);
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::copy(&entry, &dest).unwrap();
    }
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// Every file under `dir`, with its bytes.
fn snapshot(dir: &Path) -> HashMap<std::path::PathBuf, Vec<u8>> {
    walk(dir)
        .into_iter()
        .map(|p| {
            (
                p.strip_prefix(dir).unwrap().to_path_buf(),
                std::fs::read(&p).unwrap(),
            )
        })
        .collect()
}

fn first_op(dir: &Path) -> std::path::PathBuf {
    let mut ops = walk(&dir.join(OPS_PREFIX.trim_end_matches('/')));
    ops.sort();
    ops.remove(0)
}

async fn check(store: &FolderStore, silo: &Silo) -> VerifyReport {
    let keys = silo.keys.clone();
    verify_against(
        store,
        &silo.dek,
        &silo.expected,
        VerifyDepth::Content,
        &mut move |id| keys.get(&id).cloned(),
        &mut |_, _| {},
        &|| false,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn rot_a_cut_upload_a_lost_file_and_a_broken_record_are_put_back() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let silo = populate(a_dir.path()).await;
    copy_dir(a_dir.path(), b_dir.path());
    let b_before = snapshot(b_dir.path());

    // A bit rots in one blob, another upload stopped half way, a third file
    // is gone, and one record is garbled.
    let rotted = a_dir.path().join(blob_key(silo.blobs[0]));
    let mut bytes = std::fs::read(&rotted).unwrap();
    bytes[500] ^= 0x01;
    std::fs::write(&rotted, bytes).unwrap();
    let cut = a_dir.path().join(blob_key(silo.blobs[1]));
    let half = std::fs::read(&cut).unwrap();
    std::fs::write(&cut, &half[..half.len() / 2]).unwrap();
    std::fs::remove_file(a_dir.path().join(blob_key(silo.blobs[2]))).unwrap();
    std::fs::write(first_op(a_dir.path()), b"not a record").unwrap();

    let a = FolderStore::new(a_dir.path().to_path_buf());
    let b = FolderStore::new(b_dir.path().to_path_buf());
    let found = check(&a, &silo).await;
    assert_eq!(found.missing.len() + found.damaged.len(), 4, "{found:?}");

    let keys = silo.keys.clone();
    let repaired = repair_from(
        &a,
        &found,
        &[("copy B", &b as &dyn ObjectStore)],
        &silo.dek,
        &mut move |id| keys.get(&id).cloned(),
        &|| false,
    )
    .await
    .unwrap();

    assert_eq!(repaired.repaired.len(), 4, "{repaired:?}");
    assert!(repaired.unrepaired.is_empty(), "{repaired:?}");
    assert!(check(&a, &silo).await.is_sound(), "A reads whole again");
    assert_eq!(snapshot(b_dir.path()), b_before, "the source is only read");
}

#[tokio::test]
async fn nothing_is_written_when_no_source_holds_the_object_whole() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let silo = populate(a_dir.path()).await;
    copy_dir(a_dir.path(), b_dir.path());

    // The same blob rotted on both copies, differently.
    for (dir, byte) in [(a_dir.path(), 500), (b_dir.path(), 900)] {
        let path = dir.join(blob_key(silo.blobs[0]));
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[byte] ^= 0x01;
        std::fs::write(&path, bytes).unwrap();
    }
    let a_before = snapshot(a_dir.path());

    let a = FolderStore::new(a_dir.path().to_path_buf());
    let b = FolderStore::new(b_dir.path().to_path_buf());
    let found = check(&a, &silo).await;
    let keys = silo.keys.clone();
    let repaired = repair_from(
        &a,
        &found,
        &[("copy B", &b as &dyn ObjectStore)],
        &silo.dek,
        &mut move |id| keys.get(&id).cloned(),
        &|| false,
    )
    .await
    .unwrap();

    assert!(repaired.repaired.is_empty(), "{repaired:?}");
    assert_eq!(repaired.unrepaired.len(), 1, "{repaired:?}");
    assert_eq!(
        snapshot(a_dir.path()),
        a_before,
        "A is left exactly as it was"
    );
}

#[tokio::test]
async fn a_record_moved_under_another_name_is_not_a_source() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let silo = populate(a_dir.path()).await;
    copy_dir(a_dir.path(), b_dir.path());

    // On B, the first record's name now holds the second record: sealed,
    // valid, and the wrong one.
    let mut b_ops = walk(&b_dir.path().join("ops"));
    b_ops.sort();
    std::fs::copy(&b_ops[1], &b_ops[0]).unwrap();
    std::fs::write(first_op(a_dir.path()), b"not a record").unwrap();

    let a = FolderStore::new(a_dir.path().to_path_buf());
    let b = FolderStore::new(b_dir.path().to_path_buf());
    let found = check(&a, &silo).await;
    let keys = silo.keys.clone();
    let repaired = repair_from(
        &a,
        &found,
        &[("copy B", &b as &dyn ObjectStore)],
        &silo.dek,
        &mut move |id| keys.get(&id).cloned(),
        &|| false,
    )
    .await
    .unwrap();

    assert!(repaired.repaired.is_empty(), "{repaired:?}");
    assert_eq!(
        std::fs::read(first_op(a_dir.path())).unwrap(),
        b"not a record",
        "the wrong record was not copied in"
    );
}

#[tokio::test]
async fn an_object_that_is_sound_again_is_left_alone() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let silo = populate(a_dir.path()).await;
    copy_dir(a_dir.path(), b_dir.path());

    // Found damaged, then put right by something else before the repair.
    let path = a_dir.path().join(blob_key(silo.blobs[0]));
    let good = std::fs::read(&path).unwrap();
    let mut bad = good.clone();
    bad[500] ^= 0x01;
    std::fs::write(&path, &bad).unwrap();
    let a = FolderStore::new(a_dir.path().to_path_buf());
    let b = FolderStore::new(b_dir.path().to_path_buf());
    let found = check(&a, &silo).await;
    std::fs::write(&path, &good).unwrap();

    let keys = silo.keys.clone();
    let repaired = repair_from(
        &a,
        &found,
        &[("copy B", &b as &dyn ObjectStore)],
        &silo.dek,
        &mut move |id| keys.get(&id).cloned(),
        &|| false,
    )
    .await
    .unwrap();

    assert_eq!(repaired.already_sound, vec![blob_key(silo.blobs[0])]);
    assert!(repaired.repaired.is_empty());
}
