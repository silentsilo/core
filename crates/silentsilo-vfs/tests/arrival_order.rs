//! Records applied one at a time, in any order that respects what each
//! record's author had seen, must leave every device where replaying the
//! whole set in total order leaves it.
//!
//! The convergence test inside `oplog` hands a shuffled batch to `replay`,
//! which sorts it first, so it only ever checks the sorted order. Across sync
//! passes records arrive in whatever order storage lists them and devices
//! push them, and that is where trashing, restoring, renaming and password
//! edits diverged. This test applies each record on its own.

use rusqlite::Connection;
use silentsilo_vfs::{OpRecord, VaultOp, apply_op, init_schema, replay, root_folder_id_for};
use uuid::Uuid;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn uuid(&mut self) -> Uuid {
        Uuid::from_u64_pair(self.next(), self.next())
    }
}

fn device(vault: Uuid) -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    init_schema(&conn, vault).unwrap();
    conn
}

fn state(conn: &Connection) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut folders = conn
        .prepare("SELECT path, deleted_at FROM folders")
        .unwrap();
    out.extend(
        folders
            .query_map([], |r| {
                Ok(format!(
                    "folder {} deleted={:?}",
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<i64>>(1)?
                ))
            })
            .unwrap()
            .map(Result::unwrap),
    );
    let mut files = conn
        .prepare(
            "SELECT d.path, f.name, f.blob_id, f.blob_key, f.deleted_at
               FROM files f JOIN folders d ON d.id = f.folder_id",
        )
        .unwrap();
    out.extend(
        files
            .query_map([], |r| {
                Ok(format!(
                    "file {}/{} blob={} key={} deleted={:?}",
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<i64>>(4)?
                ))
            })
            .unwrap()
            .map(Result::unwrap),
    );
    let mut passwords = conn.prepare("SELECT id, data FROM passwords").unwrap();
    out.extend(
        passwords
            .query_map([], |r| {
                Ok(format!(
                    "password {} {}",
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?
                ))
            })
            .unwrap()
            .map(Result::unwrap),
    );
    out.sort();
    out
}

/// A batch from three devices, with small pools of names and ids so edits
/// meet. Each record also names the records it depends on: the creation of
/// anything it refers to, and the previous record of its own device.
fn batch(rng: &mut Rng, root: Uuid) -> Vec<(OpRecord, Vec<usize>)> {
    let devices: Vec<Uuid> = (0..3).map(|_| rng.uuid()).collect();
    let names = ["Docs", "docs", "Docs (2)", "x"];
    let mut folders: Vec<(Uuid, usize)> = Vec::new();
    // Each file with the records that wrote its content and their blobs, so
    // edits can build on an earlier edit as well as on the original.
    let mut files: Vec<(Uuid, Vec<(usize, Uuid)>)> = Vec::new();
    let mut last_of_device: Vec<Option<usize>> = vec![None; devices.len()];
    let mut lamports = vec![0u64; devices.len()];
    let mut out: Vec<(OpRecord, Vec<usize>)> = Vec::new();

    for i in 0..rng.below(30) + 10 {
        let d = rng.below(devices.len());
        let mut deps: Vec<usize> = last_of_device[d].into_iter().collect();
        let pick_folder = |rng: &mut Rng, deps: &mut Vec<usize>| -> Uuid {
            if folders.is_empty() || rng.below(3) == 0 {
                root
            } else {
                let (id, at) = folders[rng.below(folders.len())];
                deps.push(at);
                id
            }
        };
        let op = match rng.below(12) {
            0 | 1 => {
                let id = rng.uuid();
                let parent = pick_folder(rng, &mut deps);
                folders.push((id, i));
                VaultOp::CreateFolder {
                    id,
                    parent_id: parent,
                    name: names[rng.below(names.len())].into(),
                }
            }
            2 | 3 => {
                let id = rng.uuid();
                let blob = rng.uuid();
                let folder = pick_folder(rng, &mut deps);
                files.push((id, vec![(i, blob)]));
                VaultOp::AddFile {
                    id,
                    folder_id: folder,
                    name: format!("{}.txt", names[rng.below(names.len())]),
                    blob_id: blob,
                    size_bytes: 1,
                    content_hash: "h".into(),
                    mime_type: None,
                    blob_key: format!("key-{blob}"),
                }
            }
            4 | 11 if !files.is_empty() => {
                let f = rng.below(files.len());
                let (id, history) = files[f].clone();
                let (at, base) = history[rng.below(history.len())];
                deps.push(at);
                let blob = rng.uuid();
                files[f].1.push((i, blob));
                VaultOp::ReplaceFileContent {
                    id,
                    blob_id: blob,
                    size_bytes: 2,
                    content_hash: "h2".into(),
                    mime_type: None,
                    replaces: Some(base),
                    blob_key: format!("key-{blob}"),
                }
            }
            5 if !files.is_empty() => {
                let (id, history) = files[rng.below(files.len())].clone();
                deps.push(history[0].0);
                VaultOp::RenameFile {
                    id,
                    name: format!("{}.txt", names[rng.below(names.len())]),
                }
            }
            6 if !folders.is_empty() => {
                let (id, at) = folders[rng.below(folders.len())];
                deps.push(at);
                VaultOp::RenameFolder {
                    id,
                    name: names[rng.below(names.len())].into(),
                }
            }
            7 if !files.is_empty() => {
                let (id, history) = files[rng.below(files.len())].clone();
                deps.push(history[0].0);
                if rng.below(2) == 0 {
                    VaultOp::TrashFile { id }
                } else {
                    VaultOp::RestoreFile { id }
                }
            }
            8 if !folders.is_empty() => {
                let (id, at) = folders[rng.below(folders.len())];
                deps.push(at);
                if rng.below(2) == 0 {
                    VaultOp::TrashFolder { id }
                } else {
                    VaultOp::RestoreFolder { id }
                }
            }
            9 | 10 => {
                let id = Uuid::from_u128(1 + rng.below(3) as u128);
                if rng.below(3) == 0 {
                    VaultOp::DeletePassword { id }
                } else {
                    VaultOp::UpsertPassword {
                        id,
                        data: format!("sealed-{}", rng.next()),
                    }
                }
            }
            _ => {
                let id = rng.uuid();
                let parent = pick_folder(rng, &mut deps);
                folders.push((id, i));
                VaultOp::CreateFolder {
                    id,
                    parent_id: parent,
                    name: names[rng.below(names.len())].into(),
                }
            }
        };
        // A device's clock moves past what it depends on.
        let seen = deps.iter().map(|&k| out[k].0.lamport).max().unwrap_or(0);
        lamports[d] = lamports[d].max(seen) + 1 + rng.below(2) as u64;
        let record = OpRecord::authored(
            rng.uuid(),
            lamports[d],
            devices[d],
            1_700_000_000 + (i as i64) * 86_400,
            0,
            None,
            op,
        );
        last_of_device[d] = Some(i);
        deps.sort_unstable();
        deps.dedup();
        out.push((record, deps));
    }
    out
}

/// A random order in which every record comes after what it depends on.
fn arrival(rng: &mut Rng, records: &[(OpRecord, Vec<usize>)]) -> Vec<usize> {
    let mut done = vec![false; records.len()];
    let mut order = Vec::with_capacity(records.len());
    while order.len() < records.len() {
        let ready: Vec<usize> = (0..records.len())
            .filter(|&i| !done[i] && records[i].1.iter().all(|&d| done[d]))
            .collect();
        let pick = ready[rng.below(ready.len())];
        done[pick] = true;
        order.push(pick);
    }
    order
}

#[test]
fn records_applied_one_by_one_in_any_causal_order_converge() {
    let seeds: u64 = std::env::var("SILENTSILO_ARRIVAL_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(400);
    for seed in 0..seeds {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let vault = Uuid::from_u64_pair(seed, 7);
        let root = root_folder_id_for(vault);
        let records = batch(&mut rng, root);

        let reference = device(vault);
        replay(&reference, records.iter().map(|(r, _)| r.clone()).collect())
            .unwrap_or_else(|e| panic!("seed {seed}: sorted replay failed: {e}"));
        let expected = state(&reference);

        for attempt in 0..4 {
            let other = device(vault);
            for i in arrival(&mut rng, &records) {
                apply_op(&other, &records[i].0)
                    .unwrap_or_else(|e| panic!("seed {seed}, order {attempt}: apply failed: {e}"));
            }
            let got = state(&other);
            if got != expected {
                let missing: Vec<_> = expected.iter().filter(|r| !got.contains(r)).collect();
                let extra: Vec<_> = got.iter().filter(|r| !expected.contains(r)).collect();
                panic!(
                    "seed {seed}, order {attempt}: arrival order changed the result\n  sorted only: {missing:#?}\n  arrival only: {extra:#?}"
                );
            }
        }
    }
}
