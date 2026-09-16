//! Changes 1.0.0's own `Vfs` refuses, made on this build, must still write
//! records a 1.0.0 device applies.
//!
//! A 1.0.0 device stops replaying at a record it cannot apply and stays
//! there on every pass until it updates: it keeps pushing its own changes
//! and receives nothing after that record. A 1.0.0-only fleet reaches such a
//! record only when two devices change things at once. This build accepted
//! the change and wrote a record 1.0.0 refused, so it now writes the same
//! change with records 1.0.0 applies. `mixed_fleet.rs` met these cases.

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

/// Every record `new` holds, applied on `old`, which must then show the
/// same tree.
fn applies_on_1_0_0(old: &vault_v1::VaultSession, new: &VaultSession) {
    vfs_v1::replay(
        &old.conn,
        as_1_0_0(silentsilo_vfs::all_ops(&new.conn).unwrap()),
    )
    .expect("1.0.0 applies every record");
    assert_eq!(tree(&old.conn), tree(&new.conn));
}

#[test]
fn a_name_1_0_0_ranks_onto_a_file_already_called_that_is_written_as_shown() {
    let (old, new) = side_by_side();
    let vfs = Vfs::new(&new);
    let root = vfs.root_folder_id().unwrap();
    vfs.add_file(root, "a (2).txt", Uuid::new_v4(), 1, "h", None, "k")
        .unwrap();
    vfs.add_file(root, "A.txt", Uuid::new_v4(), 1, "h", None, "k")
        .unwrap();

    // This build skips the suffix another file asked for outright; 1.0.0
    // would rank it "a (2).txt", which is taken, so the record asks for the
    // name shown.
    let added = vfs
        .add_file(root, "a.txt", Uuid::new_v4(), 1, "h", None, "k")
        .unwrap();
    assert_eq!(added.name, "a (3).txt");
    applies_on_1_0_0(&old, &new);

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
fn asking_outright_for_a_suffix_a_1_0_0_rank_gave_renames_its_holder_first() {
    let (old, new) = side_by_side();
    // Written on 1.0.0: a second "x" ranked "X (2)".
    let (first, second) = {
        let vfs = vfs_v1::Vfs::new(&old);
        let root = vfs.root_folder_id().unwrap();
        let first = vfs.create_folder(root, "x").unwrap();
        let second = vfs.create_folder(root, "Y").unwrap();
        vfs.rename_folder(second.id, "X").unwrap();
        (first.id, second.id)
    };
    from_1_0_0(&old, &new);

    let vfs = Vfs::new(&new);
    let root = vfs.root_folder_id().unwrap();
    assert_eq!(vfs.get_folder(second).unwrap().name, "X (2)");
    let docs = vfs.create_folder(root, "Docs").unwrap();
    vfs.rename_folder(docs.id, "x (2)").unwrap();
    assert_eq!(vfs.get_folder(docs.id).unwrap().name, "x (2)");
    assert_eq!(vfs.get_folder(second).unwrap().name, "X (3)");
    assert_eq!(vfs.get_folder(first).unwrap().name, "x");
    applies_on_1_0_0(&old, &new);
}

#[test]
fn emptying_the_trash_moves_what_was_restored_out_of_a_trashed_folder_first() {
    let (old, new) = side_by_side();
    let vfs = Vfs::new(&new);
    let root = vfs.root_folder_id().unwrap();
    let folder = vfs.create_folder(root, "F").unwrap();
    let inner = vfs.create_folder(folder.id, "G").unwrap();
    let file = vfs
        .add_file(folder.id, "f.txt", Uuid::new_v4(), 1, "h", None, "k")
        .unwrap();
    vfs.add_file(inner.id, "g.txt", Uuid::new_v4(), 1, "h", None, "k")
        .unwrap();
    vfs.trash_folder(folder.id).unwrap();
    vfs.restore_file(file.id).unwrap();
    vfs.restore_folder(inner.id).unwrap();
    vfs.empty_trash().unwrap();

    // What was live is at the top, with its content; the rest is gone.
    let top = vfs.list_folder(root).unwrap();
    let names: Vec<String> = top
        .iter()
        .map(|e| match e {
            silentsilo_core::VaultEntry::Folder(f) => f.path.clone(),
            silentsilo_core::VaultEntry::File(f) => f.name.clone(),
        })
        .collect();
    assert_eq!(names, ["/G", "f.txt"]);
    assert!(vfs.list_trash().unwrap().is_empty());
    applies_on_1_0_0(&old, &new);

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

/// Records written on 1.0.0, applied on this build as a sync would.
fn from_1_0_0(old: &vault_v1::VaultSession, new: &VaultSession) {
    let written: Vec<silentsilo_vfs::OpRecord> = vfs_v1::all_ops(&old.conn)
        .unwrap()
        .iter()
        .map(|r| silentsilo_vfs::OpRecord::from_bytes(&r.to_bytes().unwrap()).unwrap())
        .collect();
    silentsilo_vfs::replay(&new.conn, written).unwrap();
}

#[test]
fn a_purge_leaves_1_0_0_names_ranked_as_here() {
    let (old, new) = side_by_side();
    // Written on 1.0.0: a second "a.txt" ranked "A (2).txt".
    let (gone, kept) = {
        let vfs = vfs_v1::Vfs::new(&old);
        let root = vfs.root_folder_id().unwrap();
        let gone = vfs
            .add_file(root, "a.txt", Uuid::new_v4(), 1, "h", None, "k")
            .unwrap();
        let kept = vfs
            .add_file(root, "A.txt", Uuid::new_v4(), 1, "h", None, "k")
            .unwrap();
        (gone.id, kept.id)
    };
    from_1_0_0(&old, &new);

    let vfs = Vfs::new(&new);
    let root = vfs.root_folder_id().unwrap();
    vfs.trash_file(gone).unwrap();
    vfs.empty_trash().unwrap();
    assert_eq!(vfs.get_file(kept).unwrap().name, "A.txt");
    applies_on_1_0_0(&old, &new);

    // 1.0.0 does not rank a group again on a purge, so without a rename it
    // kept "A (2).txt", and this name would then have met it.
    vfs.add_file(root, "A (2).txt", Uuid::new_v4(), 1, "h", None, "k")
        .unwrap();
    applies_on_1_0_0(&old, &new);
}

#[test]
fn a_purge_names_the_conflict_copies_it_takes_along() {
    // Which device's edit sorts first depends on the random device ids, and
    // only one order makes a copy 1.0.0 has and this build does not.
    for _ in 0..16 {
        purge_after_concurrent_edits();
    }
}

fn purge_after_concurrent_edits() {
    let (old, new) = side_by_side();
    let other = VaultSession {
        paths: silentsilo_vault::VaultPaths::new(PathBuf::from("unused")),
        conn: Connection::open_in_memory().unwrap(),
        vault_id: new.vault_id,
        dek: silentsilo_crypto::MasterDek::from_bytes(*new.dek.as_bytes()),
        kek: silentsilo_crypto::ContentKek::from_bytes(*new.kek.as_bytes()),
    };
    other.conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    Vfs::new(&other).ensure_initialized().unwrap();
    let exchange = |from: &VaultSession, to: &VaultSession| {
        silentsilo_vfs::replay(&to.conn, silentsilo_vfs::all_ops(&from.conn).unwrap()).unwrap();
    };

    let vfs = Vfs::new(&new);
    let root = vfs.root_folder_id().unwrap();
    let folder = vfs.create_folder(root, "F").unwrap();
    vfs.add_file(folder.id, "a.txt", Uuid::new_v4(), 1, "h", None, "k")
        .unwrap();
    exchange(&new, &other);
    // The same file edited on two devices at once, one of them twice. This
    // build keeps a copy of one side; 1.0.0 also copies the first edit.
    vfs.add_file(folder.id, "a.txt", Uuid::new_v4(), 2, "h2", None, "k")
        .unwrap();
    vfs.add_file(folder.id, "a.txt", Uuid::new_v4(), 4, "h4", None, "k")
        .unwrap();
    Vfs::new(&other)
        .add_file(folder.id, "a.txt", Uuid::new_v4(), 3, "h3", None, "k")
        .unwrap();
    exchange(&other, &new);
    assert_eq!(vfs.list_folder(folder.id).unwrap().len(), 2, "a copy");

    vfs.trash_folder(folder.id).unwrap();
    vfs.empty_trash().unwrap();
    applies_on_1_0_0(&old, &new);
}

#[test]
fn a_group_a_1_0_0_purge_left_unranked_refuses_every_rename_on_1_0_0_too() {
    // Records from three devices, the purge from one on 1.0.0, which writes
    // no rename after it. 1.0.0 then keeps "a (3).txt" and "A (4).txt"
    // where its ranking says "a (2).txt" and "A (3).txt", and "a (2).txt" is
    // another file's. Any claim that ranks the group again stops 1.0.0, a
    // rename made on it included, so no record this build writes for such
    // an entry can apply there. `mixed_fleet.rs` allows these refusals.
    let (old, new) = side_by_side();
    let root = silentsilo_vfs::root_folder_id_for(new.vault_id);
    let devices = [Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3)];
    let id = |n: u128| Uuid::from_u128(0x100 + n);
    let add = |n: u128, name: &str| silentsilo_vfs::VaultOp::AddFile {
        id: id(n),
        folder_id: root,
        name: name.into(),
        blob_id: Uuid::from_u128(0x200 + n),
        size_bytes: 1,
        content_hash: "h".into(),
        mime_type: None,
        blob_key: "k".into(),
    };
    let ops = [
        (2, 0, add(0, "notă.md")),
        (3, 1, add(1, "a (2).txt")),
        (5, 2, add(2, "A.txt")),
        (9, 2, add(3, "A.txt")),
        (
            11,
            1,
            silentsilo_vfs::VaultOp::RenameFile {
                id: id(0),
                name: "a.txt".into(),
            },
        ),
        (17, 2, add(4, "A.txt")),
        (
            36,
            1,
            silentsilo_vfs::VaultOp::Purge {
                folder_ids: Vec::new(),
                file_ids: vec![id(3)],
            },
        ),
    ];
    let mut seqs = [0u64; 3];
    let records: Vec<silentsilo_vfs::OpRecord> = ops
        .into_iter()
        .enumerate()
        .map(|(n, (lamport, device, op))| {
            seqs[device] += 1;
            silentsilo_vfs::OpRecord::authored(
                Uuid::from_u128(0x300 + n as u128),
                lamport,
                devices[device],
                0,
                seqs[device] - 1,
                None,
                op,
            )
        })
        .collect();
    silentsilo_vfs::replay(&new.conn, records.clone()).unwrap();
    for record in as_1_0_0(records) {
        vfs_v1::apply_op(&old.conn, &record).unwrap();
    }
    assert_eq!(tree(&old.conn), tree(&new.conn), "both show the same names");

    let old_vfs = vfs_v1::Vfs::new(&old);
    for name in ["a.txt", "a (4).txt", "b.txt"] {
        assert!(
            old_vfs.rename_file(id(4), name).is_err(),
            "1.0.0 renamed it to {name}"
        );
    }
}

// ── Guard: anything this build writes, 1.0.0 applies ────────────────

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn pick<T: Clone>(&mut self, items: &[T]) -> Option<T> {
        (!items.is_empty()).then(|| items[self.below(items.len())].clone())
    }
}

const FOLDER_NAMES: &[&str] = &["x", "X", "x (2)", "X (2)", "x (3)", "Docs"];
const FILE_NAMES: &[&str] = &["a.txt", "A.txt", "a (2).txt", "A (2).txt", "a (3).txt", "b"];

fn ids(conn: &Connection, sql: &str) -> Vec<Uuid> {
    conn.prepare(sql)
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|id| Uuid::parse_str(&id.unwrap()).unwrap())
        .collect()
}

/// Names and paths as a device shows them, for comparing the two versions.
fn tree(conn: &Connection) -> Vec<String> {
    let mut out: Vec<String> = conn
        .prepare(
            "SELECT 'folder ' || path || ' trashed=' || (deleted_at IS NOT NULL) FROM folders
             UNION ALL
             SELECT 'file ' || d.path || ' / ' || f.name || ' trashed=' || (f.deleted_at IS NOT NULL)
               FROM files f JOIN folders d ON d.id = f.folder_id",
        )
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    out.sort();
    out
}

/// One random change through this build's `Vfs`, described.
fn act(vfs: &Vfs, conn: &Connection, rng: &mut Rng) -> String {
    let live_folders = ids(
        conn,
        "SELECT id FROM folders WHERE deleted_at IS NULL ORDER BY id",
    );
    let movable_folders = ids(
        conn,
        "SELECT id FROM folders WHERE deleted_at IS NULL AND parent_id IS NOT NULL ORDER BY id",
    );
    let live_files = ids(
        conn,
        "SELECT id FROM files WHERE deleted_at IS NULL ORDER BY id",
    );
    let trashed_files = ids(
        conn,
        "SELECT id FROM files WHERE deleted_at IS NOT NULL ORDER BY id",
    );
    let trashed_folders = ids(
        conn,
        "SELECT id FROM folders WHERE deleted_at IS NOT NULL ORDER BY id",
    );
    let file_name = rng.pick(FILE_NAMES).unwrap();
    let folder_name = rng.pick(FOLDER_NAMES).unwrap();
    match rng.below(16) {
        0 | 1 => {
            let parent = rng.pick(&live_folders).unwrap();
            let r = vfs.create_folder(parent, folder_name).map(|f| f.name);
            format!("create folder {folder_name} in {parent}: {r:?}")
        }
        2..=4 => {
            let folder = rng.pick(&live_folders).unwrap();
            let r = vfs
                .add_file(folder, file_name, Uuid::new_v4(), 1, "h", None, "k")
                .map(|f| f.name);
            format!("add {file_name} in {folder}: {r:?}")
        }
        5 => {
            let Some(id) = rng.pick(&live_files) else {
                return "nothing".into();
            };
            let r = vfs.rename_file(id, file_name).map(|f| f.name);
            format!("rename file {id} to {file_name}: {r:?}")
        }
        6 => {
            let Some(id) = rng.pick(&movable_folders) else {
                return "nothing".into();
            };
            let r = vfs.rename_folder(id, folder_name).map(|f| f.name);
            format!("rename folder {id} to {folder_name}: {r:?}")
        }
        7 => {
            let (Some(id), Some(to)) = (rng.pick(&live_files), rng.pick(&live_folders)) else {
                return "nothing".into();
            };
            let r = vfs.move_file(id, to).map(|f| f.name);
            format!("move file {id} to {to}: {r:?}")
        }
        8 => {
            let (Some(id), Some(to)) = (rng.pick(&movable_folders), rng.pick(&live_folders)) else {
                return "nothing".into();
            };
            let r = vfs.move_folder(id, to).map(|f| f.path);
            format!("move folder {id} to {to}: {r:?}")
        }
        9 => {
            let Some(id) = rng.pick(&live_files) else {
                return "nothing".into();
            };
            format!("trash file {id}: {:?}", vfs.trash_file(id))
        }
        10 => {
            let Some(id) = rng.pick(&movable_folders) else {
                return "nothing".into();
            };
            format!("trash folder {id}: {:?}", vfs.trash_folder(id))
        }
        11 => {
            let Some(id) = rng.pick(&trashed_files) else {
                return "nothing".into();
            };
            format!(
                "restore file {id}: {:?}",
                vfs.restore_file(id).map(|f| f.name)
            )
        }
        12 => {
            let Some(id) = rng.pick(&trashed_folders) else {
                return "nothing".into();
            };
            format!(
                "restore folder {id}: {:?}",
                vfs.restore_folder(id).map(|f| f.path)
            )
        }
        13 => {
            if rng.below(3) == 0 {
                format!("empty trash: {:?}", vfs.empty_trash().map(|(n, _)| n))
            } else {
                let pool: Vec<Uuid> = trashed_files
                    .iter()
                    .chain(&trashed_folders)
                    .copied()
                    .collect();
                let chosen: Vec<Uuid> = (0..2).filter_map(|_| rng.pick(&pool)).collect();
                format!(
                    "purge {chosen:?}: {:?}",
                    vfs.purge_items(&chosen).map(|(n, _)| n)
                )
            }
        }
        14 => {
            let folder = rng.pick(&live_folders).unwrap();
            let r = vfs
                .record_imported_file(
                    Uuid::now_v7(),
                    folder,
                    file_name,
                    Uuid::new_v4(),
                    1,
                    "h",
                    None,
                    "k",
                )
                .map(|f| f.map(|f| f.name));
            format!("import {file_name} in {folder}: {r:?}")
        }
        _ => {
            let segments: Vec<String> = (0..1 + rng.below(2))
                .map(|_| rng.pick(FOLDER_NAMES).unwrap().to_string())
                .collect();
            let r = vfs.ensure_folder_path(&segments).map(|f| f.path);
            format!("folder path {segments:?}: {r:?}")
        }
    }
}

/// Random histories on one device of this build, each record handed to a
/// 1.0.0 database as soon as it is written. None may be refused, and the
/// two must show the same tree. `SILENTSILO_GUARD_SEEDS` sets how many.
#[test]
fn a_1_0_0_device_applies_every_record_this_build_writes() {
    let seeds: u64 = std::env::var("SILENTSILO_GUARD_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    for seed in 0..seeds {
        let (old, new) = side_by_side();
        let vfs = Vfs::new(&new);
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut applied = std::collections::HashSet::new();
        let mut history: Vec<String> = Vec::new();
        // The first step after which the two showed differently.
        let mut first_differ: Option<String> = None;
        for step in 0..80 {
            history.push(act(&vfs, &new.conn, &mut rng));
            let fresh: Vec<silentsilo_vfs::OpRecord> = silentsilo_vfs::all_ops(&new.conn)
                .unwrap()
                .into_iter()
                .filter(|r| applied.insert(r.op_id))
                .collect();
            let shown = format!("{:?}", fresh.iter().map(|r| &r.op).collect::<Vec<_>>());
            if let Err(e) = vfs_v1::replay(&old.conn, as_1_0_0(fresh)) {
                panic!(
                    "seed {seed}: 1.0.0 refused {shown}\n  {e}\n  after:\n    {}\n  differing since {first_differ:?}\n  1.0.0 had:\n    {}\n  this build has:\n    {}",
                    history.join("\n    "),
                    tree(&old.conn).join("\n    "),
                    tree(&new.conn).join("\n    "),
                );
            }
            let (a, b) = (tree(&old.conn), tree(&new.conn));
            if first_differ.is_none() && a != b {
                first_differ = Some(format!(
                    "step {step}: only on 1.0.0 {:?}, only here {:?}",
                    a.iter().filter(|l| !b.contains(l)).collect::<Vec<_>>(),
                    b.iter().filter(|l| !a.contains(l)).collect::<Vec<_>>(),
                ));
            }
        }
        // Both rank names alike, so both show the same tree.
        assert!(
            first_differ.is_none(),
            "seed {seed}: 1.0.0 shows a different tree from {first_differ:?}
  after:
    {}",
            history.join(
                "
    "
            )
        );
    }
}

#[test]
fn what_is_done_with_a_kept_edit_applies_on_1_0_0() {
    // B emptied a trash holding a.txt while A, not having that, edited it.
    // This build keeps A's edit as a file of its own and 1.0.0 drops it, so
    // what this build then writes about that file names an id 1.0.0 never
    // had.
    let (old, new) = side_by_side();
    let root = silentsilo_vfs::root_folder_id_for(new.vault_id);
    let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
    let file = Uuid::from_u128(0x100);
    let record = |n: u128, lamport, device, seq, op| {
        silentsilo_vfs::OpRecord::authored(
            Uuid::from_u128(0x300 + n),
            lamport,
            device,
            1_700_000_000,
            seq,
            None,
            op,
        )
    };
    let records = vec![
        record(
            0,
            1,
            b,
            0,
            silentsilo_vfs::VaultOp::AddFile {
                id: file,
                folder_id: root,
                name: "a.txt".into(),
                blob_id: Uuid::from_u128(0x200),
                size_bytes: 1,
                content_hash: "h".into(),
                mime_type: None,
                blob_key: "k".into(),
            },
        ),
        record(1, 2, b, 1, silentsilo_vfs::VaultOp::TrashFile { id: file }),
        record(
            2,
            3,
            b,
            2,
            silentsilo_vfs::VaultOp::Purge {
                folder_ids: Vec::new(),
                file_ids: vec![file],
            },
        ),
        record(
            3,
            3,
            a,
            0,
            silentsilo_vfs::VaultOp::ReplaceFileContent {
                id: file,
                blob_id: Uuid::from_u128(0x201),
                size_bytes: 2,
                content_hash: "h2".into(),
                mime_type: None,
                blob_key: "k2".into(),
                replaces: Some(Uuid::from_u128(0x200)),
            },
        ),
    ];
    silentsilo_vfs::replay(&new.conn, records.clone()).unwrap();
    vfs_v1::replay(&old.conn, as_1_0_0(records)).unwrap();

    let vfs = Vfs::new(&new);
    let top = vfs.list_folder(root).unwrap();
    let [silentsilo_core::VaultEntry::File(kept)] = top.as_slice() else {
        panic!("one kept file: {top:?}")
    };
    assert_eq!(kept.name, "a (conflicted copy 2023-11-14).txt");

    // Named over, renamed, another file given its old name, moved, and the
    // trash emptied: each record applies on 1.0.0, and the trees meet again.
    vfs.add_file(root, &kept.name, Uuid::new_v4(), 3, "h3", None, "k3")
        .unwrap();
    vfs.rename_file(kept.id, "b.txt").unwrap();
    vfs.add_file(
        root,
        "a (conflicted copy 2023-11-14).txt",
        Uuid::new_v4(),
        1,
        "h",
        None,
        "k",
    )
    .unwrap();
    let folder = vfs.create_folder(root, "F").unwrap();
    vfs.move_file(kept.id, folder.id).unwrap();
    vfs.empty_trash().unwrap();
    applies_on_1_0_0(&old, &new);
}
