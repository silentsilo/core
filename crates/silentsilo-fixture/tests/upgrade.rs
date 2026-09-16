//! A long history written by 1.0.0, read by this build.
//!
//! One device's log, produced through the 1.0.0 `Vfs` the shipped app used,
//! then read three ways: by 1.0.0 as it wrote it, by this build replaying
//! the same records into an empty database, and by this build opening the
//! 1.0.0 database itself, which drops the schema 1 tables and rebuilds them
//! on first unlock after the update. The two readings by this build must be
//! identical, and must match 1.0.0 except where this build deliberately
//! differs: names re-ranked, and entries 1.0.0 misplaced in the trash by
//! folding ASCII case. `compare_with_1_0_0` says exactly what is allowed.
//!
//! `SILENTSILO_UPGRADE_SEED` replays one seed. The rebuild benchmark is
//! ignored by default: `cargo test -p silentsilo-fixture --release --test
//! upgrade -- --ignored --nocapture`, sized by `SILENTSILO_UPGRADE_RECORDS`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::Connection;
use silentsilo_vault_v1_0_0 as vault_v1;
use silentsilo_vfs_v1_0_0 as vfs_v1;
use uuid::Uuid;

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

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

/// Names that collide by case, by a suffix the ranking produces, and by
/// Unicode spelling (the second "Școală" and "notă" are decomposed).
const FOLDER_NAMES: &[&str] = &[
    "Docs",
    "docs",
    "Photos",
    "x",
    "X",
    "x (2)",
    "Școală",
    "S\u{0326}coala\u{0306}",
];
/// The same without folders that differ only in ASCII case, which 1.0.0
/// mishandled (see [`case_folded_subtrees`]): with these the trash must match
/// exactly.
const FOLDER_NAMES_ONE_CASE: &[&str] = &[
    "Docs",
    "Photos",
    "x",
    "x (2)",
    "Școală",
    "S\u{0326}coala\u{0306}",
];
const FILE_NAMES: &[&str] = &[
    "a.txt",
    "A.txt",
    "a (2).txt",
    "report.pdf",
    "notă.md",
    "nota\u{0306}.md",
];

/// A database the way the app opens its working copy.
fn open_db(path: &Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA busy_timeout=5000;
         PRAGMA foreign_keys=ON;",
    )
    .unwrap();
    conn
}

fn ids(conn: &Connection, sql: &str) -> Vec<Uuid> {
    conn.prepare(sql)
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|id| Uuid::parse_str(&id.unwrap()).unwrap())
        .collect()
}

/// A 1.0.0 session over a database file, with nothing else of a silo on
/// disk: the `Vfs` needs the connection and the keys, and nothing here
/// touches the machine's work directory.
fn old_session(dir: &Path, vault_id: Uuid) -> vault_v1::VaultSession {
    let session = vault_v1::VaultSession {
        paths: vault_v1::VaultPaths::new(dir.join("silo")),
        conn: open_db(&dir.join("vault.db")),
        vault_id,
        dek: silentsilo_crypto_v1_0_0::generate_dek(),
        kek: silentsilo_crypto_v1_0_0::generate_content_kek(),
    };
    vfs_v1::Vfs::new(&session).ensure_initialized().unwrap();
    session
}

/// Drives the 1.0.0 `Vfs` until the log holds `records` records. Returns
/// every entry 1.0.0's case folding reached at some point (see
/// [`case_folded_subtrees`]).
fn write_history(
    session: &vault_v1::VaultSession,
    seed: u64,
    records: usize,
    folder_names: &[&str],
) -> HashSet<String> {
    let vfs = vfs_v1::Vfs::new(session);
    let conn = &session.conn;
    let mut rng = Rng::new(seed);
    let mut folded = HashSet::new();
    let count = |conn: &Connection| -> usize {
        conn.query_row("SELECT COUNT(*) FROM oplog", [], |r| r.get::<_, i64>(0))
            .unwrap() as usize
    };
    // Counted every few steps: a count per step is most of the cost.
    let mut step = 0usize;
    while !step.is_multiple_of(16) || count(conn) < records {
        step += 1;
        folded.extend(case_folded_subtrees(conn));
        let live_folders = ids(conn, "SELECT id FROM folders WHERE deleted_at IS NULL");
        let pick_live_folder = |rng: &mut Rng| rng.pick(&live_folders).unwrap();
        match rng.below(100) {
            0..=11 => {
                // Deep trees: a new folder under a recent one half the time.
                let parent = if rng.below(2) == 0 {
                    live_folders[live_folders.len() - 1 - rng.below(live_folders.len().min(4))]
                } else {
                    pick_live_folder(&mut rng)
                };
                let _ = vfs.create_folder(parent, rng.pick(folder_names).unwrap());
            }
            12..=36 => {
                // Over a live name this is a replace, as the app did.
                let folder = pick_live_folder(&mut rng);
                let blob = Uuid::from_u64_pair(rng.next(), rng.next());
                let _ = vfs.add_file(
                    folder,
                    rng.pick(FILE_NAMES).unwrap(),
                    blob,
                    rng.below(1 << 20) as i64,
                    &format!("{:016x}", rng.next()),
                    Some("text/plain"),
                    &format!("key-{blob}"),
                );
            }
            37..=43 => {
                let files = ids(conn, "SELECT id FROM files WHERE deleted_at IS NULL");
                if let Some(id) = rng.pick(&files) {
                    let _ = vfs.rename_file(id, rng.pick(FILE_NAMES).unwrap());
                }
            }
            44..=48 => {
                let folders = ids(
                    conn,
                    "SELECT id FROM folders WHERE deleted_at IS NULL AND parent_id IS NOT NULL",
                );
                if let Some(id) = rng.pick(&folders) {
                    let _ = vfs.rename_folder(id, rng.pick(folder_names).unwrap());
                }
            }
            49..=53 => {
                // A move as 1.0.0 could make one: the same bytes imported
                // again elsewhere, the original sent to the trash.
                let files: Vec<(String, String, i64, String)> = conn
                    .prepare(
                        "SELECT id, name, size_bytes, content_hash
                           FROM files WHERE deleted_at IS NULL",
                    )
                    .unwrap()
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                    .unwrap()
                    .map(Result::unwrap)
                    .collect();
                if let Some((id, name, size, hash)) = rng.pick(&files) {
                    let to = pick_live_folder(&mut rng);
                    let blob = Uuid::from_u64_pair(rng.next(), rng.next());
                    let key = format!("key-{blob}");
                    if vfs
                        .add_file(to, &name, blob, size, &hash, Some("text/plain"), &key)
                        .is_ok()
                    {
                        let _ = vfs.trash_file(Uuid::parse_str(&id).unwrap());
                    }
                }
            }
            54..=61 => {
                let files = ids(conn, "SELECT id FROM files WHERE deleted_at IS NULL");
                if let Some(id) = rng.pick(&files) {
                    let _ = vfs.trash_file(id);
                }
            }
            62..=66 => {
                let folders = ids(
                    conn,
                    "SELECT id FROM folders WHERE deleted_at IS NULL AND parent_id IS NOT NULL",
                );
                if let Some(id) = rng.pick(&folders) {
                    let _ = vfs.trash_folder(id);
                }
            }
            67..=71 => {
                let files = ids(conn, "SELECT id FROM files WHERE deleted_at IS NOT NULL");
                if let Some(id) = rng.pick(&files) {
                    let _ = vfs.restore_file(id);
                }
            }
            72..=75 => {
                let folders = ids(conn, "SELECT id FROM folders WHERE deleted_at IS NOT NULL");
                if let Some(id) = rng.pick(&folders) {
                    let _ = vfs.restore_folder(id);
                }
            }
            76..=79 => {
                // Deleting a few things for good from the trash.
                let trashed = ids(
                    conn,
                    "SELECT id FROM files WHERE deleted_at IS NOT NULL
                     UNION ALL SELECT id FROM folders WHERE deleted_at IS NOT NULL",
                );
                let chosen: Vec<Uuid> = (0..1 + rng.below(3))
                    .filter_map(|_| rng.pick(&trashed))
                    .collect();
                let _ = vfs.purge_items(&chosen);
            }
            80 => {
                let _ = vfs.empty_trash();
            }
            81..=84 => {
                let files = ids(conn, "SELECT id FROM files WHERE deleted_at IS NULL");
                if let Some(id) = rng.pick(&files) {
                    let _ = vfs.set_file_favorite(id, rng.below(2) == 0);
                }
                let folders = ids(
                    conn,
                    "SELECT id FROM folders WHERE deleted_at IS NULL AND parent_id IS NOT NULL",
                );
                if let Some(id) = rng.pick(&folders) {
                    let _ = vfs.set_folder_favorite(id, rng.below(2) == 0);
                }
            }
            85..=95 => {
                let id = Uuid::from_u128(1 + rng.below(12) as u128);
                let entry = serde_json::json!({
                    "id": id.to_string(),
                    "service": format!("site-{}", rng.below(5)),
                    "username": "alex",
                    "password": format!("pw-{}", rng.next()),
                    "url": "", "notes": "", "category": "General",
                    "created_at": 0, "updated_at": step, "type": "login",
                });
                vfs.upsert_password(id, &entry.to_string()).unwrap();
            }
            _ => {
                let id = Uuid::from_u128(1 + rng.below(12) as u128);
                vfs.delete_password(id).unwrap();
            }
        }
    }
    folded.extend(case_folded_subtrees(conn));
    folded
}

/// Folders whose stored path is not their parent's path and their own name.
fn stale_folders(conn: &Connection) -> Vec<String> {
    let folders: HashMap<String, (Option<String>, String, String)> = conn
        .prepare("SELECT id, parent_id, name, path FROM folders")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?, r.get(3)?))))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut stale = Vec::new();
    for (id, (parent, name, path)) in &folders {
        let expected = match parent {
            None => "/".to_string(),
            Some(parent) => format!("{}/{name}", folders[parent].2.trim_end_matches('/')),
        };
        if path != &expected {
            stale.push(id.clone());
        }
    }
    stale
}

/// A 1.0.0 bug this build repairs, and what it leaves behind. 1.0.0 found a
/// folder's subtree with `LIKE`, which folds ASCII case. Trashing, restoring
/// or renaming "x" also reached below a sibling "X", and renaming "X (2)"
/// rewrote the paths below "x (2)", which then kept a stale path that later
/// trashing and restoring of their real parent missed. So 1.0.0 can show an
/// entry live inside a trashed folder, or trashed inside a live one. This
/// build finds a subtree by id, and after the update such entries follow
/// their own folders; a star 1.0.0 set on one it wrongly thought live did
/// not land either. Returns every folder with a stale path or with an
/// ancestor path that a sibling spells in another case, everything below
/// them, and their files, as picture keys.
fn case_folded_subtrees(conn: &Connection) -> Vec<String> {
    let mut reached = stale_folders(conn);
    let paths: Vec<(String, String)> = conn
        .prepare("SELECT id, path FROM folders")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut spellings: HashMap<String, HashSet<&str>> = HashMap::new();
    for (_, path) in &paths {
        spellings
            .entry(path.to_ascii_lowercase())
            .or_default()
            .insert(path);
    }
    for (id, path) in &paths {
        let exposed = path.match_indices('/').skip(1).any(|(at, _)| {
            let prefix = &path[..at];
            spellings[&prefix.to_ascii_lowercase()]
                .iter()
                .any(|other| *other != prefix)
        });
        if exposed {
            reached.push(id.clone());
        }
    }
    if reached.is_empty() {
        return reached;
    }
    let parents: Vec<(String, Option<String>)> = conn
        .prepare("SELECT id, parent_id FROM folders")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut below: HashSet<String> = reached.into_iter().collect();
    loop {
        let before = below.len();
        for (id, parent) in &parents {
            if parent.as_ref().is_some_and(|p| below.contains(p)) {
                below.insert(id.clone());
            }
        }
        if below.len() == before {
            break;
        }
    }
    let files: Vec<String> = conn
        .prepare("SELECT id, folder_id FROM files")
        .unwrap()
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .filter(|(_, folder)| below.contains(folder))
        .map(|(id, _)| format!("file:{id}"))
        .collect();
    below
        .into_iter()
        .map(|id| format!("folder:{id}"))
        .chain(files)
        .collect()
}

/// One row of what a user sees, by entry id, in the three parts the
/// comparison with 1.0.0 treats differently.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    name: String,
    /// Place, content and key, or a password's sealed entry.
    fixed: String,
    /// When it went to the trash, and whether it is starred.
    trash: String,
}

/// The tree, the trash, stars and passwords, keyed by entry id. Paths are
/// made of names, so they are checked rather than compared: this build must
/// never hold a stale one.
fn picture(conn: &Connection) -> BTreeMap<String, Row> {
    let stale = stale_folders(conn);
    assert!(stale.is_empty(), "stale folder paths: {stale:#?}");
    picture_as_stored(conn)
}

fn picture_as_stored(conn: &Connection) -> BTreeMap<String, Row> {
    let text = |v: rusqlite::types::ValueRef<'_>| match v {
        rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
        other => format!("{other:?}"),
    };
    // Key, name, the fixed columns, then the two trash columns.
    let queries = [
        (
            "SELECT 'folder:' || id, name, parent_id, deleted_at, favorite FROM folders",
            1,
        ),
        (
            "SELECT 'file:' || id, name, folder_id, blob_id, blob_key, size_bytes,
                    content_hash, mime_type, deleted_at, favorite FROM files",
            6,
        ),
        (
            "SELECT 'password:' || id, '', data, '', '' FROM passwords",
            1,
        ),
    ];
    let mut out = BTreeMap::new();
    for (sql, fixed) in queries {
        let mut stmt = conn.prepare(sql).unwrap();
        let rows: Vec<(String, Row)> = stmt
            .query_map([], |r| {
                let join = |columns: std::ops::Range<usize>| {
                    columns
                        .map(|i| text(r.get_ref(i).unwrap()))
                        .collect::<Vec<_>>()
                        .join(" | ")
                };
                Ok((
                    text(r.get_ref(0)?),
                    Row {
                        name: text(r.get_ref(1)?),
                        fixed: join(2..2 + fixed),
                        trash: join(2 + fixed..4 + fixed),
                    },
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        out.extend(rows);
    }
    out
}

/// Strips one " (n)" rank suffix, before the extension for a file.
fn without_rank(name: &str, is_folder: bool) -> Option<String> {
    let (stem, ext) = match name.rfind('.') {
        Some(dot) if !is_folder && dot > 0 => name.split_at(dot),
        _ => (name, ""),
    };
    let inner = stem.strip_suffix(')')?;
    let open = inner.rfind(" (")?;
    let digits = &inner[open + 2..];
    (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| format!("{}{ext}", &inner[..open]))
}

/// A name group: the folder, files or folders, and the folded name asked for.
type Group = (Uuid, bool, String);

/// The name groups this build ranks differently from 1.0.0, and the group
/// each entry's last claim put it in.
fn reranked_groups(log: &[silentsilo_vfs::OpRecord]) -> (HashSet<Group>, HashMap<Uuid, Group>) {
    use silentsilo_vfs::{OpBody, VaultOp, names::fold, sanitize_name};
    let mut claims: HashMap<Uuid, Group> = HashMap::new();
    let mut disturbed = HashSet::new();
    let mut sorted: Vec<_> = log.iter().collect();
    sorted.sort_by_key(|r| r.sort_key());
    for record in sorted {
        let OpBody::Known(op) = &record.op else {
            continue;
        };
        let claim = |scope: Uuid, is_folder: bool, name: &str| {
            (scope, is_folder, fold(&sanitize_name(name)))
        };
        match op {
            VaultOp::CreateFolder {
                id,
                parent_id,
                name,
            } => {
                claims.insert(*id, claim(*parent_id, true, name));
            }
            VaultOp::AddFile {
                id,
                folder_id,
                name,
                ..
            } => {
                claims.insert(*id, claim(*folder_id, false, name));
            }
            VaultOp::RenameFolder { id, name } | VaultOp::RenameFile { id, name } => {
                if let Some((scope, is_folder, _)) = claims.get(id).cloned() {
                    claims.insert(*id, claim(scope, is_folder, name));
                }
            }
            VaultOp::Purge {
                folder_ids,
                file_ids,
            } => {
                for id in file_ids.iter().chain(folder_ids) {
                    if let Some(group) = claims.remove(id) {
                        if let Some(base) = without_rank(&group.2, group.1) {
                            disturbed.insert((group.0, group.1, base));
                        }
                        disturbed.insert(group);
                    }
                }
            }
            _ => {}
        }
    }
    // Groups whose suffixed names another entry asked for outright.
    for (scope, is_folder, key) in claims.values() {
        if let Some(base) = without_rank(key, *is_folder) {
            disturbed.insert((*scope, *is_folder, base));
        }
    }
    (disturbed, claims)
}

/// What this build shows differently from 1.0.0, by reason.
#[derive(Debug, Default)]
struct Differences {
    /// Entries named by the new ranking.
    reranked: usize,
    /// Entries whose trash state or star 1.0.0 had wrong.
    repaired: usize,
}

/// Compares what 1.0.0 shows with what this build shows. Three differences
/// are intended, and nothing else may differ.
///
/// Two are changes to ranking that make names the same on every device
/// whatever order records arrive in:
///
/// - when a purge takes a member from a name group, this build ranks the
///   rest again, so "report (2).pdf" becomes "report.pdf" once the original
///   is deleted for good. 1.0.0 kept the suffixes, and devices that applied
///   a later claim before or after the purge never agreed (CHANGELOG, 1.4.0);
/// - a suffix another entry in the folder asked for outright is skipped, so
///   the second "report.pdf" beside a real "report (2).pdf" is
///   "report (3).pdf". 1.0.0 gave it "(2)", which could collide and stop
///   every later replay (ARCHITECTURE, the operation log).
///
/// The third is what 1.0.0 put in or out of the trash by folding case,
/// [`case_folded_subtrees`]: the trash state and star of those entries.
///
/// The first unlock after the update shows all of these, once.
fn compare_with_1_0_0(
    seed: u64,
    log: &[silentsilo_vfs::OpRecord],
    folded: &HashSet<String>,
    old: &BTreeMap<String, Row>,
    new: &BTreeMap<String, Row>,
) -> Differences {
    let (disturbed, claims) = reranked_groups(log);
    let mut differences = Differences::default();
    let mut problems = Vec::new();
    for key in old.keys().chain(new.keys()).collect::<BTreeSet<_>>() {
        let (Some(was), Some(now)) = (old.get(key), new.get(key)) else {
            let only = if old.contains_key(key) {
                "1.0.0"
            } else {
                "this build"
            };
            problems.push(format!(
                "{key}: only in {only}: {:?}",
                old.get(key).or(new.get(key))
            ));
            continue;
        };
        if was.fixed != now.fixed || (was.trash != now.trash && !folded.contains(key)) {
            problems.push(format!("{key}: 1.0.0 {was:?}, this build {now:?}"));
            continue;
        }
        if was.trash != now.trash {
            differences.repaired += 1;
        }
        if was.name == now.name {
            continue;
        }
        let id = Uuid::parse_str(key.rsplit(':').next().unwrap()).unwrap();
        let explained = claims.get(&id).is_some_and(|group| {
            let ranked_in = |name: &str| {
                let folded_name = silentsilo_vfs::names::fold(name);
                folded_name == group.2
                    || without_rank(&folded_name, group.1).as_ref() == Some(&group.2)
            };
            disturbed.contains(group) && ranked_in(&was.name) && ranked_in(&now.name)
        });
        if explained {
            differences.reranked += 1;
        } else {
            problems.push(format!(
                "{key}: named {:?} by 1.0.0, {:?} by this build",
                was.name, now.name
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "seed {seed}: this build shows a 1.0.0 history differently:\n{}",
        problems.join("\n")
    );
    differences
}

/// The records 1.0.0 wrote, as this build reads them: through the bytes
/// that went to storage.
fn records_for_this_build(conn: &Connection) -> Vec<silentsilo_vfs::OpRecord> {
    vfs_v1::all_ops(conn)
        .unwrap()
        .iter()
        .map(|r| silentsilo_vfs::OpRecord::from_bytes(&r.to_bytes().unwrap()).unwrap())
        .collect()
}

fn schema_version(conn: &Connection) -> String {
    conn.query_row(
        "SELECT value FROM vault_meta WHERE key = 'schema_version'",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

struct Upgrade {
    log: Vec<silentsilo_vfs::OpRecord>,
    old: BTreeMap<String, Row>,
    folded: HashSet<String>,
    replayed: BTreeMap<String, Row>,
    upgraded: BTreeMap<String, Row>,
    rebuild: Duration,
}

/// Writes a history with 1.0.0, then reads it back both ways with this
/// build.
fn upgrade(seed: u64, records: usize, folder_names: &[&str]) -> Upgrade {
    let dir = tempfile::tempdir().unwrap();
    let vault_id = Uuid::from_u64_pair(seed, 0x0100);
    let session = old_session(dir.path(), vault_id);
    let folded = write_history(&session, seed, records, folder_names);
    let old = picture_as_stored(&session.conn);
    let log = records_for_this_build(&session.conn);
    assert_eq!(schema_version(&session.conn), "1");
    // Locked, as the app is when it updates.
    session
        .conn
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    drop(session);

    // Every record, replayed by this build into an empty database.
    let fresh = Connection::open_in_memory().unwrap();
    fresh.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    silentsilo_vfs::init_schema(&fresh, vault_id).unwrap();
    let report = silentsilo_vfs::replay(&fresh, log.clone()).unwrap();
    assert_eq!(
        report.applied + report.obsolete,
        log.len(),
        "seed {seed}: {report:?}"
    );
    let replayed = picture(&fresh);

    // The 1.0.0 database opened by this build: the first unlock after the
    // update finds schema 1 and rebuilds.
    let conn = open_db(&dir.path().join("vault.db"));
    let started = Instant::now();
    silentsilo_vfs::init_schema(&conn, vault_id).unwrap();
    let rebuild = started.elapsed();
    assert_eq!(
        schema_version(&conn),
        silentsilo_vfs::SCHEMA_VERSION.to_string()
    );
    assert!(
        silentsilo_vfs::all_ops(&conn).unwrap() == log,
        "seed {seed}: the rebuild changed the log"
    );
    let upgraded = picture(&conn);

    Upgrade {
        log,
        old,
        folded,
        replayed,
        upgraded,
        rebuild,
    }
}

fn seeds(default: std::ops::Range<u64>) -> Vec<u64> {
    match std::env::var("SILENTSILO_UPGRADE_SEED") {
        Ok(seed) => vec![seed.parse().expect("a number")],
        Err(_) => default.collect(),
    }
}

fn check_upgrade(seed: u64, folder_names: &[&str]) -> Differences {
    let run = upgrade(seed, 2500, folder_names);
    // The upgraded database and a clean replay are the same build over the
    // same records: no difference of any kind.
    assert!(
        run.upgraded == run.replayed,
        "seed {seed}: the upgraded database differs from a clean replay"
    );
    let differences = compare_with_1_0_0(seed, &run.log, &run.folded, &run.old, &run.upgraded);
    println!(
        "seed {seed}: {} records, {} entries, {} exposed to 1.0.0 case folding, {differences:?}, rebuilt on first unlock in {:?}",
        run.log.len(),
        run.old.len(),
        run.folded.len(),
        run.rebuild
    );
    differences
}

#[test]
fn a_long_history_from_1_0_0_reads_the_same_after_the_update() {
    for seed in seeds(1..4) {
        check_upgrade(seed, FOLDER_NAMES);
    }
}

#[test]
fn without_case_variant_folders_the_trash_matches_1_0_0_exactly() {
    for seed in seeds(101..104) {
        let differences = check_upgrade(seed, FOLDER_NAMES_ONE_CASE);
        assert_eq!(differences.repaired, 0, "seed {seed}");
    }
}

#[test]
#[ignore = "benchmark: run with --release --ignored --nocapture"]
fn rebuild_on_first_unlock_after_the_update_benchmark() {
    let records: usize = std::env::var("SILENTSILO_UPGRADE_RECORDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50_000);
    let started = Instant::now();
    let run = upgrade(7, records, FOLDER_NAMES);
    let differences = compare_with_1_0_0(7, &run.log, &run.folded, &run.old, &run.upgraded);
    println!(
        "{} records, {} entries, {differences:?}; whole run {:?}; this build rebuilt the derived tables on first unlock in {:?}",
        run.log.len(),
        run.old.len(),
        started.elapsed(),
        run.rebuild
    );
}
