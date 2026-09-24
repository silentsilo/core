//! Several devices on one silo for days, each its own process, killed at
//! random mid-import and mid-upload and started again. Every so often all of
//! them stop, sync until nothing moves, and are checked: every device shows
//! the same tree, every file decrypts, and nothing a device confirmed adding
//! is gone unless a device said it was about to purge or replace it.
//!
//! ```text
//! silentsilo-soak run --work D:\soak [--storage storage.json] [--devices 3]
//!                     [--hours 48] [--kill-every 300] [--check-every 3600]
//!                     [--min-free-gb 20]
//! ```
//!
//! Without `--storage` the silo backs up to a folder under `--work`. With it,
//! to the targets in that file, a JSON list of storage settings as the app
//! saves them, which is how it runs against a real bucket. That file holds
//! credentials: keep it outside any repository.
//!
//! Every third check leaves the last device out while the first compacts, so
//! it comes back behind the horizon and rebuilds with its offline work.
//! A failed check writes `FAILED` in `report.log` and stops, leaving the work
//! folder as it was for a look.
//!
//! Storage keeps everything uploaded (the sweep's grace is 30 days), so the
//! work disk fills at roughly 1.5 GB an hour. Below `--min-free-gb` the run
//! stops early, says so, and still runs the final check.
//!
//! The device key is a fixed wrap key, the way the tests open a silo, so no
//! security key or Windows Hello is needed.

use std::collections::{BTreeSet, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use silentsilo_app::files::{decrypt_to_file, import_file};
use silentsilo_app::flows::{self, DeviceKey};
use silentsilo_app::{AppEvent, AppState, Host, run_sync_pass};
use silentsilo_store::StoreConfig;
use silentsilo_vault::{BackupTarget, SiloEntry, TargetRole, VaultSession};
use silentsilo_vfs::Vfs;
use uuid::Uuid;

const KEY_ID: &str = "50a4";
const WRAP: [u8; 32] = [0x5a; 32];

// ── Arguments ───────────────────────────────────────────────────────

struct Args {
    command: String,
    work: PathBuf,
    storage: Option<PathBuf>,
    devices: usize,
    hours: f64,
    kill_every: u64,
    check_every: u64,
    min_free_gb: u64,
    n: usize,
    out: bool,
    name: String,
}

fn args() -> Args {
    let mut raw = std::env::args().skip(1);
    let mut args = Args {
        command: raw.next().unwrap_or_default(),
        work: PathBuf::new(),
        storage: None,
        devices: 3,
        hours: 48.0,
        kill_every: 300,
        check_every: 3600,
        min_free_gb: 20,
        n: 0,
        out: false,
        name: String::new(),
    };
    while let Some(flag) = raw.next() {
        let mut value = || raw.next().unwrap_or_else(|| panic!("{flag} needs a value"));
        match flag.as_str() {
            "--work" => args.work = PathBuf::from(value()),
            "--storage" => args.storage = Some(PathBuf::from(value())),
            "--devices" => args.devices = value().parse().expect("a number"),
            "--hours" => args.hours = value().parse().expect("a number"),
            "--kill-every" => args.kill_every = value().parse().expect("seconds"),
            "--check-every" => args.check_every = value().parse().expect("seconds"),
            "--min-free-gb" => args.min_free_gb = value().parse().expect("a number"),
            "--n" => args.n = value().parse().expect("a number"),
            "--compact" => args.out = true,
            "--name" => args.name = value(),
            other => panic!("unknown argument {other}"),
        }
    }
    assert!(!args.work.as_os_str().is_empty(), "--work is required");
    args
}

fn main() {
    let args = args();
    match args.command.as_str() {
        "run" => supervise(&args),
        "device" => device(&args, Mode::Work),
        "settle" => device(&args, Mode::Settle { compact: args.out }),
        "inspect" => device(&args, Mode::Inspect),
        _ => {
            eprintln!("usage: silentsilo-soak run --work <dir> [--storage <file>] [--devices 3]");
            std::process::exit(2);
        }
    }
}

// ── The silo every device shares ────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct Silo {
    vault_id: Uuid,
    targets: Vec<StoreConfig>,
}

fn silo_file(work: &Path) -> PathBuf {
    work.join("silo.json")
}

fn load_silo(work: &Path) -> Silo {
    serde_json::from_slice(&std::fs::read(silo_file(work)).expect("silo.json")).expect("silo.json")
}

struct SoakHost {
    targets: Vec<StoreConfig>,
}

impl Host for SoakHost {
    fn emit(&self, _event: AppEvent) {}
    fn warn(&self, area: &str, detail: &str) {
        eprintln!("warning [{area}] {detail}");
    }
    fn targets(&self, _silo_id: Uuid) -> Vec<BackupTarget> {
        self.targets
            .iter()
            .enumerate()
            .map(|(i, config)| BackupTarget {
                config: config.clone(),
                label: format!("copy {i}"),
                role: TargetRole::Working,
            })
            .collect()
    }
}

fn key() -> DeviceKey {
    DeviceKey {
        kind: silentsilo_vault::KIND_FIDO2.into(),
        derivation: silentsilo_vault::DERIVATION_HMAC_V1.into(),
        credential_id: KEY_ID.into(),
        public_key: String::new(),
        wrap_key: WRAP,
        label: "Soak".into(),
    }
}

// ── The supervisor ──────────────────────────────────────────────────

fn report(work: &Path, line: &str) {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("{stamp} {line}");
    println!("{line}");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(work.join("report.log"))
        .unwrap();
    writeln!(file, "{line}").unwrap();
}

fn spawn(work: &Path, command: &str, n: usize, extra: &[&str]) -> Child {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(work.join(format!("dev-{n}.log")))
        .unwrap();
    Command::new(std::env::current_exe().unwrap())
        .args([command, "--work"])
        .arg(work)
        .args(["--n", &n.to_string()])
        .args(extra)
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap()
}

fn supervise(args: &Args) {
    let work = &args.work;
    std::fs::create_dir_all(work).unwrap();
    if !silo_file(work).exists() {
        let targets = match &args.storage {
            Some(path) => serde_json::from_slice(&std::fs::read(path).unwrap())
                .expect("a JSON list of storage settings"),
            None => {
                let folder = work.join("storage");
                std::fs::create_dir_all(&folder).unwrap();
                vec![StoreConfig::Folder { path: folder }]
            }
        };
        let silo = Silo {
            vault_id: Uuid::new_v4(),
            targets,
        };
        std::fs::write(silo_file(work), serde_json::to_vec_pretty(&silo).unwrap()).unwrap();
        report(work, &format!("new silo {}", silo.vault_id));
    }

    let mut rng = Rng::seeded();
    let started = Instant::now();
    let end = Duration::from_secs_f64(args.hours * 3600.0);
    let mut children: Vec<Option<Child>> = (0..args.devices).map(|_| None).collect();
    let mut asleep_until: Vec<Instant> = vec![Instant::now(); args.devices];
    // The first device makes the silo; the others join once it is there.
    children[0] = Some(spawn(work, "device", 0, &[]));
    while !work.join("dev-0").join("ready").exists() {
        std::thread::sleep(Duration::from_millis(500));
    }
    let mut next_kill = Instant::now() + Duration::from_secs(rng.below(args.kill_every) + 1);
    let mut next_check = Instant::now() + Duration::from_secs(args.check_every);
    let mut checks = 0;
    let mut kills = 0;
    let mut next_space = Instant::now();

    while started.elapsed() < end {
        if Instant::now() >= next_space {
            if let Some(free) = free_bytes(work)
                && free < args.min_free_gb * 1_000_000_000
            {
                report(
                    work,
                    &format!(
                        "stopped early: {:.1} GB free on the work disk, under {} GB",
                        free as f64 / 1e9,
                        args.min_free_gb
                    ),
                );
                break;
            }
            next_space = Instant::now() + Duration::from_secs(60);
        }
        for (n, child) in children.iter_mut().enumerate() {
            if child.is_none() && Instant::now() >= asleep_until[n] {
                *child = Some(spawn(work, "device", n, &[]));
            }
        }
        if Instant::now() >= next_kill {
            let n = rng.below(args.devices as u64) as usize;
            if let Some(mut child) = children[n].take() {
                let _ = child.kill();
                let _ = child.wait();
                kills += 1;
                // Mostly back at once; now and then away for up to an hour.
                let away = if rng.below(10) == 0 {
                    rng.below(3600)
                } else {
                    rng.below(20)
                };
                asleep_until[n] = Instant::now() + Duration::from_secs(away);
                report(
                    work,
                    &format!("killed device {n}, back in {away}s ({kills} kills)"),
                );
            }
            next_kill = Instant::now() + Duration::from_secs(rng.below(args.kill_every) + 1);
        }
        if Instant::now() >= next_check {
            for child in children.iter_mut() {
                if let Some(mut c) = child.take() {
                    let _ = c.kill();
                    let _ = c.wait();
                }
            }
            checks += 1;
            let left_out = (checks % 3 == 0 && args.devices > 1).then_some(args.devices - 1);
            match check(work, args.devices, left_out) {
                Ok(summary) => report(work, &format!("check {checks} passed: {summary}")),
                Err(why) => {
                    report(work, &format!("check {checks} FAILED: {why}"));
                    std::process::exit(1);
                }
            }
            asleep_until = vec![Instant::now(); args.devices];
            next_check = Instant::now() + Duration::from_secs(args.check_every);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    for child in children.iter_mut().flatten() {
        let _ = child.kill();
        let _ = child.wait();
    }
    match check(work, args.devices, None) {
        Ok(summary) => report(
            work,
            &format!("final check passed after {kills} kills: {summary}"),
        ),
        Err(why) => {
            report(work, &format!("final check FAILED: {why}"));
            std::process::exit(1);
        }
    }
}

/// Bytes free to this user on the disk holding `path`. `None` when it cannot
/// be read, which never stops a run.
#[cfg(windows)]
fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut free = 0u64;
    // SAFETY: `wide` is NUL-terminated and outlives the call; the out
    // pointer is a live u64, and the two totals are optional.
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some(free)
}

#[cfg(unix)]
// The field types differ between Linux and macOS.
#[allow(clippy::unnecessary_cast)]
fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid C string and `stat` a live, writable struct.
    if unsafe { libc::statvfs(c.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    Some(stat.f_bavail as u64 * stat.f_frsize as u64)
}

/// Syncs every device until a round moves nothing, compacting first when
/// one is left out, then compares what each shows and what the ledgers say.
fn check(work: &Path, devices: usize, left_out: Option<usize>) -> Result<String, String> {
    let settle = |n: usize, compact: bool| -> Result<Picture, String> {
        let extra: &[&str] = if compact { &["--compact"] } else { &[] };
        let status = spawn(work, "settle", n, extra)
            .wait()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("device {n} failed to settle, see dev-{n}.log"));
        }
        let raw = std::fs::read(work.join(format!("dev-{n}")).join("picture.json"))
            .map_err(|e| e.to_string())?;
        serde_json::from_slice(&raw).map_err(|e| e.to_string())
    };
    let everyone: Vec<usize> = (0..devices).filter(|n| Some(*n) != left_out).collect();
    let mut pictures = Vec::new();
    for round in 0..12 {
        pictures = everyone
            .iter()
            .map(|n| settle(*n, round == 0 && left_out.is_some() && *n == 0))
            .collect::<Result<Vec<_>, _>>()?;
        if pictures.iter().all(|p| p.moved == 0) {
            break;
        }
        if round == 11 {
            return Err("the devices never stopped exchanging changes".into());
        }
    }
    let first = &pictures[0];
    for (p, n) in pictures.iter().zip(&everyone) {
        if p.folders != first.folders || p.files != first.files || p.passwords != first.passwords {
            return Err(format!("device {n} shows something else than device 0"));
        }
        if !p.unopened.is_empty() {
            return Err(format!("device {n} cannot open {:?}", p.unopened));
        }
    }

    // Nothing confirmed as added is gone unless someone was about to purge
    // or replace it. The device left out keeps what it had not sent yet;
    // its adds are checked once it is back.
    let mut added = HashSet::new();
    let mut may_go = HashSet::new();
    for n in 0..devices {
        let left = Some(n) == left_out;
        let Ok(raw) = std::fs::read_to_string(work.join(format!("dev-{n}")).join("ledger.jsonl"))
        else {
            continue;
        };
        for line in raw.lines() {
            let Ok(entry) = serde_json::from_str::<Ledger>(line) else {
                continue;
            };
            match entry {
                Ledger::Added { hash } if !left => {
                    added.insert(hash);
                }
                Ledger::Added { .. } => {}
                Ledger::MayRemove { hashes } => may_go.extend(hashes),
            }
        }
    }
    let present: HashSet<&String> = first.hashes.iter().collect();
    let lost: Vec<&String> = added
        .iter()
        .filter(|h| !present.contains(h) && !may_go.contains(*h))
        .collect();
    if !lost.is_empty() {
        return Err(format!("content lost: {lost:?}"));
    }
    Ok(format!(
        "{} devices agree on {} files, {} added in all, {} left out",
        everyone.len(),
        first.files.len(),
        added.len(),
        left_out.map_or("none".to_string(), |n| format!("device {n}"))
    ))
}

// ── A device ────────────────────────────────────────────────────────

enum Mode {
    Work,
    Settle {
        compact: bool,
    },
    /// Prints the rows and records behind files named `--name`.
    Inspect,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Ledger {
    /// An add that returned: it has to survive.
    Added { hash: String },
    /// Written before a purge or an add over a name: what it may take.
    MayRemove { hashes: Vec<String> },
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Picture {
    moved: usize,
    folders: BTreeSet<String>,
    files: BTreeSet<String>,
    passwords: BTreeSet<String>,
    /// Every content hash held, trash included.
    hashes: BTreeSet<String>,
    unopened: Vec<String>,
}

struct Dev {
    state: AppState,
    silo: SiloEntry,
    host: SoakHost,
    dir: PathBuf,
}

fn device(args: &Args, mode: Mode) {
    let dir = args.work.join(format!("dev-{}", args.n));
    std::fs::create_dir_all(&dir).unwrap();
    // Working copies and blob bookkeeping of this device alone.
    // SAFETY: set before anything else runs, on the only thread there is.
    unsafe {
        std::env::set_var("LOCALAPPDATA", dir.join("local"));
        std::env::set_var("XDG_CACHE_HOME", dir.join("local"));
        std::env::set_var("SILENTSILO_TEST_WORK_BASE", dir.join("local").join("work"));
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let silo = load_silo(&args.work);
        let dev = Dev::open(args.n, dir, silo).await;
        match mode {
            Mode::Work => dev.work(args.n).await,
            Mode::Settle { compact } => dev.settle(compact).await,
            Mode::Inspect => dev.inspect(&args.name),
        }
    });
}

impl Dev {
    async fn open(n: usize, dir: PathBuf, silo: Silo) -> Self {
        let root = dir.join("silo");
        let host = SoakHost {
            targets: silo.targets,
        };
        let session = if root.join("vault.db.enc").exists() {
            let (session, _) =
                flows::open_with_device_key(root.clone(), KEY_ID, &WRAP, silo.vault_id)
                    .expect("the key opens the silo");
            session
        } else if n == 0 && !dir.join("ready").exists() {
            let session = VaultSession::provision(root.clone(), silo.vault_id, "secret").unwrap();
            Vfs::new(&session).ensure_initialized().unwrap();
            let (_code, envelope) =
                silentsilo_vault::create_recovery_envelope(&session.dek, &session.kek).unwrap();
            silentsilo_vault::save_recovery_envelope(&root, &envelope).unwrap();
            flows::enrol_device_key(&session, &key()).unwrap();
            session
        } else {
            let store = host.targets[0].open().expect("the storage opens");
            let offer = flows::key_join_begin(&*store)
                .await
                .expect("a silo to join");
            let join = flows::key_join_open(&*store, &offer, KEY_ID, &WRAP)
                .await
                .expect("the key joins");
            let session = flows::recovery_join_provision(&*store, &join, root.clone(), "secret")
                .await
                .expect("provisioned");
            let plan =
                silentsilo_sync::fetch_join_plan_reporting(&*store, join.dek(), &mut |_, _| {})
                    .await
                    .expect("a join plan");
            flows::join_finish(session, plan).expect("joined").0
        };
        let state = AppState::default();
        state.open_session(&host, silo.vault_id, session).unwrap();
        Self {
            state,
            silo: SiloEntry {
                id: silo.vault_id,
                name: "Soak".into(),
                path: root,
                last_opened: 0,
                auto_lock_minutes: None,
            },
            host,
            dir,
        }
    }

    fn conn<T>(&self, f: impl FnOnce(&Vfs<'_>, &rusqlite::Connection) -> T) -> T {
        let sessions = self.state.sessions.lock().unwrap();
        let session = &sessions[&self.silo.id];
        f(&Vfs::new(session), &session.conn)
    }

    fn ledger(&self, entry: &Ledger) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("ledger.jsonl"))
            .unwrap();
        writeln!(file, "{}", serde_json::to_string(entry).unwrap()).unwrap();
        file.sync_all().unwrap();
    }

    /// One pass, and the rebuild the app would ask for when it is behind.
    async fn pass(&self) -> usize {
        let report = match run_sync_pass(&self.state, &self.host, &self.silo).await {
            Ok(report) => report,
            Err(e) => {
                eprintln!("pass failed: {e}");
                return 0;
            }
        };
        if report.needs_rebuild {
            let kept = self.rebuild().await;
            println!("rebuilt behind a compaction, {kept} offline changes kept");
            return 1;
        }
        assert!(!report.needs_rejoin, "sent to rejoin: {report:?}");
        assert!(report.unreadable.is_empty(), "unreadable: {report:?}");
        report.ops_pushed + report.ops_applied + report.blobs_uploaded
    }

    async fn rebuild(&self) -> usize {
        let dek = self.state.sessions.lock().unwrap()[&self.silo.id]
            .dek
            .clone();
        let mut best: Option<(silentsilo_vfs::Snapshot, Vec<silentsilo_vfs::OpRecord>)> = None;
        for target in &self.host.targets {
            let store = target.open().unwrap();
            if let Ok(Some(found)) = silentsilo_sync::fetch_rebuild(&*store, &dek).await
                && best.as_ref().is_none_or(|(b, ops)| {
                    (found.0.horizon, found.1.len()) > (b.horizon, ops.len())
                })
            {
                best = Some(found);
            }
        }
        let (snapshot, incoming) = best.expect("a snapshot to rebuild from");
        let mut sessions = self.state.sessions.lock().unwrap();
        let session = sessions.get_mut(&self.silo.id).unwrap();
        silentsilo_sync::apply_rebuild(&mut session.conn, &snapshot, incoming)
            .unwrap()
            .kept_local
    }

    async fn work(&self, n: usize) {
        let mut rng = Rng::seeded();
        if n == 0 && !self.dir.join("ready").exists() {
            self.pass().await;
            std::fs::write(self.dir.join("ready"), b"").unwrap();
        }
        let mut last_pass = Instant::now();
        let mut done = 0u64;
        loop {
            self.act(&mut rng).await;
            done += 1;
            if rng.below(8) == 0 || last_pass.elapsed() > Duration::from_secs(30) {
                self.pass().await;
                last_pass = Instant::now();
            }
            if done.is_multiple_of(60) {
                // Locked and unlocked, the way an idle timer does it.
                self.state.close_session(&self.host, self.silo.id).unwrap();
                let (session, _) = flows::open_with_device_key(
                    self.silo.path.clone(),
                    KEY_ID,
                    &WRAP,
                    self.silo.id,
                )
                .expect("the key opens the silo");
                self.state
                    .open_session(&self.host, self.silo.id, session)
                    .unwrap();
            }
            tokio::time::sleep(Duration::from_millis(100 + rng.below(1400))).await;
        }
    }

    fn folders(&self) -> Vec<Uuid> {
        self.conn(|vfs, _| {
            vfs.list_all_folders()
                .unwrap()
                .into_iter()
                .filter(|f| f.path != "/Inbox")
                .map(|f| f.id)
                .collect()
        })
    }

    fn files(&self, trashed: bool) -> Vec<(Uuid, String)> {
        self.conn(|_, conn| {
            conn.prepare(&format!(
                "SELECT id, content_hash FROM files WHERE deleted_at IS {} NULL",
                if trashed { "NOT" } else { "" }
            ))
            .unwrap()
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
            })
            .unwrap()
            .filter_map(|row| {
                let (id, hash) = row.ok()?;
                Some((Uuid::parse_str(&id).ok()?, hash?))
            })
            .collect()
        })
    }

    async fn act(&self, rng: &mut Rng) {
        const NAMES: &[&str] = &["a.txt", "A.txt", "report.pdf", "notă.md", "big.bin"];
        const FOLDERS: &[&str] = &["Docs", "docs", "Photos", "Școală"];
        match rng.below(20) {
            0..=7 => {
                let Some(folder) = rng.pick(&self.folders()) else {
                    return;
                };
                let name = rng.pick(NAMES).unwrap();
                let replaced: Vec<String> = self.conn(|_, conn| {
                    conn.prepare(
                        "SELECT content_hash FROM files WHERE folder_id = ?1
                          AND lower(name) = lower(?2) AND content_hash IS NOT NULL",
                    )
                    .unwrap()
                    .query_map([folder.to_string(), name.to_string()], |r| r.get(0))
                    .unwrap()
                    .filter_map(Result::ok)
                    .collect()
                });
                if !replaced.is_empty() {
                    self.ledger(&Ledger::MayRemove { hashes: replaced });
                }
                // Mostly small, now and then tens of megabytes, so a kill
                // lands in the middle of an import or an upload.
                let size = match rng.below(20) {
                    0 => 4_000_000 + rng.below(60_000_000),
                    1..=5 => 64_000 + rng.below(4_000_000),
                    _ => 1 + rng.below(64_000),
                } as usize;
                let mut source = Bytes::new(rng.next(), size);
                if let Ok(file) =
                    import_file(&self.state, &self.silo, folder, &mut source, name, None)
                    && let Some(hash) = file.content_hash
                {
                    self.ledger(&Ledger::Added { hash });
                }
            }
            8..=9 => {
                if let Some(parent) = rng.pick(&self.folders()) {
                    let name = rng.pick(FOLDERS).unwrap();
                    let _ = self.conn(|vfs, _| vfs.create_folder(parent, name));
                }
            }
            10 => {
                if let Some((id, _)) = rng.pick(&self.files(false)) {
                    let name = rng.pick(NAMES).unwrap();
                    let _ = self.conn(|vfs, _| vfs.rename_file(id, name));
                }
            }
            11 => {
                if let (Some((id, _)), Some(to)) =
                    (rng.pick(&self.files(false)), rng.pick(&self.folders()))
                {
                    let _ = self.conn(|vfs, _| vfs.move_file(id, to));
                }
            }
            12..=13 => {
                if let Some((id, _)) = rng.pick(&self.files(false)) {
                    let _ = self.conn(|vfs, _| vfs.trash_file(id));
                }
            }
            14 => {
                if let Some(id) = rng.pick(&self.folders()) {
                    let _ = self.conn(|vfs, _| vfs.trash_folder(id));
                }
            }
            15 => {
                if let Some((id, _)) = rng.pick(&self.files(true)) {
                    let _ = self.conn(|vfs, _| vfs.restore_file(id));
                }
            }
            16 => {
                if rng.below(4) == 0 {
                    let in_trash: Vec<String> = self.conn(|_, conn| {
                        // What is in the trash, and the conflict copies of
                        // it, which a purge takes along.
                        conn.prepare(
                            "WITH RECURSIVE gone(id) AS (
                                 SELECT f.id FROM files f JOIN folders d ON d.id = f.folder_id
                                  WHERE f.deleted_at IS NOT NULL OR d.deleted_at IS NOT NULL
                                 UNION
                                 SELECT c.copy_id FROM conflict_copies c JOIN gone g ON c.file_id = g.id
                             )
                             SELECT content_hash FROM files
                              WHERE id IN (SELECT id FROM gone) AND content_hash IS NOT NULL",
                        )
                        .unwrap()
                        .query_map([], |r| r.get(0))
                        .unwrap()
                        .filter_map(Result::ok)
                        .collect()
                    });
                    self.ledger(&Ledger::MayRemove { hashes: in_trash });
                    // A purged file's conflict copies go with it, trashed
                    // or not, so what went is also noted after: what this
                    // device held before less what it holds now.
                    let held = |dev: &Self| -> HashSet<String> {
                        dev.files(false)
                            .into_iter()
                            .chain(dev.files(true))
                            .map(|(_, h)| h)
                            .collect()
                    };
                    let before = held(self);
                    if let Ok((_, blobs)) = self.conn(|vfs, _| vfs.empty_trash()) {
                        silentsilo_app::files::release_purged_blobs(
                            &self.host,
                            self.silo.id,
                            &self.silo.path,
                            &blobs,
                        );
                    }
                    let gone = before.difference(&held(self)).cloned().collect();
                    self.ledger(&Ledger::MayRemove { hashes: gone });
                }
            }
            _ => {
                let id = Uuid::from_u128(1 + rng.below(6) as u128);
                if rng.below(4) == 0 {
                    let _ = self.conn(|vfs, _| vfs.delete_password(id));
                } else {
                    let entry = serde_json::json!({
                        "id": id.to_string(), "service": "site", "username": "soak",
                        "password": format!("pw-{}", rng.next()), "url": "", "notes": "",
                        "category": "General", "created_at": 0, "updated_at": 0, "type": "login",
                    });
                    let _ = self.conn(|vfs, _| vfs.upsert_password(id, &entry.to_string()));
                }
            }
        }
    }

    /// Syncs until a pass moves nothing, compacts first when asked, then
    /// writes what this device shows and opens every file it holds.
    async fn settle(&self, compact: bool) {
        // Every backoff over, as it would be by the time anyone looked.
        self.conn(|_, conn| {
            for target in &self.host.targets {
                silentsilo_vfs::reset_target_backoff(conn, target.target_id()).unwrap();
            }
        });
        let mut moved = 0;
        for _ in 0..6 {
            let now = self.pass().await;
            moved += now;
            if now == 0 {
                break;
            }
        }
        if compact {
            let horizon = self.compact().await;
            println!("compacted at {horizon:?}");
        }
        let mut picture = self.picture();
        picture.moved = moved;
        let scratch = self.dir.join("check");
        std::fs::create_dir_all(&scratch).unwrap();
        for (id, _) in self.files(false) {
            let dest = scratch.join(id.to_string());
            if let Err(e) = decrypt_to_file(&self.state, &self.host, &self.silo, id, &dest).await {
                picture.unopened.push(format!("{id}: {e}"));
            }
            let _ = std::fs::remove_file(&dest);
        }
        std::fs::write(
            self.dir.join("picture.json"),
            serde_json::to_vec(&picture).unwrap(),
        )
        .unwrap();
        self.state.close_session(&self.host, self.silo.id).unwrap();
    }

    /// What the pass would do after a month, now.
    async fn compact(&self) -> Option<u64> {
        let policy = silentsilo_vfs::CompactionPolicy {
            retain_seconds: 0,
            keep_recent: 50,
            min_records: 0,
        };
        let (vault_id, dek) = {
            let sessions = self.state.sessions.lock().unwrap();
            let s = &sessions[&self.silo.id];
            (s.vault_id, s.dek.clone())
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let snapshot = {
            let sessions = self.state.sessions.lock().unwrap();
            silentsilo_sync::plan_compaction(&sessions[&self.silo.id].conn, vault_id, &policy, now)
                .ok()
                .flatten()?
        };
        for target in &self.host.targets {
            let store = target.open().ok()?;
            silentsilo_sync::publish_compaction(&*store, &dek, &snapshot, true)
                .await
                .ok()?;
        }
        let mut sessions = self.state.sessions.lock().unwrap();
        let session = sessions.get_mut(&self.silo.id)?;
        silentsilo_sync::finish_compaction(&mut session.conn, &snapshot).ok()?;
        Some(snapshot.horizon)
    }

    fn inspect(&self, name: &str) {
        for line in self.picture().files.iter().filter(|l| l.contains(name)) {
            println!("picture: {line}");
        }
        self.conn(|_, conn| {
            let ids: Vec<(String, String, String, Option<i64>)> = conn
                .prepare(
                    "SELECT id, folder_id, blob_id, deleted_at FROM files WHERE name = ?1 OR blob_id LIKE ?1 || '%' OR id LIKE ?1 || '%'",
                )
                .unwrap()
                .query_map([name], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .unwrap()
                .filter_map(Result::ok)
                .collect();
            println!("rows: {ids:#?}");
            let all: Vec<String> = conn
                .prepare("SELECT id || ' ' || name || ' ' || blob_id || ' ' || IFNULL(deleted_at, '-') FROM files")
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .filter_map(Result::ok)
                .filter(|l: &String| l.contains(name))
                .collect();
            println!("raw: {all:#?}");
            let base = silentsilo_vfs::snapshot::read_base(conn).unwrap();
            println!("base horizon: {:?}", base.as_ref().map(|b| b.horizon));
            if let Some(base) = base {
                for f in base.files.iter().filter(|f| f.name == name) {
                    println!("in base: {f:?}");
                }
            }
            let me = silentsilo_vfs::device_id(conn).unwrap();
            println!("this device: {me}");
            for record in silentsilo_vfs::all_ops(conn).unwrap() {
                let text = String::from_utf8(record.to_bytes().unwrap()).unwrap();
                if ids.iter().any(|(id, ..)| text.contains(id.as_str())) || text.contains(name) {
                    println!("L{} {}: {text}", record.lamport, record.device_id);
                }
            }
        });
    }

    fn picture(&self) -> Picture {
        self.conn(|vfs, conn| {
            let strings = |sql: &str| -> BTreeSet<String> {
                conn.prepare(sql)
                    .unwrap()
                    .query_map([], |r| r.get::<_, String>(0))
                    .unwrap()
                    .filter_map(Result::ok)
                    .collect()
            };
            Picture {
                folders: strings(
                    "SELECT path || ' trashed=' || (deleted_at IS NOT NULL) FROM folders",
                ),
                files: strings(
                    "SELECT d.path || '/' || f.name || ' ' || f.blob_id || ' '
                            || IFNULL(f.content_hash, '') || ' trashed=' || (f.deleted_at IS NOT NULL)
                       FROM files f JOIN folders d ON d.id = f.folder_id",
                ),
                passwords: vfs.list_passwords().unwrap().into_iter().collect(),
                hashes: strings("SELECT content_hash FROM files WHERE content_hash IS NOT NULL"),
                ..Picture::default()
            }
        })
    }
}

// ── Randomness and content ──────────────────────────────────────────

struct Rng(u64);

impl Rng {
    fn seeded() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        Self((nanos ^ u64::from(std::process::id())).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    fn pick<T: Clone>(&mut self, items: &[T]) -> Option<T> {
        (!items.is_empty()).then(|| items[self.below(items.len() as u64) as usize].clone())
    }
}

/// `len` bytes from a seed, read in chunks, so a large file is never held.
struct Bytes {
    rng: Rng,
    left: usize,
}

impl Bytes {
    fn new(seed: u64, len: usize) -> Self {
        Self {
            rng: Rng(seed | 1),
            left: len,
        }
    }
}

impl std::io::Read for Bytes {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.left);
        for chunk in buf[..n].chunks_mut(8) {
            let word = self.rng.next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        self.left -= n;
        Ok(n)
    }
}
