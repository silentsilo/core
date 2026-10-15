//! Where a device keeps its sealed events until they reach storage.
//!
//! `<silo>/audit-queue/`, beside the silo rather than in the scratch
//! directory a lock sweeps: an event must outlive the lock it records.
//! Everything here is already sealed to the log's key.
//!
//! - `pending`: records not yet in a segment, each with its event number in
//!   clear beside it, so a restart knows where the count stands without
//!   opening anything;
//! - `state.json`: the next event number, the next segment number, the hash
//!   of the last segment, and the number below which every event is already
//!   in a segment;
//! - `outbox/<seq>.seg`: closed segments waiting for every copy to hold them;
//! - `key.json` and `policy.json`: the log's key (its private half only
//!   wrapped, as storage holds it) and the policy this device last took in,
//!   so a silo with no copies has them, and the pass can publish them to a
//!   copy that does not;
//! - `lock`: held by whoever has the spool open. One at a time, across
//!   threads and processes: two holders would each read the state, move it
//!   and write it back, and number two events alike.
//!
//! The folder travels with the silo and may sit in a synced directory, so
//! whoever can write there must not choose the key events are sealed to.
//! The pinned log in `state.json` and the policy in `policy.json` each carry
//! a check under a key derived from the content key; one without a valid
//! check is not followed (see [`Unchecked`]). `key.json` needs none: its id
//! is the hash of its public key, and the id is in what is checked.
//!
//! The order of writes is what makes a crash harmless. A record is appended
//! and synced before the count moves past it; a segment is written whole
//! before the state says it exists, and the pending file is emptied only
//! after that. Whatever moment the process dies, a restart neither numbers
//! two events alike nor puts one event in two segments.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::segment::{Proof, SegmentKey, TAG_BYTES};
use crate::{
    AuditError, AuditKey, AuditPolicy, BY_SILO, Event, KeyPair, MAX_RECORDS, MAX_SEGMENT_BYTES,
    Scope, Segment, codes, seal_event,
};

/// What a segment's header, its tag and a record's length take, beside the
/// records.
const SEGMENT_HEADER: usize = 73 + TAG_BYTES;
const RECORD_FRAME: usize = 4;

pub const QUEUE_DIR: &str = "audit-queue";
const KEY_FILE: &str = "key.json";
const POLICY_FILE: &str = "policy.json";

/// How long opening waits for another holder. Every holder is local work,
/// never a network call, so this is only reached when something is stuck.
const LOCK_WAIT: Duration = Duration::from_secs(10);

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct State {
    next_event: u64,
    next_segment: u64,
    last_hash: String,
    /// Every event below this number is in a segment already.
    closed_through: u64,
    /// When the oldest event not yet in a segment happened.
    #[serde(default)]
    pending_since: Option<i64>,
    #[serde(default)]
    pinned: Option<Pinned>,
    /// The check over `pinned`, hex. From core 1.10; a release before it
    /// ignores the field and drops it when it saves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pin_check: Option<String>,
}

/// The log this device writes to, as storage first told it. Kept here so a
/// device records offline, and so a key named later is not followed in
/// silence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pinned {
    pub key_id: String,
    pub public_key: String,
    pub scope: Scope,
    pub enabled: bool,
    pub retention_days: Option<u32>,
    /// When the policy was last read from storage, in seconds.
    pub checked_at: i64,
    /// The policy was made on this device, or read with a tag that checks
    /// under the current DEK. From then on a policy from storage whose tag
    /// does not check is not followed.
    #[serde(default)]
    pub proven: bool,
}

/// What `policy.json` holds: the policy, and its check.
#[derive(Serialize, Deserialize)]
struct KeptPolicy {
    #[serde(flatten)]
    policy: AuditPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    check: Option<String>,
}

/// What the queue does with a pinned log or a kept policy that has no valid
/// check: what a release before core 1.10 left, or what someone wrote into
/// the silo folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unchecked {
    /// Takes it in once and checks it from then on. Only for the first open
    /// by a build that checks, when the queue can only be as a release
    /// before it left it.
    Adopt,
    /// Does not follow it. The pin is made again from a kept policy whose
    /// check holds, or dropped, and the next policy read from storage
    /// settles it.
    Refuse,
}

/// The keys the queue works with, each derived from the content key.
struct QueueKeys {
    /// Checks the pin and the kept policy.
    check: Zeroizing<[u8; 32]>,
    /// Tags the segments this device closes.
    segments: SegmentKey,
}

impl QueueKeys {
    fn new(content_key: &[u8; 32]) -> Self {
        Self {
            check: Zeroizing::new(blake3::derive_key(
                "silentsilo audit queue check v1",
                content_key,
            )),
            segments: SegmentKey::new(content_key),
        }
    }

    fn pin_check(&self, pinned: &Pinned) -> String {
        let mut body = b"silentsilo audit pin\0".to_vec();
        for text in [&pinned.key_id, &pinned.public_key] {
            body.extend_from_slice(&(text.len() as u32).to_be_bytes());
            body.extend_from_slice(text.as_bytes());
        }
        body.push(match pinned.scope {
            Scope::Org => 1,
            Scope::Silo => 2,
        });
        body.push(u8::from(pinned.enabled));
        match pinned.retention_days {
            Some(days) => {
                body.push(1);
                body.extend_from_slice(&days.to_be_bytes());
            }
            None => body.push(0),
        }
        body.extend_from_slice(&pinned.checked_at.to_be_bytes());
        body.push(u8::from(pinned.proven));
        hex::encode(blake3::keyed_hash(&self.check, &body).as_bytes())
    }

    fn policy_check(&self, policy: &AuditPolicy) -> String {
        let body = policy.canonical(b"silentsilo audit kept policy\0");
        hex::encode(blake3::keyed_hash(&self.check, &body).as_bytes())
    }
}

/// What reading the policy again changed.
#[derive(Debug, PartialEq, Eq)]
pub enum PolicyRead {
    /// A key now pinned: the first this device heard of, or one that
    /// replaces a personal log's.
    Pinned,
    /// The same key; the setting or the retention may have moved.
    Kept,
    /// The policy names another key. Not followed: the device goes on
    /// sealing to the pinned one, and says so.
    KeyChanged { pinned: String, named: String },
}

pub struct Spool {
    dir: PathBuf,
    device: Uuid,
    state: State,
    keys: QueueKeys,
    /// Locked while the spool is open; dropping it lets the next one in.
    _lock: File,
}

#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    #[error("the activity log could not be written on this computer: {0}")]
    Io(#[from] std::io::Error),
    #[error("the activity log is held by another task on this computer")]
    Busy,
    #[error(transparent)]
    Audit(#[from] AuditError),
}

/// Starts a personal log on this device: a new key, its private half
/// wrapped under the silo's content key, a policy saying on, and the first
/// event. For a silo whose log nobody ever set; the caller publishes the
/// policy and the key to the copies. `now` is in seconds.
pub fn start_silo_log(
    spool: &mut Spool,
    content_key: &[u8; 32],
    now: i64,
) -> Result<(AuditPolicy, AuditKey), SpoolError> {
    let keys = KeyPair::generate();
    let mut key = AuditKey::new(&keys, Scope::Silo, now);
    key.wrap_for(BY_SILO, &keys.private, content_key)?;
    let policy = AuditPolicy::new(true, &keys.id(), None, Scope::Silo, now);
    spool.apply_policy(&policy, &key, 0)?;
    spool.record(Event::new(codes::LOG_STARTED, now.saturating_mul(1000)))?;
    Ok((policy, key))
}

/// Writes `bytes` to `path` whole or not at all.
fn write_whole(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    // A scanner holding the old file refuses the rename for a moment.
    let mut tries = 0;
    loop {
        match fs::rename(&tmp, path) {
            Ok(()) => return Ok(()),
            Err(_) if tries < 20 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(e) => return Err(e),
        }
    }
}

/// Records not in a segment yet, as (event number, sealed record).
type Records = Vec<(u64, Vec<u8>)>;

/// The pending records, as (event number, sealed record).
fn read_pending(path: &Path) -> std::io::Result<Records> {
    Ok(read_pending_with_end(path)?.0)
}

/// The pending records, and where the last whole one ends.
fn read_pending_with_end(path: &Path) -> std::io::Result<(Records, u64)> {
    let mut bytes = Vec::new();
    match File::open(path) {
        Ok(mut file) => {
            file.read_to_end(&mut bytes)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(e) => return Err(e),
    }
    let mut out = Vec::new();
    let mut at = 0;
    // A record cut off by a crash mid-append is the last one, and it was
    // never counted: it is dropped, not read as damage.
    while at + 12 <= bytes.len() {
        let number = u64::from_be_bytes(bytes[at..at + 8].try_into().expect("eight"));
        let len = u32::from_be_bytes(bytes[at + 8..at + 12].try_into().expect("four")) as usize;
        if at + 12 + len > bytes.len() {
            break;
        }
        out.push((number, bytes[at + 12..at + 12 + len].to_vec()));
        at += 12 + len;
    }
    Ok((out, at as u64))
}

/// The standard library has no file lock on Android and answers every try
/// with `Unsupported`, which left the log unwritable on Android phones. There
/// it is `flock`, which is what the standard library uses on Linux.
fn try_lock(file: &File) -> Result<(), fs::TryLockError> {
    #[cfg(target_os = "android")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: a descriptor this file owns, open for the call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::WouldBlock {
            return Err(fs::TryLockError::WouldBlock);
        }
        Err(fs::TryLockError::Error(e))
    }
    #[cfg(not(target_os = "android"))]
    file.try_lock()
}

/// Takes the spool's lock, waiting up to [`LOCK_WAIT`] for another holder.
fn take_lock(dir: &Path) -> Result<File, SpoolError> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("lock"))?;
    let started = Instant::now();
    loop {
        match try_lock(&file) {
            Ok(()) => return Ok(file),
            Err(fs::TryLockError::WouldBlock) if started.elapsed() < LOCK_WAIT => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(fs::TryLockError::WouldBlock) => return Err(SpoolError::Busy),
            Err(fs::TryLockError::Error(e)) => return Err(e.into()),
        }
    }
}

impl Spool {
    /// Opens the spool, waiting for anyone else who has it open. Keep it
    /// open only for local work: never across a network call. The content
    /// key checks what the queue keeps and tags the segments it closes;
    /// `unchecked` says what to do with a pin that has no valid check.
    pub fn open(
        silo_root: &Path,
        device: Uuid,
        content_key: &[u8; 32],
        unchecked: Unchecked,
    ) -> Result<Self, SpoolError> {
        let dir = silo_root.join(QUEUE_DIR);
        fs::create_dir_all(dir.join("outbox"))?;
        let lock = take_lock(&dir)?;
        let mut state: State = match fs::read(dir.join("state.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(AuditError::from)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e.into()),
        };
        let pending_path = dir.join("pending");
        let (pending, end) = read_pending_with_end(&pending_path)?;
        // Appended and synced, but the count had not moved past it.
        if let Some((last, _)) = pending.last() {
            state.next_event = state.next_event.max(last.saturating_add(1));
        }
        // A record cut short by a crash is cut off here, or the next one
        // would be appended after it and read as part of it.
        if fs::metadata(&pending_path).is_ok_and(|m| m.len() > end) {
            let file = OpenOptions::new().write(true).open(&pending_path)?;
            file.set_len(end)?;
            file.sync_all()?;
        }
        let mut spool = Self {
            dir,
            device,
            state,
            keys: QueueKeys::new(content_key),
            _lock: lock,
        };
        spool.check_kept(unchecked)?;
        Ok(spool)
    }

    /// Settles the kept policy and the pin against their checks.
    fn check_kept(&mut self, unchecked: Unchecked) -> Result<(), SpoolError> {
        let policy = match self.read_kept_policy()? {
            Some((policy, true)) => Some(policy),
            Some((policy, false)) if unchecked == Unchecked::Adopt => {
                self.write_kept_policy(&policy)?;
                Some(policy)
            }
            Some((_, false)) => {
                let _ = fs::remove_file(self.dir.join(POLICY_FILE));
                None
            }
            None => None,
        };
        let Some(pinned) = self.state.pinned.clone() else {
            return Ok(());
        };
        let checked = self
            .state
            .pin_check
            .as_deref()
            .is_some_and(|check| crate::same_text(check, &self.keys.pin_check(&pinned)));
        if checked {
            return Ok(());
        }
        self.state.pinned = match unchecked {
            // What this device already followed is its own choice: from now
            // on it tags that policy when it spreads it.
            Unchecked::Adopt => Some(Pinned {
                proven: true,
                ..pinned
            }),
            Unchecked::Refuse => policy.and_then(|policy| self.pin_from(&policy)),
        };
        self.save_state()
    }

    /// The pin a kept policy and the key file it names make, read again at
    /// the next pass.
    fn pin_from(&self, policy: &AuditPolicy) -> Option<Pinned> {
        let key = AuditKey::from_json(&fs::read(self.dir.join(KEY_FILE)).ok()?).ok()?;
        if key.key_id != policy.key_id || key.scope != policy.scope {
            return None;
        }
        Some(Pinned {
            key_id: policy.key_id.clone(),
            public_key: hex::encode(key.public().ok()?),
            scope: policy.scope,
            enabled: policy.enabled || policy.scope == Scope::Org,
            retention_days: policy.retention_days,
            checked_at: 0,
            proven: false,
        })
    }

    /// `policy.json`, and whether its check holds.
    fn read_kept_policy(&self) -> Result<Option<(AuditPolicy, bool)>, SpoolError> {
        let bytes = match fs::read(self.dir.join(POLICY_FILE)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let kept: KeptPolicy = serde_json::from_slice(&bytes).map_err(AuditError::from)?;
        let checked = kept
            .check
            .as_deref()
            .is_some_and(|check| crate::same_text(check, &self.keys.policy_check(&kept.policy)));
        Ok(Some((kept.policy, checked)))
    }

    fn write_kept_policy(&self, policy: &AuditPolicy) -> Result<(), SpoolError> {
        let kept = KeptPolicy {
            policy: policy.clone(),
            check: Some(self.keys.policy_check(policy)),
        };
        write_whole(
            &self.dir.join(POLICY_FILE),
            &serde_json::to_vec(&kept).map_err(AuditError::from)?,
        )?;
        Ok(())
    }

    /// What this device logs to, if it has been told.
    pub fn pinned(&self) -> Option<&Pinned> {
        self.state.pinned.as_ref()
    }

    /// Takes in a policy made on this device, and the key it names, at
    /// `now` (seconds).
    pub fn apply_policy(
        &mut self,
        policy: &AuditPolicy,
        key: &AuditKey,
        now: i64,
    ) -> Result<PolicyRead, SpoolError> {
        self.apply(policy, key, now, true)
    }

    /// Takes in a policy read from storage, and the key it names, at `now`
    /// (seconds). `proven` when its tag checks under the current DEK.
    pub fn apply_stored_policy(
        &mut self,
        policy: &AuditPolicy,
        key: &AuditKey,
        now: i64,
        proven: bool,
    ) -> Result<PolicyRead, SpoolError> {
        self.apply(policy, key, now, proven)
    }

    fn apply(
        &mut self,
        policy: &AuditPolicy,
        key: &AuditKey,
        now: i64,
        proven: bool,
    ) -> Result<PolicyRead, SpoolError> {
        // The key file is not sealed; the policy is. A key whose scope the
        // policy does not confirm is damage, not a log to follow.
        if key.key_id != policy.key_id || key.scope != policy.scope {
            return Err(AuditError::BadKey.into());
        }
        let public = hex::encode(key.public()?);
        let read = match &self.state.pinned {
            // A personal log follows the newest policy: whoever could name
            // another key also holds the content key that reads it. An
            // organisation's key stays pinned for good.
            Some(pinned) if pinned.key_id != policy.key_id && pinned.scope == Scope::Silo => {
                PolicyRead::Pinned
            }
            Some(pinned) if pinned.key_id != policy.key_id => PolicyRead::KeyChanged {
                pinned: pinned.key_id.clone(),
                named: policy.key_id.clone(),
            },
            Some(_) => PolicyRead::Kept,
            None => PolicyRead::Pinned,
        };
        // Proven once, proven for the same key.
        let was_proven = matches!(&read, PolicyRead::Kept)
            && self.state.pinned.as_ref().is_some_and(|p| p.proven);
        let pinned = match (&read, &self.state.pinned) {
            // Nothing of another key's policy is taken in: not its setting,
            // its scope or its retention. Only that it was read.
            (PolicyRead::KeyChanged { .. }, Some(pinned)) => Pinned {
                checked_at: now,
                ..pinned.clone()
            },
            _ => Pinned {
                key_id: policy.key_id.clone(),
                public_key: public,
                // An organisation's log does not stop because its policy says so.
                enabled: policy.enabled || policy.scope == Scope::Org,
                scope: policy.scope,
                retention_days: policy.retention_days,
                checked_at: now,
                proven: proven || was_proven,
            },
        };
        // Another key's policy is not kept: it is not this device's log.
        // The key file is written before the pin that names it.
        if !matches!(read, PolicyRead::KeyChanged { .. }) {
            let kept = self.with_kept_ways(key)?;
            write_whole(&self.dir.join(KEY_FILE), &kept.to_json()?)?;
            self.write_kept_policy(policy)?;
        }
        self.state.pinned = Some(pinned);
        self.save_state()?;
        Ok(read)
    }

    /// Pins `key` under `policy` whatever was pinned before, closing what is
    /// pending under the old key first. Only for an organisation starting
    /// its log where a personal one was kept; never from what storage says.
    pub fn repin(
        &mut self,
        policy: &AuditPolicy,
        key: &AuditKey,
        now_ms: i64,
    ) -> Result<(), SpoolError> {
        self.close(now_ms)?;
        self.state.pinned = None;
        // Checked at 0: the next pass publishes it.
        self.apply_policy(policy, key, 0).map(|_| ())
    }

    /// Keeps a newer copy of the pinned key, with another way in.
    pub fn keep_key(&self, key: &AuditKey) -> Result<(), SpoolError> {
        match &self.state.pinned {
            Some(pinned) if pinned.key_id == key.key_id => {
                key.public()?;
                write_whole(
                    &self.dir.join(KEY_FILE),
                    &self.with_kept_ways(key)?.to_json()?,
                )?;
                Ok(())
            }
            _ => Err(AuditError::BadKey.into()),
        }
    }

    /// `key` with every way in the copy on this computer has: one added
    /// here while a pass was reading the copies is not written over.
    fn with_kept_ways(&self, key: &AuditKey) -> Result<AuditKey, SpoolError> {
        Ok(match self.key()? {
            Some(kept) if kept.key_id == key.key_id => key.merged(&kept),
            _ => key.clone(),
        })
    }

    /// The pinned log's key, as storage holds it. Only the key the pin
    /// names: its id is the hash of its public key.
    pub fn key(&self) -> Result<Option<AuditKey>, SpoolError> {
        let Some(pinned) = &self.state.pinned else {
            return Ok(None);
        };
        match fs::read(self.dir.join(KEY_FILE)) {
            Ok(bytes) => {
                let key = AuditKey::from_json(&bytes)?;
                Ok((key.key_id == pinned.key_id).then_some(key))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The pinned log's policy, as this device last took it in. One whose
    /// check does not hold is not this device's.
    pub fn policy(&self) -> Result<Option<AuditPolicy>, SpoolError> {
        Ok(self
            .read_kept_policy()?
            .and_then(|(policy, checked)| checked.then_some(policy)))
    }

    fn save_state(&mut self) -> Result<(), SpoolError> {
        self.state.pin_check = self
            .state
            .pinned
            .as_ref()
            .map(|pinned| self.keys.pin_check(pinned));
        write_whole(
            &self.dir.join("state.json"),
            &serde_json::to_vec(&self.state).map_err(AuditError::from)?,
        )?;
        Ok(())
    }

    /// Whether the oldest event waiting is `after_ms` old by `now_ms`.
    pub fn due(&self, now_ms: i64, after_ms: i64) -> bool {
        self.state
            .pending_since
            .is_some_and(|since| now_ms.saturating_sub(since) >= after_ms)
    }

    /// Records `event` in the log this device was told of. `None` when there
    /// is none, or it is off: a personal silo that never turned it on.
    pub fn record(&mut self, event: Event) -> Result<Option<u64>, SpoolError> {
        let Some(pinned) = self.state.pinned.clone().filter(|p| p.enabled) else {
            return Ok(None);
        };
        let public = hex::decode(&pinned.public_key).map_err(|_| AuditError::BadKey)?;
        self.record_to(&public, event).map(Some)
    }

    /// Seals `event` to `public_key` and queues it. Returns once it is on
    /// disk, with the number it was given.
    fn record_to(&mut self, public_key: &[u8], mut event: Event) -> Result<u64, SpoolError> {
        event.i = self.state.next_event;
        let sealed = seal_event(public_key, self.device, &event)?;
        let mut frame = Vec::with_capacity(12 + sealed.len());
        frame.extend_from_slice(&event.i.to_be_bytes());
        frame.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
        frame.extend_from_slice(&sealed);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("pending"))?;
        let before = file.metadata()?.len();
        if let Err(e) = file.write_all(&frame).and_then(|()| file.sync_all()) {
            // Half a record left behind would swallow the next one.
            let _ = file.set_len(before);
            return Err(e.into());
        }
        self.state.next_event = event.i + 1;
        if self.state.pending_since.is_none() {
            self.state.pending_since = Some(event.t);
        }
        self.save_state()?;
        Ok(event.i)
    }

    /// Turns what is pending into the next segment, in the outbox, or into
    /// several when it is more than a reader takes in one. Returns the last.
    /// Nothing pending, nothing written.
    pub fn close(&mut self, now: i64) -> Result<Option<Segment>, SpoolError> {
        let pending: Vec<(u64, Vec<u8>)> = read_pending(&self.dir.join("pending"))?
            .into_iter()
            .filter(|(number, _)| *number >= self.state.closed_through)
            .collect();
        let mut last = None;
        let mut rest = pending.as_slice();
        while !rest.is_empty() {
            let mut size = SEGMENT_HEADER;
            let mut take = 0;
            for (_, record) in rest {
                let next = size + RECORD_FRAME + record.len();
                if take > 0 && (take == MAX_RECORDS || next as u64 > MAX_SEGMENT_BYTES) {
                    break;
                }
                size = next;
                take += 1;
            }
            let (chunk, after) = rest.split_at(take);
            last = Some(self.close_chunk(chunk, now)?);
            rest = after;
        }
        if last.is_some() {
            self.state.pending_since = None;
            self.save_state()?;
            let _ = fs::remove_file(self.dir.join("pending"));
        }
        Ok(last)
    }

    /// One segment of `records`, written before the state says it exists.
    fn close_chunk(&mut self, records: &[(u64, Vec<u8>)], now: i64) -> Result<Segment, SpoolError> {
        let prev = if self.state.last_hash.is_empty() {
            [0u8; 32]
        } else {
            hex::decode(&self.state.last_hash)
                .ok()
                .and_then(|h| h.try_into().ok())
                .unwrap_or([0u8; 32])
        };
        let through = records
            .iter()
            .map(|(n, _)| *n)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let segment = Segment {
            device: self.device,
            seq: self.state.next_segment,
            prev,
            closed_at: now,
            records: records.iter().map(|(_, r)| r.clone()).collect(),
            tag: None,
        }
        .tag_with(&self.keys.segments);
        write_whole(&self.outbox_path(segment.seq), &segment.to_bytes())?;
        self.state.next_segment = segment.seq + 1;
        self.state.last_hash = hex::encode(segment.hash());
        self.state.closed_through = through;
        self.save_state()?;
        Ok(segment)
    }

    fn outbox_path(&self, seq: u64) -> PathBuf {
        self.dir.join("outbox").join(format!("{seq:012}.seg"))
    }

    /// Closed segments not yet everywhere, oldest first. One that does not
    /// read, or whose tag does not check, is set aside as `.damaged`, kept
    /// but no longer sent: it must not hold back every segment after it.
    /// The reader then names the hole. A `.damaged` one whose tag checks is
    /// sent again: a release before core 1.10, run on this silo after this
    /// one, sets this build's segments aside because it cannot read them.
    pub fn outbox(&self) -> Result<Vec<Segment>, SpoolError> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.dir.join("outbox"))? {
            let path = entry?.path();
            let read = || {
                Segment::from_bytes(&fs::read(&path).ok()?)
                    .ok()
                    .filter(|s| s.proof(&self.keys.segments) != Proof::Forged)
            };
            if path.extension().is_some_and(|e| e == "seg") {
                match read() {
                    Some(segment) => out.push(segment),
                    None => {
                        let _ = fs::rename(&path, path.with_extension("damaged"));
                    }
                }
            } else if path.extension().is_some_and(|e| e == "damaged")
                && let Some(segment) = read().filter(|s| s.tag.is_some())
                && !path.with_extension("seg").exists()
                && fs::rename(&path, path.with_extension("seg")).is_ok()
            {
                out.push(segment);
            }
        }
        out.sort_by_key(|s| s.seq);
        Ok(out)
    }

    /// Every copy holds segment `seq`: it leaves this computer.
    pub fn delivered(&self, seq: u64) -> Result<(), SpoolError> {
        match fs::remove_file(self.outbox_path(seq)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }

    /// Records not in a segment yet, as (event number, sealed record).
    pub fn pending(&self) -> Result<Vec<(u64, Vec<u8>)>, SpoolError> {
        Ok(read_pending(&self.dir.join("pending"))?
            .into_iter()
            .filter(|(n, _)| *n >= self.state.closed_through)
            .collect())
    }

    /// Events waiting, in segments or not: what a lock would leave behind.
    pub fn waiting(&self) -> Result<usize, SpoolError> {
        let pending = read_pending(&self.dir.join("pending"))?
            .into_iter()
            .filter(|(n, _)| *n >= self.state.closed_through)
            .count();
        let queued: usize = self.outbox()?.iter().map(|s| s.records.len()).sum();
        Ok(pending + queued)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditKey, AuditPolicy, Scope};
    use crate::{KeyPair, check_chain, codes, counter_gaps, open_event};

    const KEK: [u8; 32] = [5; 32];

    fn open(root: &Path, device: Uuid) -> Spool {
        Spool::open(root, device, &KEK, Unchecked::Refuse).unwrap()
    }

    fn state_json(root: &Path) -> serde_json::Value {
        serde_json::from_slice(&fs::read(root.join(QUEUE_DIR).join("state.json")).unwrap()).unwrap()
    }

    fn write_state_json(root: &Path, state: &serde_json::Value) {
        fs::write(
            root.join(QUEUE_DIR).join("state.json"),
            serde_json::to_vec(state).unwrap(),
        )
        .unwrap();
    }

    /// A pinned personal log, on, as this build leaves it.
    fn pinned(root: &Path, device: Uuid) -> KeyPair {
        let keys = KeyPair::generate();
        let key = AuditKey::new(&keys, Scope::Silo, 1);
        let on = AuditPolicy::new(true, &keys.id(), None, Scope::Silo, 1);
        open(root, device).apply_policy(&on, &key, 10).unwrap();
        keys
    }

    #[test]
    fn a_key_written_into_the_pin_is_not_sealed_to() {
        let dir = tempfile::tempdir().unwrap();
        let device = Uuid::new_v4();
        let keys = pinned(dir.path(), device);
        // Someone who can write to the silo folder pins a key of their own.
        let theirs = KeyPair::generate();
        let mut state = state_json(dir.path());
        state["pinned"]["key_id"] = hex::encode(theirs.id()).into();
        state["pinned"]["public_key"] = hex::encode(&theirs.public).into();
        write_state_json(dir.path(), &state);

        let mut spool = open(dir.path(), device);
        assert_eq!(spool.pinned().unwrap().key_id, hex::encode(keys.id()));
        spool.record(Event::new(codes::UNLOCKED, 1)).unwrap();
        let segment = spool.close(2).unwrap().unwrap();
        assert!(open_event(&keys.private, device, &segment.records[0]).is_ok());
        assert!(open_event(&theirs.private, device, &segment.records[0]).is_err());
    }

    #[test]
    fn a_pin_and_policy_written_together_into_the_folder_are_both_refused() {
        let dir = tempfile::tempdir().unwrap();
        let device = Uuid::new_v4();
        pinned(dir.path(), device);
        let queue = dir.path().join(QUEUE_DIR);
        let theirs = KeyPair::generate();
        let policy = AuditPolicy::new(true, &theirs.id(), None, Scope::Org, 2);
        fs::write(
            queue.join(POLICY_FILE),
            serde_json::to_vec(&policy).unwrap(),
        )
        .unwrap();
        fs::write(
            queue.join(KEY_FILE),
            AuditKey::new(&theirs, Scope::Org, 2).to_json().unwrap(),
        )
        .unwrap();
        let mut state = state_json(dir.path());
        state["pinned"]["key_id"] = hex::encode(theirs.id()).into();
        state["pinned"]["public_key"] = hex::encode(&theirs.public).into();
        state["pinned"]["scope"] = "org".into();
        state.as_object_mut().unwrap().remove("pin_check");
        write_state_json(dir.path(), &state);

        let mut spool = open(dir.path(), device);
        assert!(spool.pinned().is_none(), "left for the next pass to settle");
        assert!(spool.policy().unwrap().is_none());
        assert!(spool.key().unwrap().is_none());
        assert_eq!(spool.record(Event::new(1, 1)).unwrap(), None);
    }

    #[test]
    fn a_queue_a_release_before_the_check_left_is_taken_in_once() {
        let dir = tempfile::tempdir().unwrap();
        let device = Uuid::new_v4();
        let keys = pinned(dir.path(), device);
        // As 1.9 wrote it: no check on the pin or on the policy.
        let queue = dir.path().join(QUEUE_DIR);
        let mut state = state_json(dir.path());
        state.as_object_mut().unwrap().remove("pin_check");
        state["pinned"].as_object_mut().unwrap().remove("proven");
        write_state_json(dir.path(), &state);
        let mut policy: serde_json::Value =
            serde_json::from_slice(&fs::read(queue.join(POLICY_FILE)).unwrap()).unwrap();
        policy.as_object_mut().unwrap().remove("check");
        fs::write(
            queue.join(POLICY_FILE),
            serde_json::to_vec(&policy).unwrap(),
        )
        .unwrap();

        let spool = Spool::open(dir.path(), device, &KEK, Unchecked::Adopt).unwrap();
        assert_eq!(spool.pinned().unwrap().key_id, hex::encode(keys.id()));
        assert!(
            spool.pinned().unwrap().proven,
            "its own choice, tagged from now"
        );
        assert!(spool.policy().unwrap().is_some());
        drop(spool);
        // Checked from then on.
        let spool = open(dir.path(), device);
        assert_eq!(spool.pinned().unwrap().key_id, hex::encode(keys.id()));
        assert!(state_json(dir.path())["pin_check"].is_string());
    }

    #[test]
    fn a_pin_whose_check_was_taken_away_is_made_again_from_the_kept_policy() {
        let dir = tempfile::tempdir().unwrap();
        let device = Uuid::new_v4();
        let keys = pinned(dir.path(), device);
        let mut state = state_json(dir.path());
        state.as_object_mut().unwrap().remove("pin_check");
        state["pinned"]["enabled"] = false.into();
        write_state_json(dir.path(), &state);

        let spool = open(dir.path(), device);
        let pin = spool.pinned().unwrap();
        assert_eq!(pin.key_id, hex::encode(keys.id()));
        assert!(pin.enabled, "as the kept policy says");
        assert_eq!(pin.checked_at, 0, "read again at the next pass");
        assert!(!pin.proven);
    }

    #[test]
    fn segments_are_tagged_and_a_forged_one_in_the_outbox_is_not_sent() {
        let dir = tempfile::tempdir().unwrap();
        let device = Uuid::new_v4();
        let keys = KeyPair::generate();
        let mut spool = open(dir.path(), device);
        spool.record_to(&keys.public, Event::new(1, 1)).unwrap();
        let first = spool.close(5).unwrap().unwrap();
        assert_eq!(first.proof(&SegmentKey::new(&KEK)), Proof::Tagged);
        spool.record_to(&keys.public, Event::new(2, 2)).unwrap();
        spool.close(6).unwrap();
        // Segment 0 rewritten by someone without the content key.
        let path = dir
            .path()
            .join(QUEUE_DIR)
            .join("outbox")
            .join(format!("{:012}.seg", 0));
        let forged = Segment {
            closed_at: 1,
            ..first.clone()
        };
        fs::write(&path, forged.to_bytes()).unwrap();
        let outbox = spool.outbox().unwrap();
        assert_eq!(outbox.iter().map(|s| s.seq).collect::<Vec<_>>(), vec![1]);
        assert!(path.with_extension("damaged").exists());
    }

    #[test]
    fn a_segment_an_older_release_set_aside_is_sent_again() {
        let dir = tempfile::tempdir().unwrap();
        let device = Uuid::new_v4();
        let keys = KeyPair::generate();
        let mut spool = open(dir.path(), device);
        spool.record_to(&keys.public, Event::new(1, 1)).unwrap();
        spool.close(5).unwrap();
        // What 1.9 does with a segment it cannot read.
        let path = dir
            .path()
            .join(QUEUE_DIR)
            .join("outbox")
            .join(format!("{:012}.seg", 0));
        fs::rename(&path, path.with_extension("damaged")).unwrap();
        let outbox = spool.outbox().unwrap();
        assert_eq!(outbox.len(), 1);
        assert!(path.exists());
    }

    fn events_in(segments: &[Segment], keys: &KeyPair) -> Vec<Event> {
        segments
            .iter()
            .flat_map(|s| {
                s.records
                    .iter()
                    .map(|r| open_event(&keys.private, s.device, r).unwrap())
            })
            .collect()
    }

    #[test]
    fn events_become_numbered_chained_segments() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let mut spool = open(dir.path(), device);
        for _ in 0..3 {
            spool
                .record_to(&keys.public, Event::new(codes::SECRET_COPIED, 1))
                .unwrap();
        }
        let first = spool.close(10).unwrap().unwrap();
        spool
            .record_to(&keys.public, Event::new(codes::LOCKED, 2))
            .unwrap();
        let second = spool.close(20).unwrap().unwrap();
        assert!(spool.close(30).unwrap().is_none(), "nothing pending");

        let segments = spool.outbox().unwrap();
        assert_eq!(segments, vec![first, second]);
        assert!(check_chain(&segments, 0).is_whole());
        let events = events_in(&segments, &keys);
        assert_eq!(
            events.iter().map(|e| e.i).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(spool.waiting().unwrap(), 4);

        spool.delivered(0).unwrap();
        assert_eq!(spool.outbox().unwrap().len(), 1);
    }

    #[test]
    fn nothing_is_recorded_until_the_device_is_told_of_a_log() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = open(dir.path(), Uuid::new_v4());
        assert_eq!(spool.record(Event::new(1, 1)).unwrap(), None);

        let keys = KeyPair::generate();
        let key = AuditKey::new(&keys, Scope::Silo, 1);
        let off = AuditPolicy::new(false, &keys.id(), None, Scope::Silo, 1);
        spool.apply_policy(&off, &key, 10).unwrap();
        assert_eq!(spool.record(Event::new(1, 1)).unwrap(), None, "turned off");

        let on = AuditPolicy::new(true, &keys.id(), Some(365), Scope::Silo, 2);
        assert_eq!(spool.apply_policy(&on, &key, 20).unwrap(), PolicyRead::Kept);
        assert_eq!(spool.record(Event::new(1, 1_000)).unwrap(), Some(0));
        assert!(!spool.due(1_000 + 899_999, 900_000));
        assert!(spool.due(1_000 + 900_000, 900_000));
    }

    #[test]
    fn the_pinned_key_and_policy_are_kept_and_another_key_s_are_not() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = open(dir.path(), Uuid::new_v4());
        assert!(spool.key().unwrap().is_none());
        let keys = KeyPair::generate();
        let key = AuditKey::new(&keys, Scope::Org, 1);
        let on = AuditPolicy::new(true, &keys.id(), Some(90), Scope::Org, 1);
        spool.apply_policy(&on, &key, 10).unwrap();
        assert_eq!(spool.key().unwrap(), Some(key.clone()));
        assert_eq!(spool.policy().unwrap(), Some(on.clone()));

        let theirs = KeyPair::generate();
        let swapped = AuditPolicy::new(false, &theirs.id(), None, Scope::Silo, 2);
        let before = spool.pinned().cloned().unwrap();
        spool
            .apply_policy(&swapped, &AuditKey::new(&theirs, Scope::Silo, 2), 20)
            .unwrap();
        assert_eq!(spool.key().unwrap(), Some(key));
        assert_eq!(spool.policy().unwrap(), Some(on));
        // Not switched off, not made personal, retention unchanged.
        let after = spool.pinned().cloned().unwrap();
        assert_eq!(
            after,
            Pinned {
                checked_at: 20,
                ..before
            }
        );
        assert!(spool.record(Event::new(11, 30)).unwrap().is_some());
    }

    #[test]
    fn a_key_whose_scope_the_policy_does_not_confirm_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = open(dir.path(), Uuid::new_v4());
        let keys = KeyPair::generate();
        // Storage edited the unsealed key file from Org to Silo.
        let key = AuditKey::new(&keys, Scope::Silo, 1);
        let policy = AuditPolicy::new(true, &keys.id(), Some(365), Scope::Org, 1);
        assert!(spool.apply_policy(&policy, &key, 10).is_err());
        assert!(spool.pinned().is_none());
    }

    #[test]
    fn a_personal_log_follows_a_newer_key_and_an_organisation_s_replaces_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = open(dir.path(), Uuid::new_v4());
        let mine = KeyPair::generate();
        let on = AuditPolicy::new(true, &mine.id(), None, Scope::Silo, 1);
        spool
            .apply_policy(&on, &AuditKey::new(&mine, Scope::Silo, 1), 10)
            .unwrap();
        let org = KeyPair::generate();
        let theirs = AuditPolicy::new(true, &org.id(), Some(365), Scope::Org, 2);
        assert_eq!(
            spool
                .apply_policy(&theirs, &AuditKey::new(&org, Scope::Org, 2), 20)
                .unwrap(),
            PolicyRead::Pinned
        );
        assert_eq!(spool.pinned().unwrap().key_id, hex::encode(org.id()));
        assert_eq!(spool.pinned().unwrap().scope, Scope::Org);
    }

    #[test]
    fn an_organisation_log_stays_on_and_its_key_stays_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = open(dir.path(), Uuid::new_v4());
        let keys = KeyPair::generate();
        let key = AuditKey::new(&keys, Scope::Org, 1);
        let policy = AuditPolicy::new(false, &keys.id(), Some(365), Scope::Org, 1);
        assert_eq!(
            spool.apply_policy(&policy, &key, 10).unwrap(),
            PolicyRead::Pinned
        );
        assert!(spool.pinned().unwrap().enabled, "off does not stop it");

        // Someone with the content key names a key of their own.
        let theirs = KeyPair::generate();
        let their_key = AuditKey::new(&theirs, Scope::Org, 2);
        let swapped = AuditPolicy::new(true, &theirs.id(), None, Scope::Org, 2);
        let read = spool.apply_policy(&swapped, &their_key, 20).unwrap();
        assert!(matches!(read, PolicyRead::KeyChanged { .. }));
        assert_eq!(spool.pinned().unwrap().key_id, hex::encode(keys.id()));

        // What it writes still opens with the organisation's key only.
        spool.record(Event::new(11, 5)).unwrap();
        let segment = spool.close(6).unwrap().unwrap();
        assert!(open_event(&keys.private, segment.device, &segment.records[0]).is_ok());
        assert!(open_event(&theirs.private, segment.device, &segment.records[0]).is_err());
    }

    #[test]
    fn the_count_carries_on_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        open(dir.path(), device)
            .record_to(&keys.public, Event::new(1, 1))
            .unwrap();
        let mut again = open(dir.path(), device);
        assert_eq!(again.record_to(&keys.public, Event::new(2, 2)).unwrap(), 1);
    }

    #[test]
    fn a_record_appended_before_the_count_moved_is_not_numbered_twice() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let mut spool = open(dir.path(), device);
        spool.record_to(&keys.public, Event::new(1, 1)).unwrap();
        // Dies after the append, before the state was written.
        let state = dir.path().join(QUEUE_DIR).join("state.json");
        fs::write(
            &state,
            br#"{"next_event":0,"next_segment":0,"last_hash":"","closed_through":0}"#,
        )
        .unwrap();
        drop(spool);

        let mut spool = open(dir.path(), device);
        assert_eq!(spool.record_to(&keys.public, Event::new(2, 2)).unwrap(), 1);
        let segment = spool.close(5).unwrap().unwrap();
        assert!(counter_gaps(&events_in(&[segment], &keys), 0).is_empty());
    }

    #[test]
    fn an_append_cut_short_is_dropped_not_misread() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let mut spool = open(dir.path(), device);
        spool.record_to(&keys.public, Event::new(1, 1)).unwrap();
        let pending = dir.path().join(QUEUE_DIR).join("pending");
        let mut file = OpenOptions::new().append(true).open(&pending).unwrap();
        file.write_all(&[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1]).unwrap();
        drop(spool);

        let mut spool = open(dir.path(), device);
        let segment = spool.close(5).unwrap().unwrap();
        assert_eq!(segment.records.len(), 1);
    }

    #[test]
    fn an_event_after_an_append_cut_short_is_read_whole() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let mut spool = open(dir.path(), device);
        spool.record_to(&keys.public, Event::new(1, 1)).unwrap();
        let pending = dir.path().join(QUEUE_DIR).join("pending");
        let mut file = OpenOptions::new().append(true).open(&pending).unwrap();
        file.write_all(&[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1]).unwrap();
        drop(spool);

        let mut spool = open(dir.path(), device);
        spool.record_to(&keys.public, Event::new(2, 2)).unwrap();
        spool.record_to(&keys.public, Event::new(3, 3)).unwrap();
        let segment = spool.close(5).unwrap().unwrap();
        let events = events_in(&[segment], &keys);
        assert_eq!(
            events.iter().map(|e| (e.c, e.i)).collect::<Vec<_>>(),
            vec![(1, 0), (2, 1), (3, 2)]
        );
    }

    #[test]
    fn more_than_a_segment_holds_goes_into_several_chained_ones() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let mut spool = open(dir.path(), device);
        // 600 records of about 15 KB: more than 8 MiB.
        let big = "x".repeat(15_000);
        for t in 0..600 {
            spool
                .record_to(&keys.public, Event::new(1, t).with("pad", big.as_str()))
                .unwrap();
        }
        spool.close(5).unwrap().unwrap();
        let outbox = spool.outbox().unwrap();
        assert_eq!(outbox.len(), 2);
        assert_eq!(outbox[1].prev, outbox[0].hash());
        for segment in &outbox {
            assert!(segment.to_bytes().len() as u64 <= MAX_SEGMENT_BYTES);
            Segment::from_bytes(&segment.to_bytes()).unwrap();
        }
        assert_eq!(events_in(&outbox, &keys).len(), 600);
        assert!(spool.pending().unwrap().is_empty());
    }

    #[test]
    fn a_damaged_segment_in_the_outbox_does_not_hold_the_rest_back() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let mut spool = open(dir.path(), device);
        spool.record_to(&keys.public, Event::new(1, 1)).unwrap();
        spool.close(5).unwrap();
        spool.record_to(&keys.public, Event::new(2, 2)).unwrap();
        spool.close(6).unwrap();
        let first = dir
            .path()
            .join(QUEUE_DIR)
            .join("outbox")
            .join(format!("{:012}.seg", 0));
        fs::write(&first, b"noise").unwrap();
        let outbox = spool.outbox().unwrap();
        assert_eq!(outbox.iter().map(|s| s.seq).collect::<Vec<_>>(), vec![1]);
        assert!(first.with_extension("damaged").exists());
    }

    #[test]
    fn a_segment_written_before_the_state_moved_is_not_repeated() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let mut spool = open(dir.path(), device);
        spool.record_to(&keys.public, Event::new(1, 1)).unwrap();
        spool.close(5).unwrap();
        // Dies after the state, before the pending file was emptied: what is
        // left there is already in segment 0.
        let queue = dir.path().join(QUEUE_DIR);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(queue.join("pending"))
            .unwrap();
        let sealed = seal_event(&keys.public, device, &{
            let mut e = Event::new(1, 1);
            e.i = 0;
            e
        })
        .unwrap();
        file.write_all(&0u64.to_be_bytes()).unwrap();
        file.write_all(&(sealed.len() as u32).to_be_bytes())
            .unwrap();
        file.write_all(&sealed).unwrap();
        drop(spool);

        let mut spool = open(dir.path(), device);
        assert!(spool.close(6).unwrap().is_none(), "already in a segment");
        spool.record_to(&keys.public, Event::new(2, 2)).unwrap();
        let segments = {
            spool.close(7).unwrap();
            spool.outbox().unwrap()
        };
        let events = events_in(&segments, &keys);
        assert_eq!(events.iter().map(|e| e.i).collect::<Vec<_>>(), vec![0, 1]);
        assert!(check_chain(&segments, 0).is_whole());
    }

    /// A command recording while the sync pass closes a segment: each opens
    /// its own spool, and the lock keeps the count whole.
    #[test]
    fn spools_opened_at_once_take_turns() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let workers: Vec<_> = (0..4)
            .map(|w| {
                let root = dir.path().to_path_buf();
                let public = keys.public.clone();
                std::thread::spawn(move || {
                    for n in 0..25 {
                        let mut spool = open(&root, device);
                        spool.record_to(&public, Event::new(1, n)).unwrap();
                        if (w + n) % 7 == 0 {
                            spool.close(n).unwrap();
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        let mut spool = open(dir.path(), device);
        spool.close(100).unwrap();
        let segments = spool.outbox().unwrap();
        assert!(check_chain(&segments, 0).is_whole());
        let mut numbers: Vec<u64> = events_in(&segments, &keys).iter().map(|e| e.i).collect();
        numbers.sort_unstable();
        assert_eq!(numbers, (0..100).collect::<Vec<_>>());
    }
}

/// Literal value from 1.10: a queue kept across an update must still check.
#[cfg(test)]
mod known_answers {
    use super::*;

    #[test]
    fn the_queue_check_key_is_fixed() {
        assert_eq!(
            hex::encode(*QueueKeys::new(&[0x04; 32]).check),
            "1177ff0208177b506fed21e1affba1ebeab455621977b6780e6c2e0cdbddb46c"
        );
    }
}
