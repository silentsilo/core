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

use crate::{
    AuditError, AuditKey, AuditPolicy, BY_SILO, Event, KeyPair, Scope, Segment, codes, seal_event,
};

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

/// The pending records, as (event number, sealed record).
fn read_pending(path: &Path) -> std::io::Result<Vec<(u64, Vec<u8>)>> {
    let mut bytes = Vec::new();
    match File::open(path) {
        Ok(mut file) => {
            file.read_to_end(&mut bytes)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
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
    Ok(out)
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
        match file.try_lock() {
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
    /// open only for local work: never across a network call.
    pub fn open(silo_root: &Path, device: Uuid) -> Result<Self, SpoolError> {
        let dir = silo_root.join(QUEUE_DIR);
        fs::create_dir_all(dir.join("outbox"))?;
        let lock = take_lock(&dir)?;
        let mut state: State = match fs::read(dir.join("state.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(AuditError::from)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e.into()),
        };
        // Appended and synced, but the count had not moved past it.
        if let Some((last, _)) = read_pending(&dir.join("pending"))?.last() {
            state.next_event = state.next_event.max(last + 1);
        }
        Ok(Self {
            dir,
            device,
            state,
            _lock: lock,
        })
    }

    /// What this device logs to, if it has been told.
    pub fn pinned(&self) -> Option<&Pinned> {
        self.state.pinned.as_ref()
    }

    /// Takes in the policy and the key it names, as read from storage at
    /// `now` (seconds).
    pub fn apply_policy(
        &mut self,
        policy: &AuditPolicy,
        key: &AuditKey,
        now: i64,
    ) -> Result<PolicyRead, SpoolError> {
        if key.key_id != policy.key_id {
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
        let (key_id, public_key) = match (&read, &self.state.pinned) {
            (PolicyRead::KeyChanged { .. }, Some(pinned)) => {
                (pinned.key_id.clone(), pinned.public_key.clone())
            }
            _ => (policy.key_id.clone(), public),
        };
        self.state.pinned = Some(Pinned {
            key_id,
            public_key,
            // An organisation's log does not stop because its policy says so.
            enabled: policy.enabled || key.scope == Scope::Org,
            scope: key.scope,
            retention_days: policy.retention_days,
            checked_at: now,
        });
        // Another key's policy is not kept: it is not this device's log.
        if !matches!(read, PolicyRead::KeyChanged { .. }) {
            write_whole(&self.dir.join(KEY_FILE), &key.to_json()?)?;
            write_whole(
                &self.dir.join(POLICY_FILE),
                &serde_json::to_vec(policy).map_err(AuditError::from)?,
            )?;
        }
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
                write_whole(&self.dir.join(KEY_FILE), &key.to_json()?)?;
                Ok(())
            }
            _ => Err(AuditError::BadKey.into()),
        }
    }

    /// The pinned log's key, as storage holds it.
    pub fn key(&self) -> Result<Option<AuditKey>, SpoolError> {
        match fs::read(self.dir.join(KEY_FILE)) {
            Ok(bytes) => Ok(Some(AuditKey::from_json(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The pinned log's policy, as this device last took it in.
    pub fn policy(&self) -> Result<Option<AuditPolicy>, SpoolError> {
        match fs::read(self.dir.join(POLICY_FILE)) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).map_err(AuditError::from)?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn save_state(&self) -> Result<(), SpoolError> {
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
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("pending"))?;
        file.write_all(&event.i.to_be_bytes())?;
        file.write_all(&(sealed.len() as u32).to_be_bytes())?;
        file.write_all(&sealed)?;
        file.sync_all()?;
        self.state.next_event = event.i + 1;
        if self.state.pending_since.is_none() {
            self.state.pending_since = Some(event.t);
        }
        self.save_state()?;
        Ok(event.i)
    }

    /// Turns what is pending into the next segment, in the outbox. Nothing
    /// pending, nothing written.
    pub fn close(&mut self, now: i64) -> Result<Option<Segment>, SpoolError> {
        let pending: Vec<(u64, Vec<u8>)> = read_pending(&self.dir.join("pending"))?
            .into_iter()
            .filter(|(number, _)| *number >= self.state.closed_through)
            .collect();
        if pending.is_empty() {
            return Ok(None);
        }
        let prev = if self.state.last_hash.is_empty() {
            [0u8; 32]
        } else {
            hex::decode(&self.state.last_hash)
                .ok()
                .and_then(|h| h.try_into().ok())
                .unwrap_or([0u8; 32])
        };
        let through = pending.iter().map(|(n, _)| *n).max().unwrap_or(0) + 1;
        let segment = Segment {
            device: self.device,
            seq: self.state.next_segment,
            prev,
            closed_at: now,
            records: pending.into_iter().map(|(_, r)| r).collect(),
        };
        write_whole(&self.outbox_path(segment.seq), &segment.to_bytes())?;
        self.state.next_segment = segment.seq + 1;
        self.state.last_hash = hex::encode(segment.hash());
        self.state.closed_through = through;
        self.state.pending_since = None;
        self.save_state()?;
        let _ = fs::remove_file(self.dir.join("pending"));
        Ok(Some(segment))
    }

    fn outbox_path(&self, seq: u64) -> PathBuf {
        self.dir.join("outbox").join(format!("{seq:012}.seg"))
    }

    /// Closed segments not yet everywhere, oldest first.
    pub fn outbox(&self) -> Result<Vec<Segment>, SpoolError> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.dir.join("outbox"))? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "seg") {
                out.push(Segment::from_bytes(&fs::read(&path)?)?);
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
        let mut spool = Spool::open(dir.path(), device).unwrap();
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
        let mut spool = Spool::open(dir.path(), Uuid::new_v4()).unwrap();
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
        let mut spool = Spool::open(dir.path(), Uuid::new_v4()).unwrap();
        assert!(spool.key().unwrap().is_none());
        let keys = KeyPair::generate();
        let key = AuditKey::new(&keys, Scope::Org, 1);
        let on = AuditPolicy::new(true, &keys.id(), Some(90), Scope::Org, 1);
        spool.apply_policy(&on, &key, 10).unwrap();
        assert_eq!(spool.key().unwrap(), Some(key.clone()));
        assert_eq!(spool.policy().unwrap(), Some(on.clone()));

        let theirs = KeyPair::generate();
        let swapped = AuditPolicy::new(false, &theirs.id(), None, Scope::Silo, 2);
        spool
            .apply_policy(&swapped, &AuditKey::new(&theirs, Scope::Silo, 2), 20)
            .unwrap();
        assert_eq!(spool.key().unwrap(), Some(key));
        assert_eq!(spool.policy().unwrap(), Some(on));
    }

    #[test]
    fn a_personal_log_follows_a_newer_key_and_an_organisation_s_replaces_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = Spool::open(dir.path(), Uuid::new_v4()).unwrap();
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
        let mut spool = Spool::open(dir.path(), Uuid::new_v4()).unwrap();
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
        Spool::open(dir.path(), device)
            .unwrap()
            .record_to(&keys.public, Event::new(1, 1))
            .unwrap();
        let mut again = Spool::open(dir.path(), device).unwrap();
        assert_eq!(again.record_to(&keys.public, Event::new(2, 2)).unwrap(), 1);
    }

    #[test]
    fn a_record_appended_before_the_count_moved_is_not_numbered_twice() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let mut spool = Spool::open(dir.path(), device).unwrap();
        spool.record_to(&keys.public, Event::new(1, 1)).unwrap();
        // Dies after the append, before the state was written.
        let state = dir.path().join(QUEUE_DIR).join("state.json");
        fs::write(
            &state,
            br#"{"next_event":0,"next_segment":0,"last_hash":"","closed_through":0}"#,
        )
        .unwrap();
        drop(spool);

        let mut spool = Spool::open(dir.path(), device).unwrap();
        assert_eq!(spool.record_to(&keys.public, Event::new(2, 2)).unwrap(), 1);
        let segment = spool.close(5).unwrap().unwrap();
        assert!(counter_gaps(&events_in(&[segment], &keys), 0).is_empty());
    }

    #[test]
    fn an_append_cut_short_is_dropped_not_misread() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let mut spool = Spool::open(dir.path(), device).unwrap();
        spool.record_to(&keys.public, Event::new(1, 1)).unwrap();
        let pending = dir.path().join(QUEUE_DIR).join("pending");
        let mut file = OpenOptions::new().append(true).open(&pending).unwrap();
        file.write_all(&[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1]).unwrap();
        drop(spool);

        let mut spool = Spool::open(dir.path(), device).unwrap();
        let segment = spool.close(5).unwrap().unwrap();
        assert_eq!(segment.records.len(), 1);
    }

    #[test]
    fn a_segment_written_before_the_state_moved_is_not_repeated() {
        let dir = tempfile::tempdir().unwrap();
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let mut spool = Spool::open(dir.path(), device).unwrap();
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

        let mut spool = Spool::open(dir.path(), device).unwrap();
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
                        let mut spool = Spool::open(&root, device).unwrap();
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
        let mut spool = Spool::open(dir.path(), device).unwrap();
        spool.close(100).unwrap();
        let segments = spool.outbox().unwrap();
        assert!(check_chain(&segments, 0).is_whole());
        let mut numbers: Vec<u64> = events_in(&segments, &keys).iter().map(|e| e.i).collect();
        numbers.sort_unstable();
        assert_eq!(numbers, (0..100).collect::<Vec<_>>());
    }
}
