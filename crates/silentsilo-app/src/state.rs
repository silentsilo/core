use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use silentsilo_core::{CoreError, CoreResult};
use silentsilo_vault::{SiloEntry, VaultSession};
use silentsilo_vfs::Vfs;
use uuid::Uuid;

use crate::Host;

/// The most silos that may be unlocked at the same time.
///
/// Each open silo means a decrypted index and a set of keys in memory, so
/// the number of them is the size of what a compromised process gets while
/// the user is unlocked. Switching between silos all day
/// would otherwise leave every one of them open, which is not something a
/// person would choose deliberately.
pub const MAX_OPEN_SILOS: usize = 3;

#[derive(Default)]
pub struct AppState {
    /// Which silo the app is currently pointed at.
    ///
    /// Everything path-shaped reads through this, so switching silos is a
    /// matter of changing it rather than of threading an id through every
    /// command. `None` only before the first one is opened.
    pub active_silo: Mutex<Option<SiloEntry>>,
    /// Every silo currently unlocked, keyed by id. More than one may be
    /// open so switching costs nothing; the alternative is a key tap every
    /// time somebody moves between work and personal. Bounded by
    /// [`MAX_OPEN_SILOS`]; see [`AppState::open_session`] for the limit.
    pub sessions: Mutex<HashMap<Uuid, VaultSession>>,
    /// When each open silo was last used, for the idle timer and for
    /// deciding which one to close when the limit is reached.
    pub last_touched: Mutex<HashMap<Uuid, Instant>>,
    /// Set by `cancel_import`, checked between items by the long-running
    /// folder/paste import commands (which run as one blocking call, so a
    /// JS-side abort signal can't reach them directly). Callers reset it via
    /// `reset_import_cancel` before starting a new cancellable batch.
    pub import_cancelled: AtomicBool,
    /// Set by `cancel_verify`, checked between objects by `vault_verify`.
    /// Same pattern as `import_cancelled`: the check runs as one blocking
    /// invoke, so a JS-side abort signal cannot reach it directly. Reset at
    /// the start of every run rather than by a separate command.
    pub verify_cancelled: AtomicBool,
    /// Set by `cancel_seed`, checked between objects by `backup_target_seed`.
    /// Stopping a seed is safe: what already landed stays, and the next run
    /// skips it and carries on.
    pub seed_cancelled: AtomicBool,
    /// Which silos have a pass running, and whether a key operation holds
    /// every pass off. Per silo: two passes over one silo would read the
    /// same pending queue and upload it twice, but a large upload on one
    /// silo has no reason to stop another from syncing.
    pub(crate) sync_locks: Mutex<SyncLocks>,
    /// Content that would not go to a copy, or come down from any, and when
    /// to try it again. In memory only: one more attempt after a restart is
    /// cheap, and a file refused for its size is not sent again every pass.
    pub(crate) blob_waits: Mutex<HashMap<(Uuid, Uuid), BlobWait>>,
    /// Silos this process has seen keep an organisation's log. Never
    /// forgotten while it runs: a queue that later cannot be read must not
    /// make such a silo look like one that may go on unrecorded.
    pub(crate) audit_org: Mutex<HashSet<Uuid>>,
    /// Each open silo's activity log as read so far, so the next read opens
    /// only new segments. The log in clear: forgotten when the silo closes
    /// ([`AppState::forget_audit_read`]), never written anywhere.
    pub(crate) audit_opened: Mutex<HashMap<Uuid, silentsilo_audit::reading::Opened>>,
    /// How each open silo was unlocked, and when the user last proved they
    /// were there (the unlock itself, or a confirmation since).
    pub(crate) unlocked: Mutex<HashMap<Uuid, (crate::Unlocked, Instant)>>,
}

/// What [`AppState::sync_locks`] holds.
#[derive(Default)]
pub(crate) struct SyncLocks {
    pub(crate) held: bool,
    pub(crate) running: HashSet<Uuid>,
    /// A key operation is waiting for the running passes to end: no new pass
    /// starts until then. Renewed by every try, so a caller that gives up
    /// lets passes start again a few seconds later.
    pub(crate) wanted_until: Option<Instant>,
}

/// How long one failed `try_hold_sync` keeps new passes from starting.
const HOLD_WANTED_FOR: std::time::Duration = std::time::Duration::from_secs(5);

/// One blob's failures on one copy.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlobWait {
    pub(crate) fails: u32,
    pub(crate) next_try: i64,
}

/// Held while a pass runs over one silo. Released on drop, so an error or
/// an early return cannot leave that silo's sync off for the session.
pub(crate) struct PassGuard<'a> {
    state: &'a AppState,
    silo: Uuid,
}

impl Drop for PassGuard<'_> {
    fn drop(&mut self) {
        self.state.locks().running.remove(&self.silo);
    }
}

/// A silo's activity log, as this device knows it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AuditStatus {
    pub enabled: bool,
    /// This computer holds the log's key: there is a log to read, on or off.
    pub kept: bool,
    /// Kept by an organisation: on for good, read with an organisation key.
    pub organisation: bool,
    pub retention_days: Option<u32>,
    /// Events on this computer not yet on every copy.
    pub waiting: usize,
}

/// The focused silo's session, held for as long as the caller needs it.
///
/// Deliberately shaped like the `Option<VaultSession>` this replaced, so
/// that every command asking "is a silo open, and which" reads the same as
/// it did when only one could be. Which silo it resolves to is the one
/// question they don't have to ask.
pub struct SessionGuard<'a> {
    sessions: std::sync::MutexGuard<'a, HashMap<Uuid, VaultSession>>,
    focused: Option<Uuid>,
}

impl SessionGuard<'_> {
    pub fn as_ref(&self) -> Option<&VaultSession> {
        self.sessions.get(&self.focused?)
    }

    pub fn is_some(&self) -> bool {
        self.as_ref().is_some()
    }

    pub fn is_none(&self) -> bool {
        !self.is_some()
    }
}

/// The cheap-to-clone parts of the focused silo's session, taken under a
/// lock held only for the copy. This is what lets encryption run without
/// the sessions mutex, which every command funnels through: holding it for
/// the length of a large file freezes the window for exactly that long.
/// The short per-item commits go back through [`AppState::with_session_id`].
pub struct SessionSnapshot {
    pub id: Uuid,
    pub root: PathBuf,
    pub kek: silentsilo_crypto::ContentKek,
}

impl AppState {
    fn locks(&self) -> std::sync::MutexGuard<'_, SyncLocks> {
        // Two plain fields that no panic leaves half written.
        self.sync_locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Starts a pass over `silo`, unless one is running there already or a
    /// key operation holds sync off.
    pub(crate) fn try_start_pass(&self, silo: Uuid) -> Option<PassGuard<'_>> {
        let mut locks = self.locks();
        let wanted = locks
            .wanted_until
            .is_some_and(|until| Instant::now() < until);
        if locks.held || wanted || !locks.running.insert(silo) {
            return None;
        }
        Some(PassGuard { state: self, silo })
    }

    /// Whether a pass over `silo` is running, or sync is held off.
    pub fn pass_running(&self, silo: Uuid) -> bool {
        let locks = self.locks();
        locks.held || locks.running.contains(&silo)
    }

    /// Whether any pass is running, or sync is held off.
    pub fn sync_busy(&self) -> bool {
        let locks = self.locks();
        locks.held || !locks.running.is_empty()
    }

    /// Holds every pass off, when none is running and nothing else holds
    /// them. For a key operation that rewrites what a pass reads: a pass
    /// that loaded the key file before the change and saved it after put
    /// the old envelopes back. Released with [`AppState::release_sync_hold`].
    pub fn try_hold_sync(&self) -> bool {
        let mut locks = self.locks();
        if locks.held || !locks.running.is_empty() {
            // Passes keep starting otherwise, back to back with work left,
            // and the moment none runs may never come.
            if !locks.held {
                locks.wanted_until = Some(Instant::now() + HOLD_WANTED_FOR);
            }
            return false;
        }
        locks.held = true;
        locks.wanted_until = None;
        true
    }

    pub fn release_sync_hold(&self) {
        self.locks().held = false;
    }

    /// Locks `active_silo` before `sessions`, and never the other way
    /// round: the two are taken together often enough for the order to
    /// matter.
    pub fn focused_session(&self) -> Result<SessionGuard<'_>, String> {
        let focused = self
            .active_silo
            .lock()
            .map_err(|e| e.to_string())?
            .as_ref()
            .map(|s| s.id);
        Ok(SessionGuard {
            sessions: self.sessions.lock().map_err(|e| e.to_string())?,
            focused,
        })
    }

    /// Adds a freshly unlocked silo, closing the least recently used one if
    /// that would take the count past [`MAX_OPEN_SILOS`].
    ///
    /// Returns the silo that was closed to make room, so the caller can say
    /// so rather than leaving the user to discover it.
    pub fn open_session(
        &self,
        host: &dyn Host,
        id: Uuid,
        session: VaultSession,
    ) -> Result<Option<Uuid>, String> {
        let mut sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        let mut touched = self.last_touched.lock().map_err(|e| e.to_string())?;

        let evicted = if sessions.contains_key(&id) || sessions.len() < MAX_OPEN_SILOS {
            None
        } else {
            // Oldest by last use. A silo with no recorded touch is one that
            // was opened and never used, which makes it the best candidate,
            // so a missing entry sorts as maximally stale.
            stalest(sessions.keys().copied(), &touched).inspect(|stale| {
                if let Some(old) = sessions.remove(stale) {
                    close_one(host, old);
                }
                self.forget_audit_read(*stale);
                self.forget_unlocked(*stale);
                touched.remove(stale);
            })
        };

        sessions.insert(id, session);
        touched.insert(id, Instant::now());
        // Whatever an earlier session of this silo was opened with does not
        // carry over; the caller records this one with `set_unlocked`.
        self.forget_unlocked(id);
        Ok(evicted)
    }

    /// Closes one silo, leaving any others open.
    pub fn close_session(&self, host: &dyn Host, id: Uuid) -> Result<(), String> {
        let closed = self.sessions.lock().map_err(|e| e.to_string())?.remove(&id);
        self.forget_audit_read(id);
        self.forget_unlocked(id);
        if let Ok(mut touched) = self.last_touched.lock() {
            touched.remove(&id);
        }
        if let Some(session) = closed {
            close_one(host, session);
        }
        Ok(())
    }

    /// Records how silo `id` was opened, after its session entered the
    /// state. The unlock counts as the first confirmation.
    pub fn set_unlocked(&self, id: Uuid, how: crate::Unlocked) {
        self.unlocked_map().insert(id, (how, Instant::now()));
    }

    /// How silo `id` was opened. [`crate::Unlocked::Fresh`] when nothing
    /// was recorded, which never skips a check a credential would need.
    pub fn unlocked(&self, id: Uuid) -> crate::Unlocked {
        self.unlocked_map()
            .get(&id)
            .map(|(how, _)| how.clone())
            .unwrap_or(crate::Unlocked::Fresh)
    }

    /// Notes that the user just confirmed something on silo `id`.
    pub fn note_confirmed(&self, id: Uuid) {
        if let Some((_, at)) = self.unlocked_map().get_mut(&id) {
            *at = Instant::now();
        }
    }

    /// When the user last proved they were there on silo `id`.
    pub fn last_confirmed(&self, id: Uuid) -> Option<Instant> {
        self.unlocked_map().get(&id).map(|(_, at)| *at)
    }

    /// What `action` needs on silo `id` right now: [`crate::confirmation_for`]
    /// for how it was opened, unless a confirmation inside `grace` covers it.
    pub fn confirmation_needed(
        &self,
        id: Uuid,
        action: crate::Action,
        means: crate::DeviceMeans,
        grace: std::time::Duration,
    ) -> crate::Confirmation {
        let needed = crate::confirmation_for(action, &self.unlocked(id), means);
        if needed != crate::Confirmation::None
            && crate::within_grace(self.last_confirmed(id), Instant::now(), grace)
        {
            return crate::Confirmation::None;
        }
        needed
    }

    /// Drops how silo `id` was opened. [`Self::open_session`] and
    /// [`Self::close_session`] call it; a host that keeps its own sessions
    /// calls it on every open and close.
    pub fn forget_unlocked(&self, id: Uuid) {
        self.unlocked_map().remove(&id);
    }

    fn unlocked_map(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, (crate::Unlocked, Instant)>> {
        // A plain map no panic leaves half written.
        self.unlocked
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Drops what was read of a silo's activity log. Every path that closes
    /// a silo calls it, the client's own included.
    pub fn forget_audit_read(&self, id: Uuid) {
        let mut opened = self
            .audit_opened
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        opened.remove(&id);
    }

    /// Whether anything read of a silo's activity log is held in memory.
    pub fn holds_audit_read(&self, id: Uuid) -> bool {
        self.audit_opened
            .lock()
            .map(|held| held.contains_key(&id))
            .unwrap_or(false)
    }

    /// Records `event` in the open silo's activity log. `Ok(None)` when the
    /// silo keeps none. An error means the event could not be written on
    /// this computer; on a silo whose log is an organisation's
    /// ([`audit_is_mandatory`]), the client locks it rather than go on
    /// unrecorded.
    ///
    /// [`audit_is_mandatory`]: AppState::audit_is_mandatory
    pub fn audit_record(
        &self,
        id: Uuid,
        event: silentsilo_audit::Event,
    ) -> Result<Option<u64>, String> {
        let mut spool = self.audit_spool(id)?;
        spool.record(event).map_err(|e| e.to_string())
    }

    /// Whether the open silo's log is an organisation's, which this device
    /// may not go on without. Once seen, remembered: a queue that can no
    /// longer be read still answers yes.
    pub fn audit_is_mandatory(&self, id: Uuid) -> bool {
        // A poisoned lock answers yes: wrongly locking beats going on
        // unrecorded.
        if self
            .audit_org
            .lock()
            .map(|org| org.contains(&id))
            .unwrap_or(true)
        {
            return true;
        }
        self.audit_spool(id).is_ok_and(|spool| {
            spool
                .pinned()
                .is_some_and(|p| p.scope == silentsilo_audit::Scope::Org)
        })
    }

    /// The open silo's log as this device knows it.
    pub fn audit_status(&self, id: Uuid) -> Result<AuditStatus, String> {
        let spool = self.audit_spool(id)?;
        let pinned = spool.pinned();
        Ok(AuditStatus {
            enabled: pinned.is_some_and(|p| p.enabled),
            kept: spool.key().map_err(|e| e.to_string())?.is_some(),
            organisation: pinned.is_some_and(|p| p.scope == silentsilo_audit::Scope::Org),
            retention_days: pinned.and_then(|p| p.retention_days),
            waiting: spool.waiting().map_err(|e| e.to_string())?,
        })
    }

    /// Turns the open silo's own log on or off: on this device at once,
    /// with no copies needed, and on every copy at the next pass. A log this
    /// device already knows is turned back on under the same key. An
    /// organisation's log stays on.
    pub fn set_audit_log(&self, id: Uuid, enabled: bool) -> Result<(), String> {
        use silentsilo_audit::{AuditKey, AuditPolicy, BY_SILO, Event, KeyPair, Scope, codes};

        let kek = {
            let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
            sessions
                .get(&id)
                .ok_or(silentsilo_core::coded!(
                    "err.silo_not_open",
                    "That silo is not open."
                ))?
                .kek
                .clone()
        };
        let mut spool = self.audit_spool(id)?;
        if spool.pinned().is_some_and(|p| p.scope == Scope::Org) {
            return Err(silentsilo_core::coded!(
                "err.audit_org_stays_on",
                "This silo's activity log is kept by its organisation and stays on."
            )
            .into());
        }
        let known = spool.key().map_err(|e| e.to_string())?;
        if spool.pinned().is_some() && known.is_none() {
            return Err(silentsilo_core::coded!(
                "err.audit_key_missing",
                "This computer has not received the activity log's key yet. Sync, then try again."
            )
            .into());
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let now = now_ms / 1000;
        // Off chosen before the log ever started is kept too, under a key of
        // its own: otherwise the next pass would start it by default.
        let key = match known {
            Some(key) => key,
            None => {
                let keys = KeyPair::generate();
                let mut key = AuditKey::new(&keys, Scope::Silo, now);
                key.wrap_for(BY_SILO, &keys.private, kek.as_bytes())
                    .map_err(|e| e.to_string())?;
                key
            }
        };
        let key_id: silentsilo_audit::KeyId = hex::decode(&key.key_id)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(silentsilo_core::coded!(
                "err.audit_key_damaged",
                "The activity log's key is damaged."
            ))?;
        let previous = spool.policy().map_err(|e| e.to_string())?;
        // After the policy it replaces, even on a clock that is behind.
        let changed_at = previous.as_ref().map_or(now, |p| p.next_changed_at(now));
        let retention = previous.and_then(|p| p.retention_days);

        let at = |code| Event::new(code, now_ms);
        if !enabled {
            spool
                .record(at(codes::LOG_STOPPED))
                .map_err(|e| e.to_string())?;
        }
        let policy = AuditPolicy::new(enabled, &key_id, retention, Scope::Silo, changed_at);
        // Checked at 0: the next pass reads the copies and publishes this.
        spool
            .apply_policy(&policy, &key, 0)
            .map_err(|e| e.to_string())?;
        if enabled {
            spool
                .record(at(codes::LOG_STARTED))
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// The log is on by default. A silo with copies gets it at its first
    /// sync pass, once every copy has answered that nobody set it; one with
    /// no copies has nobody to ask, and gets it here, when it is opened.
    /// Nothing happens once the log was ever set, on or off.
    pub fn start_audit_by_default(&self, host: &dyn Host, id: Uuid) -> Result<(), String> {
        if !host.targets(id).is_empty() {
            return Ok(());
        }
        let kek = {
            let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
            sessions
                .get(&id)
                .ok_or(silentsilo_core::coded!(
                    "err.silo_not_open",
                    "That silo is not open."
                ))?
                .kek
                .clone()
        };
        let mut spool = self.audit_spool(id)?;
        if spool.pinned().is_some() || spool.policy().map_err(|e| e.to_string())?.is_some() {
            return Ok(());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        silentsilo_audit::start_silo_log(&mut spool, kek.as_bytes(), now)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// The open silo's queue, noting on the way whether its log is an
    /// organisation's. Opened outside the sessions lock: it may wait for
    /// the sync pass.
    pub(crate) fn audit_spool(&self, id: Uuid) -> Result<silentsilo_audit::Spool, String> {
        let (root, device, kek, unchecked) = {
            let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
            let session = sessions.get(&id).ok_or(silentsilo_core::coded!(
                "err.silo_not_open",
                "That silo is not open."
            ))?;
            (
                session.paths.root.clone(),
                silentsilo_vfs::device_id(&session.conn).map_err(|e| e.to_string())?,
                session.kek.clone(),
                queue_unchecked(session),
            )
        };
        let spool = silentsilo_audit::Spool::open(&root, device, kek.as_bytes(), unchecked)
            .map_err(|e| e.to_string())?;
        // Without waiting: a close holds the sessions lock while it opens
        // this spool. Missed now, it is noted at the next open.
        if unchecked == silentsilo_audit::Unchecked::Adopt
            && let Ok(sessions) = self.sessions.try_lock()
            && let Some(session) = sessions.get(&id)
        {
            queue_checked(session);
        }
        if spool
            .pinned()
            .is_some_and(|p| p.scope == silentsilo_audit::Scope::Org)
            && let Ok(mut org) = self.audit_org.lock()
        {
            org.insert(id);
        }
        Ok(spool)
    }

    /// Removes the plaintext scratch of every silo that is not open, including
    /// what a crash or kill left behind, and keeps their ciphered working
    /// copies. The client calls it at start and after each lock; not from
    /// `close_session`, so that tests sharing a work base do not sweep each
    /// other. Returns how many directories still hold plaintext.
    pub fn sweep_scratch(&self) -> usize {
        let roots: Vec<PathBuf> = self
            .sessions
            .lock()
            .map(|s| {
                s.values()
                    .map(|session| session.paths.root.clone())
                    .collect()
            })
            .unwrap_or_default();
        let open: Vec<&Path> = roots.iter().map(|r| r.as_path()).collect();
        silentsilo_vault::wipe_work_dirs_except(&open)
    }

    pub fn open_silo_ids(&self) -> Vec<Uuid> {
        self.sessions
            .lock()
            .map(|s| s.keys().copied().collect())
            .unwrap_or_default()
    }

    /// The id of the silo the user is looking at.
    pub fn focused_id(&self) -> Result<Uuid, String> {
        self.active_silo
            .lock()
            .map_err(|e| e.to_string())?
            .as_ref()
            .map(|s| s.id)
            .ok_or_else(|| "No silo is open".to_string())
    }

    /// Whether a named silo is still unlocked.
    ///
    /// Long operations pin a silo and then work item by item without holding
    /// the sessions lock, so it can close underneath them: the idle sweep does
    /// not do it, because every step touches the silo, but locking the
    /// workstation and walking away does, and so does opening a fourth silo.
    /// Asked between items, this is what tells "that one file was locked by
    /// another program" apart from "the silo is gone and nothing else will
    /// succeed either".
    pub fn session_is_open(&self, id: Uuid) -> bool {
        self.sessions
            .lock()
            .map(|sessions| sessions.contains_key(&id))
            .unwrap_or(false)
    }

    /// Records that a silo was used just now.
    ///
    /// This is what the idle timer measures against, so it has to be called
    /// on the way through anything the user did, which is why it lives in the
    /// two accessors every command already goes through, rather than being
    /// something each command has to remember.
    pub fn touch(&self, id: Uuid) {
        if let Ok(mut seen) = self.last_touched.lock() {
            seen.insert(id, Instant::now());
        }
    }

    /// How long each open silo has gone unused, in seconds.
    pub fn idle_seconds(&self) -> Vec<(Uuid, u64)> {
        let Ok(seen) = self.last_touched.lock() else {
            return Vec::new();
        };
        let now = Instant::now();
        seen.iter()
            .map(|(id, at)| (*id, now.saturating_duration_since(*at).as_secs()))
            .collect()
    }

    pub fn with_vfs<F, T>(&self, f: F) -> Result<T, String>
    where
        F: FnOnce(&VaultSession, &Vfs<'_>) -> CoreResult<T>,
    {
        let id = self.focused_id()?;
        self.with_session_id(id, f)
    }

    /// Short-lock access to one specific open silo, named by id.
    ///
    /// For long operations, which pin the silo they started on rather than
    /// re-reading the focus per step: an import that resolved "the focused
    /// silo" on every file would follow the user into a different silo
    /// mid-batch and write the rest of the files there.
    pub fn with_session_id<F, T>(&self, id: Uuid, f: F) -> Result<T, String>
    where
        F: FnOnce(&VaultSession, &Vfs<'_>) -> CoreResult<T>,
    {
        let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        let session = sessions
            .get(&id)
            .ok_or_else(|| CoreError::VaultLocked.to_string())?;
        self.touch(id);
        let vfs = Vfs::new(session);
        f(session, &vfs).map_err(|e| e.to_string())
    }

    pub fn snapshot_focused_session(&self) -> Result<SessionSnapshot, String> {
        let id = self.focused_id()?;
        let sessions = self.sessions.lock().map_err(|e| e.to_string())?;
        let session = sessions
            .get(&id)
            .ok_or_else(|| CoreError::VaultLocked.to_string())?;
        self.touch(id);
        Ok(SessionSnapshot {
            id,
            root: session.paths.root.clone(),
            kek: session.kek.clone(),
        })
    }

    /// Writes every open silo's snapshot before lock or app exit.
    ///
    /// Every open silo, not only the focused one: they all have unsaved work
    /// by the same argument, and the reason to flush (the app is going away)
    /// does not distinguish between them.
    pub fn flush_all(&self, host: &dyn Host) {
        let Ok(sessions) = self.sessions.lock() else {
            return;
        };
        for session in sessions.values() {
            if let Err(e) = session.backup_locally() {
                host.warn("flush", &format!("local snapshot failed: {e}"));
            }
        }
    }
}

/// Which open silo has gone longest without being used.
///
/// A silo with no recorded touch was opened and never used, which makes it
/// the best thing to close, and `None` sorting below every `Some` gives that
/// for free, which is worth stating because it is the kind of ordering that
/// is easy to get backwards.
fn stalest(ids: impl Iterator<Item = Uuid>, touched: &HashMap<Uuid, Instant>) -> Option<Uuid> {
    ids.min_by_key(|id| touched.get(id).copied())
}

/// Snapshots a session and clears the plaintext it was working through. The
/// ciphered working copy stays, so the next unlock reuses it.
///
/// The session is dropped before anything is removed: Windows will not
/// delete a file that still has an open handle.
fn close_one(host: &dyn Host, session: VaultSession) {
    log_lock(host, &session);
    if let Err(e) = session.seal_for_lock() {
        host.warn("lock", &format!("local snapshot failed: {e}"));
    }
    let paths = session.paths.clone();
    drop(session);
    silentsilo_vault::wipe_plaintext_working_copy(&paths);
}

/// The lock as the session's last event, and the batch it ends closed into a
/// segment at once: the next pass sends it, whenever that is.
fn log_lock(host: &dyn Host, session: &VaultSession) {
    if let Err(e) = record_lock(session) {
        host.warn("audit", &e);
    }
}

/// What [`AppState::close_session`] records as it locks, for a client that
/// closes its sessions itself. Call it before the session is dropped.
pub fn record_lock(session: &VaultSession) -> Result<(), String> {
    let device = silentsilo_vfs::device_id(&session.conn).map_err(|e| e.to_string())?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let unchecked = queue_unchecked(session);
    let recorded = silentsilo_audit::Spool::open(
        &session.paths.root,
        device,
        session.kek.as_bytes(),
        unchecked,
    )
    .and_then(|mut spool| {
        spool.record(silentsilo_audit::Event::new(
            silentsilo_audit::codes::LOCKED,
            now_ms,
        ))?;
        spool.close(now_ms).map(|_| ())
    })
    .map_err(|e| e.to_string());
    if recorded.is_ok() && unchecked == silentsilo_audit::Unchecked::Adopt {
        queue_checked(session);
    }
    recorded
}

/// Set in the silo's index once this build has opened its activity queue.
/// The index is under the DEK, out of reach of whoever can write to the
/// silo folder, so a pin there without a check is not mistaken for one a
/// release before the check left.
const QUEUE_CHECKED: &str = "audit_queue_checked";

/// What the queue does with a pin that has no check: taken in until this
/// build has opened the queue once, refused after.
pub(crate) fn queue_unchecked(session: &VaultSession) -> silentsilo_audit::Unchecked {
    match Vfs::new(session).get_meta(QUEUE_CHECKED) {
        Ok(Some(_)) => silentsilo_audit::Unchecked::Refuse,
        // An index that cannot say is read as one that has not been told.
        _ => silentsilo_audit::Unchecked::Adopt,
    }
}

/// Notes that the queue has been opened by a build that checks it.
pub(crate) fn queue_checked(session: &VaultSession) {
    let _ = Vfs::new(session).set_meta(QUEUE_CHECKED, "1");
}

/// Where a file goes when the user opens it rather than exporting it.
///
/// Under the vault's own directory, not the shared OS temp dir, which many
/// other processes read routinely: indexers, backup agents, antivirus.
pub fn open_scratch_dir(vault_root: &Path) -> PathBuf {
    silentsilo_vault::work_dir_for(vault_root).join("open")
}

/// Shreds every decrypted copy left behind by opening files.
///
/// Called on lock and on exit, so plaintext never outlives the session that
/// asked for it. Best-effort: an application still holding a file open will
/// block it on Windows, and failing the lock over that would be worse than
/// one file surviving until the next attempt, which is why this also runs
/// on unlock, cleaning up whatever a crash left. Returns whether something
/// is left.
pub fn wipe_open_scratch(vault_root: &Path) -> bool {
    let dir = open_scratch_dir(vault_root);
    dir.exists() && silentsilo_vault::shred_path(&dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    #[test]
    fn a_pass_on_one_silo_does_not_stand_another_down() {
        let state = AppState::default();
        let first = state.try_start_pass(id(1)).expect("free");
        assert!(state.try_start_pass(id(1)).is_none(), "one per silo");
        let second = state.try_start_pass(id(2)).expect("another silo runs");
        assert!(state.pass_running(id(1)) && state.pass_running(id(2)));
        assert!(!state.try_hold_sync(), "a key operation waits for both");
        drop(first);
        drop(second);
        assert!(!state.sync_busy());
    }

    #[test]
    fn a_key_operation_waiting_stops_new_passes() {
        let state = AppState::default();
        let running = state.try_start_pass(id(1)).expect("free");
        assert!(!state.try_hold_sync(), "a pass runs");
        assert!(
            state.try_start_pass(id(2)).is_none(),
            "no new pass while it waits"
        );
        drop(running);
        assert!(state.try_hold_sync(), "its turn came");
        state.release_sync_hold();
        assert!(state.try_start_pass(id(2)).is_some());
    }

    #[test]
    fn a_held_sync_stops_every_pass_until_released() {
        let state = AppState::default();
        assert!(state.try_hold_sync());
        assert!(!state.try_hold_sync(), "one hold at a time");
        assert!(state.try_start_pass(id(1)).is_none());
        assert!(state.pass_running(id(1)));
        state.release_sync_hold();
        assert!(state.try_start_pass(id(1)).is_some());
    }

    #[test]
    fn the_silo_used_longest_ago_is_the_one_closed() {
        let now = Instant::now();
        let touched = HashMap::from([
            (id(1), now - std::time::Duration::from_secs(60)),
            (id(2), now - std::time::Duration::from_secs(600)),
            (id(3), now - std::time::Duration::from_secs(5)),
        ]);

        assert_eq!(
            stalest([id(1), id(2), id(3)].into_iter(), &touched),
            Some(id(2))
        );
    }

    #[test]
    fn a_silo_that_was_never_used_goes_first() {
        // Opened and left alone: nothing would be lost by closing it, and
        // every other candidate has at least been looked at.
        let touched =
            HashMap::from([(id(1), Instant::now() - std::time::Duration::from_secs(3600))]);

        assert_eq!(stalest([id(1), id(9)].into_iter(), &touched), Some(id(9)));
    }

    #[test]
    fn nothing_open_means_nothing_to_close() {
        assert_eq!(stalest(std::iter::empty(), &HashMap::new()), None);
    }
}
