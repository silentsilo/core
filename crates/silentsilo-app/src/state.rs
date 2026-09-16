use std::collections::HashMap;
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
/// Each open silo means a decrypted working database on disk and a set of
/// keys in memory, so the number of them is the size of what a compromised
/// process gets while the user is unlocked. Switching between silos all day
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
    /// Held for the duration of a sync pass. Two passes at once, the timer
    /// firing while the user is holding the button, would each read the
    /// same pending queue and upload it twice.
    pub sync_in_flight: AtomicBool,
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
                touched.remove(stale);
            })
        };

        sessions.insert(id, session);
        touched.insert(id, Instant::now());
        Ok(evicted)
    }

    /// Closes one silo, leaving any others open.
    pub fn close_session(&self, host: &dyn Host, id: Uuid) -> Result<(), String> {
        let closed = self.sessions.lock().map_err(|e| e.to_string())?.remove(&id);
        if let Ok(mut touched) = self.last_touched.lock() {
            touched.remove(&id);
        }
        if let Some(session) = closed {
            close_one(host, session);
        }
        Ok(())
    }

    /// Removes the decrypted scratch of every silo that is not open, including
    /// what a crash or kill left behind. The client calls it at start and after
    /// each lock; not from `close_session`, so that tests sharing a work base
    /// do not sweep each other. Returns how many directories survived.
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

/// Snapshots a session and clears the plaintext it was working through.
///
/// The session is dropped before the working copy is removed: Windows will
/// not delete a file that still has an open handle, so the order here is the
/// difference between locking a silo and leaving its decrypted database on
/// disk.
fn close_one(host: &dyn Host, session: VaultSession) {
    if let Err(e) = session.backup_locally() {
        host.warn("lock", &format!("local snapshot failed: {e}"));
    }
    let paths = session.paths.clone();
    drop(session);
    wipe_open_scratch(&paths.root);
    silentsilo_vault::wipe_plaintext_working_copy(&paths);
}

/// Where a file goes when the user opens it rather than exporting it.
///
/// Under the vault's own directory, not the shared OS temp dir, which many
/// other processes read routinely: indexers, backup agents, antivirus.
pub fn open_scratch_dir(vault_root: &Path) -> PathBuf {
    silentsilo_vault::work_dir_for(vault_root).join("open")
}

/// Removes every decrypted copy left behind by opening files.
///
/// Called on lock and on exit, so plaintext never outlives the session that
/// asked for it. Best-effort: an application still holding a file open will
/// block the delete on Windows, and failing the lock over that would be
/// worse than one file surviving until the next attempt, which is why this
/// also runs on unlock, cleaning up whatever a crash left.
pub fn wipe_open_scratch(vault_root: &Path) {
    let dir = open_scratch_dir(vault_root);
    if !dir.exists() {
        return;
    }
    // Read-only is set on every file written here, and Windows refuses to
    // delete a read-only file, so the bit has to come off first.
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(meta) = std::fs::metadata(&path) {
                let mut perms = meta.permissions();
                #[allow(clippy::permissions_set_readonly_false)]
                perms.set_readonly(false);
                let _ = std::fs::set_permissions(&path, perms);
            }
            let _ = std::fs::remove_file(&path);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
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
