//! An organisation's activity log: started, given another key that reads
//! it, its retention changed, and its old segments removed.
//!
//! Each of these belongs to whoever holds one of the organisation's keys.
//! The client asks for that key's touch first, checks it against the silo
//! (`OrgProof`), and hands over what the touch gave. Core cannot tell a
//! touch from a claim: anyone holding the content key can write a policy.
//! What it can do is keep the log's private key out of reach of everyone
//! else, which is what the wrapping does.

use silentsilo_audit::{
    AUDIT_PREFIX, AuditKey, AuditPolicy, Event, KeyPair, Scope, Segment, codes, parse_segment_key,
};
use silentsilo_vault::SiloEntry;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit_read::CACHE_DIR;
use crate::{AppState, Host};

/// One organisation key, as its touch left it: the credential id (hex) and
/// the wrap key the touch derived.
pub struct OrgKeyTouch {
    pub credential_id: String,
    pub wrap_key: Zeroizing<[u8; 32]>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl AppState {
    /// Starts the organisation's log on the open silo, read with the key
    /// `touch` came from. A personal log kept until now is closed and left
    /// as it is; what follows is sealed to the organisation's key.
    pub fn start_org_audit_log(
        &self,
        id: Uuid,
        touch: &OrgKeyTouch,
        retention_days: Option<u32>,
    ) -> Result<(), String> {
        let mut spool = self.audit_spool(id)?;
        if spool.pinned().is_some_and(|p| p.scope == Scope::Org) {
            return Err("This silo already keeps an activity log for its organisation.".into());
        }
        let now_ms = now_ms();
        let now = now_ms / 1000;
        let keys = KeyPair::generate();
        let mut key = AuditKey::new(&keys, Scope::Org, now);
        key.wrap_for(&touch.credential_id, &keys.private, &touch.wrap_key)
            .map_err(|e| e.to_string())?;
        let previous = spool.policy().map_err(|e| e.to_string())?;
        let changed_at = previous.map_or(now, |p| now.max(p.changed_at + 1));
        let policy = AuditPolicy::new(true, &keys.id(), retention_days, Scope::Org, changed_at);

        if spool.pinned().is_some_and(|p| p.enabled) {
            spool
                .record(Event::new(codes::LOG_STOPPED, now_ms).with("for", "organisation"))
                .map_err(|e| e.to_string())?;
        }
        spool
            .repin(&policy, &key, now_ms)
            .map_err(|e| e.to_string())?;
        spool
            .record(Event::new(codes::LOG_STARTED, now_ms).with("for", "organisation"))
            .map_err(|e| e.to_string())?;
        self.remember_org_log(id);
        Ok(())
    }

    /// Lets the organisation key `new` read the log too, unwrapping it with
    /// `by`, which already does. Reaches the copies at the next pass.
    pub fn add_org_audit_reader(
        &self,
        id: Uuid,
        by: &OrgKeyTouch,
        new: &OrgKeyTouch,
    ) -> Result<(), String> {
        let spool = self.audit_spool(id)?;
        let mut key = org_key(&spool)?;
        let private = key
            .unwrap_with(&by.credential_id, &by.wrap_key)
            .map_err(|_| "That organisation key does not read this silo's activity log.")?;
        key.wrap_for(&new.credential_id, &private, &new.wrap_key)
            .map_err(|e| e.to_string())?;
        spool.keep_key(&key).map_err(|e| e.to_string())?;
        republish(spool, None)
    }

    /// Changes how long the organisation's log keeps its segments. `None`
    /// keeps them.
    pub fn set_org_audit_retention(
        &self,
        id: Uuid,
        retention_days: Option<u32>,
    ) -> Result<(), String> {
        let mut spool = self.audit_spool(id)?;
        org_key(&spool)?;
        let event = Event::new(codes::RETENTION_CHANGED, now_ms());
        let event = match retention_days {
            Some(days) => event.with("days", days),
            None => event.with("days", "kept"),
        };
        spool.record(event).map_err(|e| e.to_string())?;
        republish(spool, Some(retention_days))
    }

    fn remember_org_log(&self, id: Uuid) {
        if let Ok(mut org) = self.audit_org.lock() {
            org.insert(id);
        }
    }
}

/// The pinned key, when it is an organisation's.
fn org_key(spool: &silentsilo_audit::Spool) -> Result<AuditKey, String> {
    match spool.key().map_err(|e| e.to_string())? {
        Some(key) if key.scope == Scope::Org => Ok(key),
        Some(_) => Err("This silo's activity log is not kept for an organisation.".into()),
        None => Err("This silo keeps no activity log.".into()),
    }
}

/// The policy again, newer, with `retention` when it changes, so the next
/// pass writes it and the key to every copy.
fn republish(
    mut spool: silentsilo_audit::Spool,
    retention: Option<Option<u32>>,
) -> Result<(), String> {
    let key = spool
        .key()
        .map_err(|e| e.to_string())?
        .ok_or("This silo keeps no activity log.")?;
    let mut policy = spool
        .policy()
        .map_err(|e| e.to_string())?
        .ok_or("This silo keeps no activity log.")?;
    let now = now_ms() / 1000;
    policy.changed_at = now.max(policy.changed_at + 1);
    if let Some(retention) = retention {
        policy.retention_days = retention;
    }
    spool
        .apply_policy(&policy, &key, 0)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// The shortest retention the app offers. Expiry never goes below it.
pub const MIN_RETENTION_DAYS: u32 = 90;

/// Removes the organisation log's segments closed before its retention
/// allows, from every copy that takes deletes and from this computer's
/// cache. A copy kept append-only keeps them. Returns how many went.
pub async fn expire_audit_segments(
    state: &AppState,
    host: &dyn Host,
    silo: &SiloEntry,
) -> Result<usize, String> {
    // The sessions lock first and on its own: opening a silo holds it while
    // it closes another, which opens that one's spool.
    let root = state
        .sessions
        .lock()
        .map_err(|e| e.to_string())?
        .get(&silo.id)
        .ok_or("That silo is not open.")?
        .paths
        .root
        .clone();
    let retention = {
        let spool = state.audit_spool(silo.id)?;
        org_key(&spool)?;
        spool
            .policy()
            .map_err(|e| e.to_string())?
            .ok_or("This silo keeps no activity log.")?
            .retention_days
    };
    let Some(days) = retention else {
        return Ok(0);
    };
    // Anyone with the content key can write a policy. A retention shorter
    // than any the app offers is not one an organisation chose.
    let days = days.max(MIN_RETENTION_DAYS);
    let now = now_ms();
    let cutoff = now.saturating_sub(i64::from(days) * 86_400_000);
    let cache = root.join(CACHE_DIR);

    let mut removed = std::collections::HashSet::new();
    for target in host.targets(silo.id) {
        if !target.role.allows_delete() {
            continue;
        }
        let Ok(store) = target.config.open() else {
            continue;
        };
        let Ok(listed) = store.list(AUDIT_PREFIX).await else {
            continue;
        };
        for object in listed {
            let Some((device, seq)) = parse_segment_key(&object.key) else {
                continue;
            };
            let cached = cache.join(object.key.trim_start_matches(AUDIT_PREFIX));
            let bytes = match std::fs::read(&cached) {
                Ok(bytes) => bytes,
                Err(_) => match store.get(&object.key).await {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                },
            };
            // One that names another place is not this segment, and its
            // age says nothing about the one that belongs here.
            let Ok(segment) = Segment::from_bytes(&bytes) else {
                continue;
            };
            if segment.device != device || segment.seq != seq || segment.closed_at >= cutoff {
                continue;
            }
            if store.delete(&object.key).await.is_ok() {
                let _ = std::fs::remove_file(&cached);
                removed.insert((device, seq));
            }
        }
    }
    if !removed.is_empty() {
        state
            .audit_record(
                silo.id,
                Event::new(codes::SEGMENTS_EXPIRED, now).with("count", removed.len()),
            )
            .map_err(|e| e.to_string())?;
    }
    Ok(removed.len())
}
