//! The unlock password's envelope in storage: published to every target,
//! adopted from another device, removed everywhere.
//!
//! The rules follow the recovery envelope's, with three differences the
//! password needs:
//!
//! - a device that has no local copy adopts one from storage, because the
//!   password has to open the silo on every device, offline included;
//! - adoption asks for the tag only a holder of the current vault key can
//!   make (`auth_dek`), from the first envelope: there is no release that
//!   wrote an untagged one;
//! - a newer object that fails that tag does not block republishing: it is
//!   either planted or left behind by a rotation, and the current envelope
//!   goes over it. An object that could not be read, or that a newer release
//!   wrote, is never written over.
//!
//! The object sits at the root of storage, which no release lists, so every
//! client before this one leaves it alone. See `FORMATS.md`.

use silentsilo_crypto::{ContentKek, MasterDek};
use silentsilo_store::ObjectStore;
use silentsilo_vault::password::{
    PasswordEnvelope, clear_password_envelope, clear_unreadable_envelope, load_password_envelope,
    parse_password_envelope, save_password_envelope,
};

use crate::SyncError;
use crate::key_sync::{PASSWORD_MARKER_ID, revoked_at};

/// Where the envelope lives in storage. At the root, beside `recovery.env`,
/// never under `keys/`.
pub const PASSWORD_KEY: &str = "unlock-password.env";

/// What storage holds under [`PASSWORD_KEY`].
#[derive(Debug)]
pub enum StoredPassword {
    Absent,
    Envelope(PasswordEnvelope),
    /// Written by a newer release: never replaced or adopted by this one.
    NeedsNewer,
    /// Not an envelope at all: oversized or not one this build can parse.
    Junk,
}

/// Reads the envelope a target holds. A failed request is an error, which
/// callers treat as "unknown": nothing is written over what was not read.
pub async fn fetch_password_envelope(
    client: &dyn ObjectStore,
) -> Result<StoredPassword, SyncError> {
    // The size first, so an oversized object reads as junk rather than as a
    // failed request, which would keep the password off this target.
    match client.head(PASSWORD_KEY).await? {
        None => return Ok(StoredPassword::Absent),
        Some(size) if crate::too_large(size) => return Ok(StoredPassword::Junk),
        Some(_) => {}
    }
    let Some(bytes) = crate::fetch_small(client, PASSWORD_KEY).await? else {
        return Ok(StoredPassword::Absent);
    };
    Ok(match parse_password_envelope(&bytes) {
        Ok(envelope) => StoredPassword::Envelope(envelope),
        Err(silentsilo_vault::VaultError::Corrupted(m)) if m.contains("needs a newer") => {
            StoredPassword::NeedsNewer
        }
        Err(_) => StoredPassword::Junk,
    })
}

/// Publishes the envelope, as made on this device.
pub async fn push_password_envelope(
    client: &dyn ObjectStore,
    envelope: &PasswordEnvelope,
) -> Result<(), SyncError> {
    let bytes = serde_json::to_vec(envelope).map_err(|e| SyncError::Vault(e.to_string()))?;
    client.put(PASSWORD_KEY, bytes).await?;
    Ok(())
}

/// Publishes `envelope` on a target that does not hold it yet. Called on
/// every pass, so a target added after the password was set still gets it.
///
/// Left alone: an object that could not be read, one a newer release wrote,
/// an exact copy, and a newer envelope a device would adopt (another device
/// changed the password and this one has not heard yet). Written over:
/// nothing there, junk, and every other envelope, so a planted object, or a
/// copy of this one with a field changed, cannot keep the password from
/// reaching a target.
pub async fn ensure_password_envelope(
    client: &dyn ObjectStore,
    envelope: &PasswordEnvelope,
    kek: &ContentKek,
    dek: &MasterDek,
) -> Result<bool, SyncError> {
    match fetch_password_envelope(client).await {
        Err(_) | Ok(StoredPassword::NeedsNewer) => return Ok(false),
        Ok(StoredPassword::Envelope(held)) => {
            if held == *envelope {
                return Ok(false);
            }
            if held.is_newer_than(envelope) && adoptable(&held, kek, dek, now()) {
                return Ok(false);
            }
        }
        Ok(StoredPassword::Absent | StoredPassword::Junk) => {}
    }
    push_password_envelope(client, envelope).await?;
    Ok(true)
}

/// Removes the published envelope.
pub async fn delete_password_envelope(client: &dyn ObjectStore) -> Result<(), SyncError> {
    client.delete(PASSWORD_KEY).await?;
    Ok(())
}

/// What a pass decided about the unlock password.
#[derive(Debug, Default)]
pub struct PasswordSettlement {
    /// The envelope to publish. `None` when the silo has no password, and
    /// when this device keeps one a removal covers (`kept_after_removal`).
    pub envelope: Option<PasswordEnvelope>,
    /// This device now holds an envelope another device made: a password set
    /// or changed elsewhere.
    pub adopted: bool,
    /// The password this device held was dropped because a marker says it
    /// was removed. A former holder of the KEK can write one, so the caller
    /// tells the user.
    pub removed_elsewhere: bool,
    /// A marker says the password was removed, but no key opens the silo
    /// here, so dropping it would leave only the recovery code. Kept for
    /// this device and not published again; the caller tells the user.
    pub kept_after_removal: bool,
    /// The password this device held was made under a vault key a rotation
    /// retired (a release that does not know about passwords rotated). It
    /// no longer opens the silo and was dropped; the user sets it again.
    pub dropped_after_rotation: bool,
    /// An envelope no device on the current vault key made, or one made
    /// too light or dated too far ahead, was found: in the silo folder or
    /// in storage. Not used; reported.
    pub refused: bool,
}

/// How far ahead of this clock an envelope may be dated and still be
/// adopted or left in a target: a device whose clock runs fast must not
/// date one past every later change.
pub const ENVELOPE_AHEAD_SECS: i64 = 13 * 3600;

/// How far ahead a removal marker may be dated and still count, and the
/// most this device dates one ahead. Under the envelope limit, so a
/// password set right after a removal is never born covered by it.
pub const MARKER_AHEAD_SECS: i64 = 12 * 3600;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The latest date a new envelope may carry.
pub fn date_ceiling() -> i64 {
    now().saturating_add(ENVELOPE_AHEAD_SECS)
}

/// An envelope worth adopting: made on the current vault key, at the
/// parameters this build seals with or heavier, not dated past the limit.
fn adoptable(envelope: &PasswordEnvelope, kek: &ContentKek, dek: &MasterDek, now: i64) -> bool {
    envelope.is_authentic_now(kek, dek)
        && envelope.meets_kdf_floor()
        && envelope.created_at <= now.saturating_add(ENVELOPE_AHEAD_SECS)
}

/// When a target says the password was removed, if its marker opens with
/// `kek` and is not dated past [`MARKER_AHEAD_SECS`].
pub async fn password_removed_at(
    client: &dyn ObjectStore,
    kek: &ContentKek,
) -> Result<Option<i64>, SyncError> {
    let limit = now().saturating_add(MARKER_AHEAD_SECS);
    Ok(revoked_at(client, kek, PASSWORD_MARKER_ID)
        .await?
        .filter(|at| *at <= limit))
}

/// Brings this device's password envelope in line with storage before a
/// push, and returns the one to publish. `targets` pairs each store with
/// whether it allows deletes. `key_opens_here` says whether a key this
/// device has proven opens the silo here: without one a removal marker does
/// not take the password away, since a former holder of the KEK can write
/// one and the recovery code would be all that is left.
///
/// Only an envelope carrying a valid `auth_dek` is ever kept or adopted.
/// The local copy is held to the same rule: whoever can write the silo
/// folder (a sync client, another account) cannot put a password there.
pub async fn settle_password_envelope(
    targets: &[(&dyn ObjectStore, bool)],
    kek: &ContentKek,
    dek: &MasterDek,
    vault_root: &std::path::Path,
    key_opens_here: bool,
) -> PasswordSettlement {
    let now = now();
    let mut settlement = PasswordSettlement::default();
    // A file there that is not an envelope is no password.
    clear_unreadable_envelope(vault_root);
    let mut local = load_password_envelope(vault_root).ok();

    // The local copy first: current, left behind by a rotation, or not ours.
    if let Some(held) = local.as_ref()
        && !held.is_authentic_now(kek, dek)
    {
        if held.is_authentic(kek) {
            settlement.dropped_after_rotation = true;
        } else {
            settlement.refused = true;
        }
        clear_password_envelope(vault_root);
        local = None;
    }

    let mut removed_at: Option<i64> = None;
    for (store, _) in targets {
        if let Ok(Some(at)) = password_removed_at(*store, kek).await {
            removed_at = Some(removed_at.map_or(at, |r| r.max(at)));
        }
    }
    let mut publish = true;
    if let Some(off) = removed_at
        && local.as_ref().is_some_and(|l| l.created_at <= off)
    {
        if key_opens_here {
            clear_password_envelope(vault_root);
            local = None;
            settlement.removed_elsewhere = true;
        } else {
            settlement.kept_after_removal = true;
            publish = false;
        }
    }

    // What each target holds: adopt the newest one worth it, clean what a
    // removal or a rotation left behind where deleting is allowed.
    let mut newest: Option<PasswordEnvelope> = None;
    for (store, allows_delete) in targets {
        let Ok(StoredPassword::Envelope(found)) = fetch_password_envelope(*store).await else {
            continue;
        };
        let dead = removed_at.is_some_and(|off| found.created_at <= off);
        let current = found.is_authentic_now(kek, dek);
        let left_by_rotation = !current && found.is_authentic(kek);
        if (dead || left_by_rotation) && *allows_delete {
            let _ = delete_password_envelope(*store).await;
        }
        if dead || left_by_rotation {
            continue;
        }
        let newer_than_local = local.as_ref().is_none_or(|l| found.is_newer_than(l));
        if !adoptable(&found, kek, dek, now) {
            if newer_than_local {
                settlement.refused = true;
            }
            continue;
        }
        let newer_than_seen = newest.as_ref().is_none_or(|n| found.is_newer_than(n));
        if newer_than_local && newer_than_seen {
            newest = Some(found);
        }
    }
    if let Some(adopt) = newest
        && save_password_envelope(vault_root, &adopt).is_ok()
    {
        local = Some(adopt);
        settlement.adopted = true;
        settlement.dropped_after_rotation = false;
        settlement.kept_after_removal = false;
        publish = true;
    }

    settlement.envelope = local.filter(|_| publish);
    settlement
}

/// Removes the password everywhere: a marker on every target, so a device
/// that has not heard drops its copy, then the envelope wherever the marker
/// went and deleting is allowed, then the local copy. Returns the date used.
pub async fn remove_password(
    targets: &[(&dyn ObjectStore, bool)],
    kek: &ContentKek,
    vault_root: &std::path::Path,
) -> Result<i64, SyncError> {
    // At or after the envelope this device holds, so the marker covers it
    // even when this clock is behind the one that made it; never past the
    // limit every device reads markers with.
    let now = now();
    let mut at = now;
    if let Ok(local) = load_password_envelope(vault_root) {
        at = at.max(local.created_at);
    }
    let at = at.min(now.saturating_add(MARKER_AHEAD_SECS));
    let mut marked = 0;
    for (store, allows_delete) in targets {
        if crate::mark_password_removed(*store, kek, at).await.is_err() {
            continue;
        }
        marked += 1;
        if *allows_delete {
            let _ = delete_password_envelope(*store).await;
        }
    }
    if marked == 0 && !targets.is_empty() {
        return Err(SyncError::Vault(
            "no copy took the removal; nothing was changed".into(),
        ));
    }
    clear_password_envelope(vault_root);
    Ok(at)
}

/// The date a new envelope has to be after: the newest removal marker or
/// adoptable envelope any target holds, so it is never born dead or older
/// than one it replaces. Never past [`date_ceiling`]. Pass it to
/// [`PasswordEnvelope::date_after`].
pub async fn password_date_floor(
    targets: &[&dyn ObjectStore],
    kek: &ContentKek,
    dek: &MasterDek,
) -> i64 {
    let now = now();
    let mut floor = 0i64;
    for store in targets {
        if let Ok(Some(at)) = password_removed_at(*store, kek).await {
            floor = floor.max(at.saturating_add(1));
        }
        if let Ok(StoredPassword::Envelope(found)) = fetch_password_envelope(*store).await
            && adoptable(&found, kek, dek, now)
        {
            floor = floor.max(found.created_at.saturating_add(1));
        }
    }
    floor.min(now.saturating_add(ENVELOPE_AHEAD_SECS))
}

/// Whether an envelope from storage is one a joining device may keep:
/// adoptable now and not covered by a removal on that store.
pub async fn joinable(
    store: &dyn ObjectStore,
    envelope: &PasswordEnvelope,
    kek: &ContentKek,
    dek: &MasterDek,
) -> Result<bool, SyncError> {
    if !envelope.is_authentic_now(kek, dek) || !envelope.meets_kdf_floor() {
        return Ok(false);
    }
    Ok(match password_removed_at(store, kek).await? {
        Some(off) => envelope.created_at > off,
        None => true,
    })
}
