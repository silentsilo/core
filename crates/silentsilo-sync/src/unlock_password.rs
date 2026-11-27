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
    PasswordEnvelope, clear_password_envelope, load_password_envelope, parse_password_envelope,
    save_password_envelope,
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
/// and a newer envelope a device on the current vault key made (another
/// device changed the password and this one has not heard yet). Written
/// over: nothing there, junk, and an envelope that is not current, whatever
/// its date, so a planted object with a date in the future cannot keep the
/// password from reaching a target.
pub async fn ensure_password_envelope(
    client: &dyn ObjectStore,
    envelope: &PasswordEnvelope,
    kek: &ContentKek,
    dek: &MasterDek,
) -> Result<bool, SyncError> {
    match fetch_password_envelope(client).await {
        Err(_) | Ok(StoredPassword::NeedsNewer) => return Ok(false),
        Ok(StoredPassword::Envelope(held)) => {
            if held.id == envelope.id && held.created_at == envelope.created_at {
                return Ok(false);
            }
            if held.created_at > envelope.created_at && held.is_authentic_now(kek, dek) {
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
    /// The envelope this device holds afterwards, the one to publish. `None`
    /// when the silo has no password.
    pub envelope: Option<PasswordEnvelope>,
    /// This device now holds an envelope another device made: a password set
    /// or changed elsewhere.
    pub adopted: bool,
    /// The password this device held was dropped because a marker says it
    /// was removed. A former holder of the KEK can write one, so the caller
    /// tells the user.
    pub removed_elsewhere: bool,
    /// The password this device held was made under a vault key a rotation
    /// retired (a release that does not know about passwords rotated). It
    /// no longer opens the silo and was dropped; the user sets it again.
    pub dropped_after_rotation: bool,
    /// An envelope that no device on the current vault key made was found:
    /// in the silo folder, or newer in storage. Not used; reported.
    pub refused: bool,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Brings this device's password envelope in line with storage before a
/// push, and returns the one to publish. `targets` pairs each store with
/// whether it allows deletes.
///
/// Only an envelope carrying a valid `auth_dek` is ever kept or adopted.
/// The local copy is held to the same rule: whoever can write the silo
/// folder (a sync client, another account) cannot put a password there.
pub async fn settle_password_envelope(
    targets: &[(&dyn ObjectStore, bool)],
    kek: &ContentKek,
    dek: &MasterDek,
    vault_root: &std::path::Path,
) -> PasswordSettlement {
    let mut settlement = PasswordSettlement::default();
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
        if let Ok(Some(at)) = revoked_at(*store, kek, PASSWORD_MARKER_ID).await {
            removed_at = Some(removed_at.map_or(at, |r| r.max(at)));
        }
    }
    if let Some(off) = removed_at
        && local.as_ref().is_some_and(|l| l.created_at <= off)
    {
        clear_password_envelope(vault_root);
        local = None;
        settlement.removed_elsewhere = true;
    }

    // What each target holds: adopt the newest current one, clean what a
    // removal or a rotation left behind where deleting is allowed.
    let mut newest: Option<PasswordEnvelope> = None;
    for (store, allows_delete) in targets {
        let Ok(StoredPassword::Envelope(found)) = fetch_password_envelope(*store).await else {
            continue;
        };
        let dead = removed_at.is_some_and(|off| found.created_at <= off);
        let current = found.is_authentic_now(kek, dek);
        if (dead || (!current && found.is_authentic(kek))) && *allows_delete {
            let _ = delete_password_envelope(*store).await;
        }
        if dead {
            continue;
        }
        if !current {
            if found.is_authentic(kek) {
                // A rotation by a release that does not know about passwords.
                if local.is_none() {
                    settlement.dropped_after_rotation = true;
                }
            } else if local
                .as_ref()
                .is_none_or(|l| found.created_at > l.created_at)
            {
                settlement.refused = true;
            }
            continue;
        }
        let newer_than_local = local
            .as_ref()
            .is_none_or(|l| found.created_at > l.created_at);
        let newer_than_seen = newest
            .as_ref()
            .is_none_or(|n| found.created_at > n.created_at);
        if newer_than_local && newer_than_seen {
            newest = Some(found);
        }
    }
    if let Some(adopt) = newest
        && save_password_envelope(vault_root, &adopt).is_ok()
    {
        local = Some(adopt);
        settlement.adopted = true;
    }

    settlement.envelope = local;
    settlement
}

/// Removes the password everywhere: a marker dated now on every target, so
/// a device that has not heard drops its copy, then the envelope wherever
/// deleting is allowed, then the local copy. Returns the date it used.
pub async fn remove_password(
    targets: &[(&dyn ObjectStore, bool)],
    kek: &ContentKek,
    vault_root: &std::path::Path,
) -> Result<i64, SyncError> {
    // At or after the newest envelope this device knows, so the marker
    // covers it even when this clock is behind the one that made it.
    let mut at = now();
    if let Ok(local) = load_password_envelope(vault_root) {
        at = at.max(local.created_at);
    }
    let mut marked = 0;
    for (store, allows_delete) in targets {
        if crate::mark_password_removed(*store, kek, at).await.is_ok() {
            marked += 1;
        }
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
/// envelope any target holds, so it is never born dead or older than one
/// it replaces. Pass it to [`PasswordEnvelope::date_after`].
pub async fn password_date_floor(targets: &[&dyn ObjectStore], kek: &ContentKek) -> i64 {
    let mut floor = 0;
    for store in targets {
        if let Ok(Some(at)) = revoked_at(*store, kek, PASSWORD_MARKER_ID).await {
            floor = floor.max(at + 1);
        }
        if let Ok(StoredPassword::Envelope(found)) = fetch_password_envelope(*store).await
            && found.is_authentic(kek)
        {
            floor = floor.max(found.created_at + 1);
        }
    }
    floor
}
