//! The flows that open or create a silo on this device, split at the points
//! where a client does its own part (the silo list, the keyring, the screen)
//! so each client keeps the order the desktop has always had.
//!
//! Joining with the recovery code, in order:
//! 1. [`recovery_join_begin`]: nothing local is touched yet;
//! 2. the client registers the silo folder and saves this device's
//!    credentials and storage settings;
//! 3. [`recovery_join_provision`]: the local silo is created;
//! 4. the client records the silo as the open one;
//! 5. `silentsilo_sync::fetch_join_plan_reporting`, then [`join_finish`] on
//!    a blocking thread, then the session enters the app state.
//!
//! Joining with a security key replaces step 1 with [`key_join_begin`], the
//! key's ceremony against the envelopes it lists, and [`key_join_open`].

use std::path::{Path, PathBuf};

use silentsilo_core::VaultMeta;
use silentsilo_crypto::MasterDek;
use silentsilo_store::ObjectStore;
use silentsilo_sync as sync;
use silentsilo_vault::{
    RecoveryEnvelope, StoredFidoCredential, StoredFidoKeys, VaultSession, load_fido_keys,
    save_fido_keys, save_recovery_envelope, unwrap_with_code, wrap_dek_bytes,
};
use silentsilo_vfs::Vfs;
use uuid::Uuid;

/// What the recovery code, or a security key, opened before anything local
/// exists.
pub struct RecoveryJoin {
    pub vault_id: Uuid,
    dek: MasterDek,
    /// Absent for a key join on a silo that never set up a code.
    envelope: Option<RecoveryEnvelope>,
}

impl RecoveryJoin {
    /// The key the join plan is fetched with.
    pub fn dek(&self) -> &MasterDek {
        &self.dek
    }
}

/// Reads the silo a store holds and opens its recovery envelope with `code`.
/// Everything here can fail without leaving anything behind.
pub async fn recovery_join_begin(
    store: &dyn ObjectStore,
    code: &str,
) -> Result<RecoveryJoin, String> {
    let manifest = sync::read_manifest(store)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "That bucket doesn't hold a silo.".to_string())?;
    let envelope = sync::fetch_recovery_envelope(store)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "No recovery code was set up for this silo.".to_string())?;

    let dek = unwrap_with_code(&envelope, code)
        .map_err(|_| "That recovery code doesn't match this silo.".to_string())?;
    Ok(RecoveryJoin {
        vault_id: manifest.vault_id,
        dek,
        envelope: Some(envelope),
    })
}

/// A silo in storage and the key envelopes a device could join it with.
pub struct KeyJoinOffer {
    pub vault_id: Uuid,
    pub keys: Vec<StoredFidoCredential>,
}

/// Reads the silo a store holds and its published key envelopes. Nothing
/// local is created.
pub async fn key_join_begin(store: &dyn ObjectStore) -> Result<KeyJoinOffer, String> {
    let manifest = sync::read_manifest(store)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "That bucket doesn't hold a silo.".to_string())?;
    let keys = sync::fetch_key_envelopes(store)
        .await
        .map_err(|e| e.to_string())?;
    if keys.is_empty() {
        return Err(
            "No keys have been published to this storage yet. Sync once from a device that has the silo."
                .into(),
        );
    }
    Ok(KeyJoinOffer {
        vault_id: manifest.vault_id,
        keys,
    })
}

/// The join a key opened: `wrap_key` is what the key produced for
/// `credential_id`. The recovery envelope comes along when there is one.
pub async fn key_join_open(
    store: &dyn ObjectStore,
    offer: &KeyJoinOffer,
    credential_id: &str,
    wrap_key: &[u8; 32],
) -> Result<RecoveryJoin, String> {
    let wrapped = offer
        .keys
        .iter()
        .find(|k| k.credential_id == credential_id && !k.wrapped_dek.is_empty())
        .map(|k| k.wrapped_dek.as_str())
        .ok_or_else(|| "That security key isn't one of this silo's keys.".to_string())?;
    let dek = silentsilo_vault::unwrap_dek_hex(wrapped, wrap_key)
        .map_err(|_| "That security key could not open the silo.".to_string())?;
    // A removed key's envelope can come back: a device that had not heard
    // of the removal publishes it again. The revocation marker decides.
    if let Some(sealed) = sync::fetch_content_kek(store)
        .await
        .map_err(|e| e.to_string())?
    {
        let kek = silentsilo_vault::unwrap_kek_bytes(&sealed, &dek).map_err(|e| e.to_string())?;
        if sync::is_key_revoked(store, &kek, credential_id)
            .await
            .map_err(|e| e.to_string())?
        {
            return Err("That security key was removed from this silo.".into());
        }
    }
    let envelope = sync::fetch_recovery_envelope(store).await.ok().flatten();
    Ok(RecoveryJoin {
        vault_id: offer.vault_id,
        dek,
        envelope,
    })
}

/// Creates the silo at `root` from the store: the content key, the published
/// key envelopes, the recovery envelope and a first snapshot.
pub async fn recovery_join_provision(
    store: &dyn ObjectStore,
    join: &RecoveryJoin,
    root: PathBuf,
    device_secret: &str,
) -> Result<VaultSession, String> {
    let kek_envelope = sync::fetch_content_kek(store)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            "This storage has no content key yet, so there is nothing here to recover.".to_string()
        })?;
    let kek =
        silentsilo_vault::unwrap_kek_bytes(&kek_envelope, &join.dek).map_err(|e| e.to_string())?;
    let session = VaultSession::provision_with_dek(
        root.clone(),
        join.vault_id,
        device_secret,
        join.dek.clone(),
        kek.clone(),
    )
    .map_err(|e| e.to_string())?;
    Vfs::new(&session)
        .ensure_initialized()
        .map_err(|e| e.to_string())?;

    // The key envelopes come down too, so the keys still in the user's
    // possession keep working here. The local DEK envelope is re-wrapped
    // under one of them, closing the weaker door `provision_with_dek` opened
    // (the folder plus this device's secret). Only when an envelope exists:
    // a silo with no enrolled key still needs that door to open at all.
    // Envelopes are not authenticated: only well-formed ones, and none a
    // sealed revocation marker names, so a removed key put back by storage
    // does not become a key of this device.
    let mut keys = sync::fetch_key_envelopes(store).await.unwrap_or_default();
    let mut usable = Vec::with_capacity(keys.len());
    for key in keys.drain(..) {
        if key.revoked || !sync::plausible_credential_id(&key.credential_id) {
            continue;
        }
        if sync::is_key_revoked(store, &kek, &key.credential_id)
            .await
            .unwrap_or(true)
        {
            continue;
        }
        usable.push(key);
    }
    let keys = usable;
    if !keys.is_empty() {
        if let Some(envelope) = keys
            .iter()
            .find(|key| !key.wrapped_dek.is_empty())
            .and_then(|key| hex::decode(&key.wrapped_dek).ok())
        {
            silentsilo_vault::save_wrapped_dek_bytes(&root, &envelope)
                .map_err(|e| e.to_string())?;
        }
        // Created here from the published envelopes, so nothing is removed.
        let _ = save_fido_keys(
            &root,
            &StoredFidoKeys { keys },
            silentsilo_vault::Authority::Machine,
        );
    }
    if let Some(envelope) = &join.envelope {
        save_recovery_envelope(&root, envelope).map_err(|e| e.to_string())?;
    }

    session.backup_locally().map_err(|e| e.to_string())?;
    Ok(session)
}

/// Replays a fetched join plan into the new session and snapshots it. Heavy
/// database work: run it on a blocking thread, before the session is shared.
pub fn join_finish(
    mut session: VaultSession,
    plan: sync::JoinPlan,
) -> Result<(VaultSession, VaultMeta), String> {
    plan.apply(&mut session.conn).map_err(|e| e.to_string())?;
    session.backup_locally().map_err(|e| e.to_string())?;
    let meta = Vfs::new(&session).meta().map_err(|e| e.to_string())?;
    Ok((session, meta))
}

/// The recovery envelope for a silo on this device: the local copy, or the
/// store's when this device joined after the code was created.
pub async fn recovery_envelope_for(
    root: &Path,
    store: Option<&dyn ObjectStore>,
) -> Result<RecoveryEnvelope, String> {
    if silentsilo_vault::has_recovery_code(root) {
        return silentsilo_vault::load_recovery_envelope(root).map_err(|e| e.to_string());
    }
    let store = store.ok_or_else(|| "No recovery code is set up for this silo.".to_string())?;
    sync::fetch_recovery_envelope(store)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "No recovery code is set up for this silo.".to_string())
}

/// Opens a silo on this device with the recovery code. Disk work: blocking
/// thread.
pub fn open_with_recovery(
    root: PathBuf,
    envelope: &RecoveryEnvelope,
    code: &str,
    expected_vault_id: Uuid,
) -> Result<(VaultSession, VaultMeta), String> {
    let dek = unwrap_with_code(envelope, code)
        .map_err(|_| "That recovery code doesn't match this silo.".to_string())?;
    let session = VaultSession::open_with_dek(root, dek).map_err(|e| e.to_string())?;
    if session.vault_id != expected_vault_id {
        return Err("vault id mismatch".into());
    }
    let vfs = Vfs::new(&session);
    vfs.ensure_initialized().map_err(|e| e.to_string())?;
    let meta = vfs.meta().map_err(|e| e.to_string())?;
    Ok((session, meta))
}

/// A key made on this device, ready to record: what its platform returned.
pub struct DeviceKey {
    pub kind: String,
    pub derivation: String,
    pub credential_id: String,
    pub public_key: String,
    pub wrap_key: [u8; 32],
    pub label: String,
}

/// Records a device key on an open silo. The first key on a silo also
/// re-wraps the local DEK envelope under it, as the desktop's first
/// enrolment does, so the device secret alone no longer opens the silo.
/// The next sync pass publishes the envelope.
pub fn enrol_device_key(
    session: &VaultSession,
    key: &DeviceKey,
) -> Result<StoredFidoCredential, String> {
    let root = &session.paths.root;
    let envelope = wrap_dek_bytes(&session.dek, &key.wrap_key).map_err(|e| e.to_string())?;
    let mut keys = if silentsilo_vault::is_fido_enrolled(root) {
        load_fido_keys(root).map_err(|e| e.to_string())?
    } else {
        StoredFidoKeys { keys: Vec::new() }
    };
    if keys.active().any(|k| k.credential_id == key.credential_id) {
        return Err("This credential is already enrolled".into());
    }
    // A key put back after an offline removal: its tombstone would delete
    // the new envelope in the pass that publishes it.
    keys.keys.retain(|k| k.credential_id != key.credential_id);
    let first = keys.active().next().is_none();

    let stored = StoredFidoCredential {
        kind: key.kind.clone(),
        derivation: key.derivation.clone(),
        policy: String::new(),
        credential_id: key.credential_id.clone(),
        public_key: key.public_key.clone(),
        key_slot: keys.next_slot(),
        rp_id: "silentsilo.com".into(),
        label: key.label.clone(),
        wrapped_dek: hex::encode(&envelope),
        // A security key added from a phone travels; the phone's own does not.
        platform: key.kind != silentsilo_vault::KIND_FIDO2,
        revoked: false,
    };
    keys.keys.push(stored.clone());
    if first {
        silentsilo_vault::save_wrapped_dek_bytes(root, &envelope).map_err(|e| e.to_string())?;
    }
    save_fido_keys(root, &keys, silentsilo_vault::Authority::Machine).map_err(|e| e.to_string())?;
    if let Err(e) = session.backup_locally() {
        return Err(format!(
            "The key was added, but the local snapshot failed: {e}"
        ));
    }
    Ok(stored)
}

/// Opens a silo with the wrap key a device key produced for `credential_id`.
/// Disk work: blocking thread.
pub fn open_with_device_key(
    root: PathBuf,
    credential_id: &str,
    wrap_key: &[u8; 32],
    expected_vault_id: Uuid,
) -> Result<(VaultSession, VaultMeta), String> {
    let keys = load_fido_keys(&root).map_err(|e| e.to_string())?;
    let wrapped = keys
        .active()
        .find(|k| k.credential_id == credential_id)
        .map(|k| k.wrapped_dek.clone())
        .filter(|w| !w.is_empty())
        .ok_or_else(|| "No matching enrolled key".to_string())?;
    let session = VaultSession::open_with_fido_wrapped(root, wrap_key, &wrapped)
        .map_err(|e| e.to_string())?;
    if session.vault_id != expected_vault_id {
        return Err("these credentials belong to a different silo".into());
    }
    let vfs = Vfs::new(&session);
    vfs.ensure_initialized().map_err(|e| e.to_string())?;
    let meta = vfs.meta().map_err(|e| e.to_string())?;
    // A crash between opening a file and locking would have left plaintext
    // behind; this is the first moment it is safe to clear it.
    crate::wipe_open_scratch(&session.paths.root);
    Ok((session, meta))
}

/// The credential ids of the keys of `kind` this device can offer its
/// platform, for the unlock prompt.
pub fn device_key_ids(root: &Path, kind: &str) -> Vec<String> {
    load_fido_keys(root)
        .map(|keys| {
            keys.active()
                .filter(|k| k.kind == kind)
                .map(|k| k.credential_id.clone())
                .collect()
        })
        .unwrap_or_default()
}
