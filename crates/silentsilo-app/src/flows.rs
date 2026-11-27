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
//! Joining with the unlock password replaces it with [`password_join_begin`].
//!
//! The unlock password on an open silo: [`set_unlock_password`] (also a
//! change), [`remove_unlock_password`], and [`open_with_password`] to unlock.

use std::path::{Path, PathBuf};

use silentsilo_core::VaultMeta;
use silentsilo_crypto::MasterDek;
use silentsilo_store::ObjectStore;
use silentsilo_sync as sync;
use silentsilo_vault::password::{
    PasswordEnvelope, has_unlock_password, load_password_envelope, save_password_envelope,
    seal_under_password, unwrap_with_password,
};
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
    /// The unlock password's envelope, when the join was made with it.
    /// Otherwise provisioning looks for one in storage.
    password: Option<PasswordEnvelope>,
    /// The organisation key that opened this join, proven by its wrap key.
    proven_org_key: Option<String>,
    /// A rotation retired the key the credential opened.
    retired: bool,
}

impl RecoveryJoin {
    /// Whether a rotation retired the key this credential opened. Either the
    /// rotation stopped part way, which is safe to join and finish, or the
    /// storage was put back from an older copy by someone who still holds
    /// the old key and would read everything this device adds. Only the
    /// user can tell the two apart, so the caller asks before going on.
    pub fn retired_by_rotation(&self) -> bool {
        self.retired
    }

    /// The key the join plan is fetched with.
    pub fn dek(&self) -> &MasterDek {
        &self.dek
    }
}

/// Reads the silo a store holds and opens its recovery envelope with `code`.
/// Everything here can fail without leaving anything behind.
/// What a refused recovery code says. A code made by a newer version is
/// told apart from a wrong one: the format rules ask for an explicit "update"
/// rather than a wrong-code message someone would keep retyping.
fn code_refused(e: silentsilo_vault::VaultError) -> String {
    if e.to_string().contains("needs a newer SilentSilo") {
        silentsilo_core::coded!("err.code_needs_update", "This recovery code was made by a newer version of SilentSilo. Update SilentSilo, then try again.")
            .into()
    } else {
        silentsilo_core::coded!(
            "err.code_wrong",
            "That recovery code does not match this silo."
        )
        .into()
    }
}

pub async fn recovery_join_begin(
    store: &dyn ObjectStore,
    code: &str,
) -> Result<RecoveryJoin, String> {
    let manifest = sync::read_manifest(store)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            silentsilo_core::coded!(
                "err.storage_no_silo",
                "That backup storage does not hold a silo."
            )
            .to_string()
        })?;
    let envelope = sync::fetch_recovery_envelope(store)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            silentsilo_core::coded!(
                "err.no_recovery_code",
                "No recovery code was set up for this silo."
            )
            .to_string()
        })?;

    // Argon2id takes a second of CPU and memory on purpose, so it runs off
    // the async workers.
    let (dek, envelope) = {
        let code = code.to_string();
        tokio::task::spawn_blocking(move || {
            unwrap_with_code(&envelope, &code).map(|dek| (dek, envelope))
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(code_refused)?
    };
    let retired = sync::retired_by_rotation(store, &dek).await;
    Ok(RecoveryJoin {
        vault_id: manifest.vault_id,
        dek,
        envelope: Some(envelope),
        password: None,
        proven_org_key: None,
        retired,
    })
}

/// What to tell someone whose credential opened the silo but not the
/// content key beside it.
///
/// The two cases need different sentences and one of them used to be
/// reported as a crypto error. A rotation is something to act on with a
/// current credential; a content key that disagrees with the records around
/// it is storage having been written to, and joining again reads the same
/// object, so saying "rejoin" would send someone round a loop that cannot
/// end.
async fn kek_refusal(store: &dyn ObjectStore, dek: &MasterDek) -> String {
    match sync::kek_envelope_state(store, dek).await {
        Ok(sync::KekState::Replaced) => "This silo's content key in storage does not open with \
             the credential that just opened the silo, while the records beside it do. A key \
             rotation cannot leave it that way, so that object was replaced or put back from an \
             older copy. Restore the storage from a copy, or join from a device that already has \
             the silo."
            .to_string(),
        Ok(sync::KekState::RotatedUnproven) => "This silo's content key in storage does not \
             open with the credential that just opened the silo, and nothing in storage shows \
             that a rotation did that. If you changed the silo's keys on a device with an older \
             version, use a credential that was kept or the recovery code shown then. If you \
             did not, the storage was written to: restore it from a copy."
            .to_string(),
        _ => "This silo's key was rotated after this storage was last written to by a device \
             holding the credential you used. Use a credential that was kept through the \
             rotation, or the recovery code shown when it was done."
            .to_string(),
    }
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
        .ok_or_else(|| {
            silentsilo_core::coded!(
                "err.storage_no_silo",
                "That backup storage does not hold a silo."
            )
            .to_string()
        })?;
    let keys = sync::fetch_key_envelopes(store)
        .await
        .map_err(|e| e.to_string())?;
    if keys.is_empty() {
        return Err(
            silentsilo_core::coded!("err.no_keys_published", "No keys have been published to this storage yet. Sync once from a device that has the silo.")
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
    let key = offer
        .keys
        .iter()
        .find(|k| k.credential_id == credential_id && !k.wrapped_dek.is_empty())
        .ok_or_else(|| {
            silentsilo_core::coded!(
                "err.key_not_of_silo",
                "That security key isn't one of this silo's keys."
            )
            .to_string()
        })?;
    let dek = silentsilo_vault::unwrap_dek_hex(&key.wrapped_dek, wrap_key).map_err(|_| {
        silentsilo_core::coded!(
            "err.key_could_not_open",
            "That security key could not open the silo."
        )
        .to_string()
    })?;
    // A removed key's envelope can come back: a device that had not heard
    // of the removal publishes it again. The revocation marker decides.
    if let Some(sealed) = sync::fetch_content_kek(store)
        .await
        .map_err(|e| e.to_string())?
    {
        let kek = match silentsilo_vault::unwrap_kek_bytes(&sealed, &dek) {
            Ok(kek) => kek,
            Err(_) => return Err(kek_refusal(store, &dek).await),
        };
        if sync::is_key_revoked(store, &kek, credential_id)
            .await
            .map_err(|e| e.to_string())?
        {
            return Err(silentsilo_core::coded!(
                "err.key_removed",
                "That security key was removed from this silo."
            )
            .into());
        }
    }
    let envelope = sync::fetch_recovery_envelope(store).await.ok().flatten();
    let retired = sync::retired_by_rotation(store, &dek).await;
    Ok(RecoveryJoin {
        vault_id: offer.vault_id,
        dek,
        envelope,
        password: None,
        retired,
        // Whoever holds this key can always prove it, so its policy cannot
        // lock anyone out.
        proven_org_key: key.managed().then(|| key.credential_id.clone()),
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
            silentsilo_core::coded!(
                "err.storage_no_content_key",
                "This storage has no content key yet, so there is nothing here to recover."
            )
            .to_string()
        })?;
    let kek = match silentsilo_vault::unwrap_kek_bytes(&kek_envelope, &join.dek) {
        Ok(kek) => kek,
        Err(_) => return Err(kek_refusal(store, &join.dek).await),
    };
    // Read before anything is made here. A listing that failed used to count
    // as no keys at all, which left the new silo opening with this device's
    // secret alone, the weaker door the envelopes below exist to close.
    let mut keys = sync::fetch_key_envelopes(store)
        .await
        .map_err(|e| e.to_string())?;
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
    let mut usable = Vec::with_capacity(keys.len());
    for mut key in keys.drain(..) {
        if key.revoked || !sync::plausible_credential_id(&key.credential_id) {
            continue;
        }
        if sync::is_key_revoked(store, &kek, &key.credential_id)
            .await
            .unwrap_or(true)
        {
            continue;
        }
        // Policy is unauthenticated: an "org" planted on a key nobody can
        // prove would refuse rotation and recovery changes here for good.
        // Only the key that opened this join, and proved it, keeps it.
        if join.proven_org_key.as_deref() != Some(key.credential_id.as_str()) {
            key.policy.clear();
            // Nor is any of them proven here until it unlocks this device.
            key.unconfirmed = true;
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
            // A key opens the silo here now, so the device secret goes, as
            // on a first enrolment: kept, it and the `master.dek.enc` it
            // wrapped (a synced folder's history) would still open it.
            let _ = silentsilo_vault::retire_device_secret(join.vault_id);
        }
        // Created here from the published envelopes, so nothing is removed.
        let _ = save_fido_keys(
            &root,
            &StoredFidoKeys { keys },
            silentsilo_vault::Authority::Machine,
        );
    }
    // Checked before it is kept: one whose tags fail was not made on this
    // silo's current key, whatever opened it. One with none is what releases
    // before 1.10.0 wrote, which the passes after this one settle.
    if let Some(envelope) = &join.envelope
        && (envelope.auth_dek.is_none() || envelope.is_authentic_now(&kek, &join.dek))
    {
        save_recovery_envelope(&root, envelope).map_err(|e| e.to_string())?;
    }

    // The unlock password comes too, so it opens this copy from the start.
    let password = match &join.password {
        Some(envelope) => Some(envelope.clone()),
        None => adoptable_password(store, &kek, &join.dek).await,
    };
    if let Some(envelope) = password {
        save_password_envelope(&root, &envelope).map_err(|e| e.to_string())?;
        if !key_opens_here(&root) {
            guard_with_password(&root, join.vault_id, &envelope)?;
        }
    }

    session.backup_locally().map_err(|e| e.to_string())?;
    Ok(session)
}

/// Whether a key this device has proven opens the silo here: usable on
/// this platform, enrolled or unlocked with here, holding an envelope. One
/// that only came down from storage, another phone's included, does not.
pub fn key_opens_here(root: &Path) -> bool {
    load_fido_keys(root).is_ok_and(|keys| keys.opens_here())
}

/// Whether the local DEK envelope is not yet the password's: a set that
/// stopped before [`guard_with_password`], or one that failed. The sync pass
/// guards again when this says so.
pub fn password_guard_missing(root: &Path, envelope: &PasswordEnvelope) -> bool {
    let wanted = hex::decode(&envelope.wrapped_dek).ok();
    let held = std::fs::read(silentsilo_vault::dek_store::dek_path(root)).ok();
    wanted.is_none() || wanted != held
}

/// Puts the local DEK envelope under the password and retires the device
/// secret, as a first key does: kept, the secret and an old
/// `master.dek.enc` (a synced folder's history) would open the silo without
/// the password. For a silo no key opens here.
pub fn guard_with_password(
    root: &Path,
    vault_id: Uuid,
    envelope: &PasswordEnvelope,
) -> Result<(), String> {
    let wrapped = hex::decode(&envelope.wrapped_dek).map_err(|e| e.to_string())?;
    silentsilo_vault::save_wrapped_dek_bytes(root, &wrapped).map_err(|e| e.to_string())?;
    silentsilo_vault::retire_device_secret(vault_id).map_err(|e| e.to_string())
}

/// The password envelope a store holds, when a device on the current vault
/// key made it and no removal covers it.
async fn adoptable_password(
    store: &dyn ObjectStore,
    kek: &silentsilo_crypto::ContentKek,
    dek: &MasterDek,
) -> Option<PasswordEnvelope> {
    let Ok(sync::unlock_password::StoredPassword::Envelope(envelope)) =
        sync::unlock_password::fetch_password_envelope(store).await
    else {
        return None;
    };
    match sync::unlock_password::joinable(store, &envelope, kek, dek).await {
        Ok(true) => Some(envelope),
        _ => None,
    }
}

/// What a refused unlock password says. One set by a newer version is told
/// apart from a wrong one, as for the recovery code.
fn password_refused(e: silentsilo_vault::VaultError) -> String {
    if e.to_string().contains("needs a newer SilentSilo") {
        silentsilo_core::coded!(
            "err.password_needs_update",
            "This unlock password was set by a newer version of SilentSilo. Update SilentSilo, then try again."
        )
        .into()
    } else {
        silentsilo_core::coded!(
            "err.password_wrong",
            "That password does not open this silo."
        )
        .into()
    }
}

fn password_not_of_silo() -> String {
    silentsilo_core::coded!(
        "err.password_not_of_silo",
        "This silo's unlock password was not set on its current key. Use the recovery code or a key."
    )
    .into()
}

/// Reads the silo a store holds and opens it with the unlock password.
/// Nothing local is touched. The envelope's tags are checked before
/// anything is kept: storage is not trusted, and only a device holding the
/// current vault key can make them.
pub async fn password_join_begin(
    store: &dyn ObjectStore,
    password: &str,
) -> Result<RecoveryJoin, String> {
    use sync::unlock_password::{StoredPassword, fetch_password_envelope};

    let manifest = sync::read_manifest(store)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            silentsilo_core::coded!(
                "err.storage_no_silo",
                "That backup storage does not hold a silo."
            )
            .to_string()
        })?;
    let envelope = match fetch_password_envelope(store)
        .await
        .map_err(|e| e.to_string())?
    {
        StoredPassword::Envelope(envelope) => envelope,
        StoredPassword::NeedsNewer => {
            return Err(password_refused(silentsilo_vault::VaultError::Corrupted(
                "needs a newer SilentSilo".into(),
            )));
        }
        StoredPassword::Absent | StoredPassword::Junk => {
            return Err(silentsilo_core::coded!(
                "err.no_unlock_password",
                "No unlock password was set up for this silo."
            )
            .into());
        }
    };
    // Lighter than this build seals with: not one SilentSilo made, and no
    // guess is spent on it.
    if !envelope.meets_kdf_floor() {
        return Err(password_not_of_silo());
    }

    // Argon2id at 256 MiB, off the async workers.
    let (dek, envelope) = {
        let password = zeroize::Zeroizing::new(password.to_string());
        tokio::task::spawn_blocking(move || {
            unwrap_with_password(&envelope, &password).map(|dek| (dek, envelope))
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(password_refused)?
    };

    let sealed = sync::fetch_content_kek(store)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            silentsilo_core::coded!(
                "err.storage_no_content_key",
                "This storage has no content key yet, so there is nothing here to recover."
            )
            .to_string()
        })?;
    let kek = match silentsilo_vault::unwrap_kek_bytes(&sealed, &dek) {
        Ok(kek) => kek,
        Err(_) => return Err(kek_refusal(store, &dek).await),
    };
    if !envelope.is_authentic_now(&kek, &dek) {
        return Err(password_not_of_silo());
    }
    if let Some(off) = sync::unlock_password::password_removed_at(store, &kek)
        .await
        .map_err(|e| e.to_string())?
        && envelope.created_at <= off
    {
        return Err(silentsilo_core::coded!(
            "err.password_removed",
            "The unlock password was removed from this silo. Use the recovery code or a key."
        )
        .into());
    }

    let recovery = sync::fetch_recovery_envelope(store).await.ok().flatten();
    let retired = sync::retired_by_rotation(store, &dek).await;
    Ok(RecoveryJoin {
        vault_id: manifest.vault_id,
        dek,
        envelope: recovery,
        password: Some(envelope),
        proven_org_key: None,
        retired,
    })
}

/// Opens a silo on this device with the unlock password. Disk work and
/// Argon2id: blocking thread.
pub fn open_with_password(
    root: PathBuf,
    password: &str,
    expected_vault_id: Uuid,
) -> Result<(VaultSession, VaultMeta), String> {
    let envelope = load_password_envelope(&root).map_err(|_| {
        silentsilo_core::coded!(
            "err.no_unlock_password",
            "No unlock password was set up for this silo."
        )
        .to_string()
    })?;
    open_with(root, &envelope, password, expected_vault_id)
}

/// [`open_with_password`] with the envelope a copy holds, for a password
/// changed on another device since this one last synced. Kept as this
/// device's copy once it opened the silo and its tag is the silo's.
pub fn open_with_stored_password(
    root: PathBuf,
    envelope: &PasswordEnvelope,
    password: &str,
    expected_vault_id: Uuid,
) -> Result<(VaultSession, VaultMeta), String> {
    if !envelope.meets_kdf_floor() {
        return Err(password_not_of_silo());
    }
    let opened = open_with(root, envelope, password, expected_vault_id)?;
    let root = &opened.0.paths.root;
    save_password_envelope(root, envelope).map_err(|e| e.to_string())?;
    if !key_opens_here(root) {
        guard_with_password(root, expected_vault_id, envelope)?;
    }
    Ok(opened)
}

/// Whether an unlock error is a wrong password, the one worth trying the
/// copy in storage for and counting towards the wait.
pub fn is_wrong_password(error: &str) -> bool {
    error.contains("err.password_wrong")
}

fn open_with(
    root: PathBuf,
    envelope: &PasswordEnvelope,
    password: &str,
    expected_vault_id: Uuid,
) -> Result<(VaultSession, VaultMeta), String> {
    let dek = unwrap_with_password(envelope, password).map_err(password_refused)?;
    let session = VaultSession::open_with_dek(root, dek).map_err(|e| e.to_string())?;
    // The copy in the silo folder is held to the same rule as storage's:
    // whoever can write there cannot make the tag.
    if !envelope.is_authentic_now(&session.kek, &session.dek) {
        return Err(password_not_of_silo());
    }
    if session.vault_id != expected_vault_id {
        return Err(silentsilo_core::coded!(
            "err.password_other_silo",
            "That password opens a different silo."
        )
        .into());
    }
    // It opens the silo without a key, so the secret has nothing left to do.
    if !key_opens_here(&session.paths.root) {
        let _ = silentsilo_vault::retire_device_secret(session.vault_id);
    }
    let vfs = Vfs::new(&session);
    vfs.ensure_initialized().map_err(|e| e.to_string())?;
    let meta = vfs.meta().map_err(|e| e.to_string())?;
    crate::wipe_open_scratch(&session.paths.root);
    Ok((session, meta))
}

/// Whether the silo at `root` has an unlock password on this device.
pub fn has_password(root: &Path) -> bool {
    has_unlock_password(root)
}

/// Checks a password the user typed again to confirm an action, against
/// the envelope this device holds. Argon2id: blocking thread.
pub fn check_password(
    root: &Path,
    password: &str,
    kek: &silentsilo_crypto::ContentKek,
    dek: &MasterDek,
) -> Result<(), String> {
    let envelope = load_password_envelope(root).map_err(|_| {
        silentsilo_core::coded!(
            "err.no_unlock_password",
            "No unlock password was set up for this silo."
        )
        .to_string()
    })?;
    let opened = unwrap_with_password(&envelope, password).map_err(password_refused)?;
    // Both tags equal only if the key it opened is the session's: the
    // comparison is the tag's, in constant time.
    if !envelope.is_authentic_now(kek, dek) || !envelope.is_authentic_now(kek, &opened) {
        return Err(password_refused(
            silentsilo_vault::VaultError::InvalidCredentials,
        ));
    }
    Ok(())
}

/// The words the strength check holds against a new password: the silo's
/// name, its keys' labels, and whatever else the app knows (the device's
/// name). The check adds "silentsilo" itself.
pub fn password_context(root: &Path, silo_name: &str, extra: &[&str]) -> Vec<String> {
    let mut words: Vec<String> = vec![silo_name.to_string()];
    if let Ok(keys) = load_fido_keys(root) {
        words.extend(keys.active().map(|k| k.label.clone()));
    }
    words.extend(extra.iter().map(|w| w.to_string()));
    words.retain(|w| !w.trim().is_empty());
    words
}

/// An open silo, as the password flows need it.
pub struct OpenSilo<'a> {
    pub root: &'a Path,
    pub vault_id: Uuid,
    pub dek: &'a MasterDek,
    pub kek: &'a silentsilo_crypto::ContentKek,
}

impl<'a> OpenSilo<'a> {
    pub fn of(session: &'a VaultSession) -> Self {
        Self {
            root: &session.paths.root,
            vault_id: session.vault_id,
            dek: &session.dek,
            kek: &session.kek,
        }
    }
}

/// Sets the unlock password on an open silo, or changes it. `stores` are the
/// silo's copies, read for the date the new envelope has to be after.
///
/// Sealed here and saved locally; the next sync pass publishes it. On a silo
/// no key opens here, the local DEK envelope goes under the password and the
/// device secret is retired. The caller has already asked for what
/// [`crate::confirmation_for`] says, the old password included on a change.
///
/// On a silo an organisation administers, a password is another way in the
/// organisation did not hand out: refused without the touch of one of its
/// keys ([`silentsilo_vault::Authority::Organisation`]).
pub async fn set_unlock_password(
    silo: OpenSilo<'_>,
    stores: &[&dyn ObjectStore],
    password: &str,
    context: &[String],
    confirmed_weak: bool,
    authority: silentsilo_vault::Authority<'_>,
) -> Result<PasswordEnvelope, String> {
    if matches!(authority, silentsilo_vault::Authority::Machine)
        && load_fido_keys(silo.root).is_ok_and(|keys| keys.is_org_controlled())
    {
        return Err(silentsilo_core::coded!(
            "err.password_needs_org_key",
            "This silo is administered by an organisation, so a password needs one of its keys."
        )
        .into());
    }
    let floor = sync::unlock_password::password_date_floor(stores, silo.kek, silo.dek).await;
    let mut envelope = {
        let dek = silo.dek.clone();
        let kek = silo.kek.clone();
        let password = zeroize::Zeroizing::new(password.to_string());
        let context = context.to_vec();
        tokio::task::spawn_blocking(move || {
            let inputs: Vec<&str> = context.iter().map(String::as_str).collect();
            seal_under_password(&dek, &kek, &password, &inputs, confirmed_weak)
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?
    };
    // After the one it replaces and after the newest marker or envelope any
    // copy holds, whatever this clock says, but never far past it.
    if let Ok(local) = load_password_envelope(silo.root) {
        let after = local
            .created_at
            .saturating_add(1)
            .min(sync::unlock_password::date_ceiling());
        envelope.date_after(after, silo.kek, silo.dek);
    }
    envelope.date_after(floor, silo.kek, silo.dek);
    save_password_envelope(silo.root, &envelope).map_err(|e| e.to_string())?;
    // The password is set from here on. A guard that fails is done again by
    // the next sync pass ([`password_guard_missing`]).
    if !key_opens_here(silo.root) {
        let _ = guard_with_password(silo.root, silo.vault_id, &envelope);
    }
    Ok(envelope)
}

/// Removes the unlock password everywhere: a marker on every copy, the
/// envelope deleted where deleting is allowed, the local copy gone.
///
/// Refused while no key opens the silo here: a silo needs a key or a
/// password on top of the recovery code. `key_usable_here` is the app's
/// answer (a phone's key whose fingerprint changed is recorded but opens
/// nothing); [`key_opens_here`] has to agree. `targets` pairs each copy with
/// whether it allows deletes.
pub async fn remove_unlock_password(
    root: &Path,
    kek: &silentsilo_crypto::ContentKek,
    targets: &[(&dyn ObjectStore, bool)],
    key_usable_here: bool,
) -> Result<(), String> {
    if !has_unlock_password(root) {
        return Ok(());
    }
    if !key_usable_here || !key_opens_here(root) {
        return Err(silentsilo_core::coded!(
            "err.password_last_way_in",
            "The password is this silo's only way in besides the recovery code. Add a key first."
        )
        .into());
    }
    sync::unlock_password::remove_password(targets, kek, root)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
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
    let store = store.ok_or_else(|| {
        silentsilo_core::coded!(
            "err.no_recovery_code",
            "No recovery code is set up for this silo."
        )
        .to_string()
    })?;
    sync::fetch_recovery_envelope(store)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            silentsilo_core::coded!(
                "err.no_recovery_code",
                "No recovery code is set up for this silo."
            )
            .to_string()
        })
}

/// Opens a silo on this device with the recovery code. Disk work: blocking
/// thread.
pub fn open_with_recovery(
    root: PathBuf,
    envelope: &RecoveryEnvelope,
    code: &str,
    expected_vault_id: Uuid,
) -> Result<(VaultSession, VaultMeta), String> {
    let dek = unwrap_with_code(envelope, code).map_err(code_refused)?;
    let session = VaultSession::open_with_dek(root, dek).map_err(|e| e.to_string())?;
    if session.vault_id != expected_vault_id {
        return Err(silentsilo_core::coded!(
            "err.code_other_silo",
            "That recovery code opens a different silo."
        )
        .into());
    }
    let vfs = Vfs::new(&session);
    vfs.ensure_initialized().map_err(|e| e.to_string())?;
    let meta = vfs.meta().map_err(|e| e.to_string())?;
    Ok((session, meta))
}

/// A key made on this device, ready to record: what its platform returned.
/// The wrap key is wiped when this is dropped.
pub struct DeviceKey {
    pub kind: String,
    pub derivation: String,
    pub credential_id: String,
    pub public_key: String,
    pub wrap_key: [u8; 32],
    pub label: String,
}

impl Drop for DeviceKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.wrap_key);
    }
}

/// Records a device key on an open silo. The first key on a silo also
/// re-wraps the local DEK envelope under it, as the desktop's first
/// enrolment does, and retires the device secret
/// (`silentsilo_vault::retire_device_secret`), so it opens nothing again.
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
        unconfirmed: false,
    };
    keys.keys.push(stored.clone());
    if first {
        silentsilo_vault::save_wrapped_dek_bytes(root, &envelope).map_err(|e| e.to_string())?;
    }
    save_fido_keys(root, &keys, silentsilo_vault::Authority::Machine).map_err(|e| e.to_string())?;
    // The key opens the silo now, so the device secret goes: kept, it and
    // an old copy of `master.dek.enc` (a synced folder's history) would
    // still open it. Not fatal: the next unlock with a key tries again.
    if first {
        let _ = silentsilo_vault::retire_device_secret(session.vault_id);
    }
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
    // It opened the silo here, so it is one of this device's keys now.
    let _ = silentsilo_vault::confirm_key(&session.paths.root, credential_id);
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
