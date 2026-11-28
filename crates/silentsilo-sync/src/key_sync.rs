//! Keeping each device's list of enrolled keys in step with the others.
//!
//! Every device publishes its keys' envelopes to `keys/`, but until this a
//! device learned other devices' keys only when it joined: a phone added
//! later never appeared on a desktop that was already set up, and a key
//! revoked on one device was published again by any other that still had it.
//!
//! A pass now calls [`reconcile_key_envelopes`] before it pushes:
//!
//! - a revocation this device made leaves a marker at
//!   `keys/revoked/<credential_id>.sealed`, sealed under the content KEK so
//!   nobody with only write access to storage can forge one;
//! - a key another device revoked is marked revoked here too, so it is not
//!   published again;
//! - a key another device enrolled is added here, carrying no organisation
//!   policy on a silo that has none, and never on a silo with no keys file
//!   (one that opens with its device secret must not start asking for a key).
//!
//! A client that has never heard of this (1.0.0) skips the markers as
//! unreadable envelopes and behaves as it always did.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use silentsilo_crypto::{ContentKek, MasterDek, seal_with_key, unseal_with_key};
use silentsilo_store::ObjectStore;
use silentsilo_vault::{StoredFidoCredential, StoredFidoKeys};

use crate::{KEYS_PREFIX, SyncError};

pub const REVOKED_PREFIX: &str = "keys/revoked/";

const MARKER_VERSION: u32 = 1;

/// `keys/revoked/<credential_id>.sealed`, once opened.
///
/// `proof`, from 1.12, is a tag under the vault key of the device that
/// revoked: the content key a marker is sealed with never rotates, so
/// anyone who once held it can seal one, but only a holder of the current
/// vault key can make the proof. Earlier readers skip the field.
#[derive(Serialize, Deserialize)]
struct RevocationMarker {
    version: u32,
    credential_id: String,
    revoked_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof: Option<String>,
}

fn proof_for(dek: &MasterDek, credential_id: &str, revoked_at: i64) -> blake3::Hash {
    let key = blake3::derive_key("silentsilo 2026-11-28 key revocation proof", dek.as_bytes());
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(&(credential_id.len() as u64).to_le_bytes());
    hasher.update(credential_id.as_bytes());
    hasher.update(&revoked_at.to_le_bytes());
    hasher.finalize()
}

impl RevocationMarker {
    /// Whether the proof was made with `dek`. Compared in constant time.
    fn proven_by(&self, dek: &MasterDek) -> bool {
        self.proof
            .as_deref()
            .and_then(|hex| blake3::Hash::from_hex(hex).ok())
            .is_some_and(|tag| tag == proof_for(dek, &self.credential_id, self.revoked_at))
    }
}

fn marker_key(credential_id: &str) -> String {
    format!("{REVOKED_PREFIX}{credential_id}.sealed")
}

/// Whether storage holds a marker revoking `credential_id` that opens with
/// `kek`. One that does not open proves nothing: anyone holding the storage
/// credentials can write an object there.
pub async fn is_key_revoked(
    client: &dyn ObjectStore,
    kek: &ContentKek,
    credential_id: &str,
) -> Result<bool, SyncError> {
    let Some(bytes) = crate::fetch_small(client, &marker_key(credential_id)).await? else {
        return Ok(false);
    };
    Ok(unseal_with_key(&bytes, kek.as_bytes())
        .ok()
        .and_then(|plain| serde_json::from_slice::<RevocationMarker>(&plain).ok())
        .is_some_and(|m| m.credential_id == credential_id))
}

/// How far ahead of this device's clock a marker's date may be and still
/// count: clocks drift, but not by more than a day.
const MARKER_CLOCK_SLACK_SECS: i64 = 86_400;

/// When storage says the marker for `credential_id` was written, if it
/// holds one that opens with `kek`.
///
/// A date further ahead than [`MARKER_CLOCK_SLACK_SECS`] is ignored: the
/// recovery code's marker kills every envelope made before it, so one dated
/// in the far future would also kill every code made from now on.
pub async fn revoked_at(
    client: &dyn ObjectStore,
    kek: &ContentKek,
    credential_id: &str,
) -> Result<Option<i64>, SyncError> {
    let Some(bytes) = marker_bytes(client, credential_id).await? else {
        return Ok(None);
    };
    Ok(marker_date(&bytes, kek, credential_id))
}

/// The sealed marker for `credential_id`, as storage holds it.
pub async fn marker_bytes(
    client: &dyn ObjectStore,
    credential_id: &str,
) -> Result<Option<Vec<u8>>, SyncError> {
    crate::fetch_small(client, &marker_key(credential_id)).await
}

/// The date in a marker fetched earlier, if it opens with `kek`, names
/// `credential_id` and is not dated past [`MARKER_CLOCK_SLACK_SECS`].
pub fn marker_date(bytes: &[u8], kek: &ContentKek, credential_id: &str) -> Option<i64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    marker_date_as_written(bytes, kek, credential_id)
        .filter(|at| *at <= now.saturating_add(MARKER_CLOCK_SLACK_SECS))
}

/// The date a marker carries, however far ahead of this clock.
pub(crate) fn marker_date_as_written(
    bytes: &[u8],
    kek: &ContentKek,
    credential_id: &str,
) -> Option<i64> {
    unseal_with_key(bytes, kek.as_bytes())
        .ok()
        .and_then(|plain| serde_json::from_slice::<RevocationMarker>(&plain).ok())
        .filter(|m| m.credential_id == credential_id)
        .map(|m| m.revoked_at)
}

/// The id the recovery code's marker goes under. Not hex, so no key can
/// ever have it, and the key reconciliation already ignores it.
pub const RECOVERY_MARKER_ID: &str = "recovery";

/// Records that the recovery code was turned off at `at`: every envelope
/// made at or before then is dead, whichever device still holds one. The
/// same sealed marker a key's removal leaves, which every earlier client
/// already skips.
pub async fn mark_recovery_disabled(
    client: &dyn ObjectStore,
    kek: &ContentKek,
    at: i64,
) -> Result<(), SyncError> {
    let marker = RevocationMarker {
        version: MARKER_VERSION,
        credential_id: RECOVERY_MARKER_ID.into(),
        revoked_at: at,
        proof: None,
    };
    let json = serde_json::to_vec(&marker).map_err(|e| SyncError::Vault(e.to_string()))?;
    let sealed = seal_with_key(&json, kek.as_bytes())?;
    client.put(&marker_key(RECOVERY_MARKER_ID), sealed).await?;
    Ok(())
}

/// The id the unlock password's marker goes under. Not hex either, so the
/// key reconciliation ignores it, as it ignores the recovery code's.
pub const PASSWORD_MARKER_ID: &str = "unlock-password";

/// Records that the unlock password was removed at `at`: every envelope made
/// at or before then is dead, as with the recovery code.
pub async fn mark_password_removed(
    client: &dyn ObjectStore,
    kek: &ContentKek,
    at: i64,
) -> Result<(), SyncError> {
    let marker = RevocationMarker {
        version: MARKER_VERSION,
        credential_id: PASSWORD_MARKER_ID.into(),
        revoked_at: at,
        proof: None,
    };
    let json = serde_json::to_vec(&marker).map_err(|e| SyncError::Vault(e.to_string()))?;
    let sealed = seal_with_key(&json, kek.as_bytes())?;
    client.put(&marker_key(PASSWORD_MARKER_ID), sealed).await?;
    Ok(())
}

/// What one reconciliation changed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KeyReconcile {
    /// Keys another device enrolled, now in the local list.
    pub added: Vec<String>,
    /// Keys another device revoked, now tombstoned here.
    pub revoked: Vec<String>,
    /// Tombstones whose marker storage now holds. Only these may be dropped
    /// from the local list once their envelope is gone; without a marker the
    /// revocation would not reach the other devices.
    pub marked: HashSet<String>,
}

impl KeyReconcile {
    pub fn changed(&self) -> bool {
        !self.added.is_empty() || !self.revoked.is_empty()
    }
}

/// The credential id a marker revokes, if it opens under `kek` and names
/// the key its object name does.
fn open_marker(bytes: &[u8], kek: &ContentKek, id: &str) -> Option<String> {
    read_marker(bytes, kek, id).map(|m| m.credential_id)
}

fn read_marker(bytes: &[u8], kek: &ContentKek, id: &str) -> Option<RevocationMarker> {
    unseal_with_key(bytes, kek.as_bytes())
        .ok()
        .and_then(|plain| serde_json::from_slice::<RevocationMarker>(&plain).ok())
        .filter(|m| m.version == MARKER_VERSION && m.credential_id == id)
}

/// The markers a store holds, and which of them carry a proof made with
/// the current vault key.
#[derive(Debug, Default, Clone)]
pub struct RevocationMarks {
    pub all: HashSet<String>,
    pub proven: HashSet<String>,
}

impl RevocationMarks {
    fn add(&mut self, marker: RevocationMarker, dek: &MasterDek) {
        if marker.proven_by(dek) {
            self.proven.insert(marker.credential_id.clone());
        }
        self.all.insert(marker.credential_id);
    }

    pub fn extend(&mut self, other: RevocationMarks) {
        self.all.extend(other.all);
        self.proven.extend(other.proven);
    }
}

/// Every key `client` holds a marker for that opens under `kek`.
///
/// A pass reads these from every copy before reconciling any: a copy that
/// was unplugged when a key was removed still holds its envelope and no
/// marker, and judged on its own markers it put the key back.
pub async fn revocation_marks(
    client: &dyn ObjectStore,
    kek: &ContentKek,
) -> Result<HashSet<String>, SyncError> {
    let mut marked = HashSet::new();
    for entry in client.list(KEYS_PREFIX).await? {
        if crate::too_large(entry.size) {
            continue;
        }
        let Some(id) = entry
            .key
            .strip_prefix(REVOKED_PREFIX)
            .and_then(|name| name.strip_suffix(".sealed"))
        else {
            continue;
        };
        let Ok(bytes) = client.get(&entry.key).await else {
            continue;
        };
        marked.extend(open_marker(&bytes, kek, id));
    }
    Ok(marked)
}

/// [`revocation_marks`], telling apart the markers a holder of `dek` made.
pub async fn revocation_marks_proven(
    client: &dyn ObjectStore,
    kek: &ContentKek,
    dek: &MasterDek,
) -> Result<RevocationMarks, SyncError> {
    let mut marks = RevocationMarks::default();
    for entry in client.list(KEYS_PREFIX).await? {
        if crate::too_large(entry.size) {
            continue;
        }
        let Some(id) = entry
            .key
            .strip_prefix(REVOKED_PREFIX)
            .and_then(|name| name.strip_suffix(".sealed"))
        else {
            continue;
        };
        let Ok(bytes) = client.get(&entry.key).await else {
            continue;
        };
        if let Some(marker) = read_marker(&bytes, kek, id) {
            marks.add(marker, dek);
        }
    }
    Ok(marks)
}

/// Reads the envelopes and revocation markers `client` holds, writes a
/// marker for every revocation of this device's that lacks one, and folds
/// the rest into `local`. The caller saves `local` when [`KeyReconcile::changed`].
///
/// `marked_elsewhere` is what [`revocation_marks`] found on the other copies:
/// an envelope is not taken in when any copy holds a marker for its key.
pub async fn reconcile_key_envelopes(
    client: &dyn ObjectStore,
    kek: &ContentKek,
    local: &mut StoredFidoKeys,
    now: i64,
    marked_elsewhere: &HashSet<String>,
) -> Result<KeyReconcile, SyncError> {
    let mut published = Vec::new();
    let mut marked = HashSet::new();
    read_keys(client, kek, &mut published, &mut |bytes, id| {
        marked.extend(open_marker(bytes, kek, id))
    })
    .await?;
    publish_own_revocations(client, kek, local, now, None, &mut marked).await?;
    let everywhere: HashSet<String> = marked.union(marked_elsewhere).cloned().collect();
    let mut outcome = merge(local, published, &everywhere, &HashSet::new(), false);
    outcome.marked = marked;
    Ok(outcome)
}

/// [`reconcile_key_envelopes`] with the vault key at hand: the markers this
/// device writes carry its proof, and `password_here` (the unlock password
/// opens the silo here) lets a removal take this device's last key, but only
/// when every marker that does so carries a proof made with `dek`. A forged
/// set, sealed by someone who once held the content key, is not followed.
pub async fn reconcile_key_envelopes_with(
    client: &dyn ObjectStore,
    kek: &ContentKek,
    dek: &MasterDek,
    local: &mut StoredFidoKeys,
    now: i64,
    marked_elsewhere: &RevocationMarks,
    password_here: bool,
) -> Result<KeyReconcile, SyncError> {
    let mut published = Vec::new();
    let mut marks = RevocationMarks::default();
    read_keys(client, kek, &mut published, &mut |bytes, id| {
        if let Some(marker) = read_marker(bytes, kek, id) {
            marks.add(marker, dek);
        }
    })
    .await?;
    // A marker already there without this vault key's proof (an earlier
    // build's, or a forged one) is written over with one that has it.
    let mut proven_here = marks.proven.clone();
    publish_own_revocations(client, kek, local, now, Some(dek), &mut proven_here).await?;
    let marked: HashSet<String> = marks.all.union(&proven_here).cloned().collect();
    let everywhere: HashSet<String> = marked.union(&marked_elsewhere.all).cloned().collect();
    let proven: HashSet<String> = proven_here
        .union(&marked_elsewhere.proven)
        .cloned()
        .collect();
    let mut outcome = merge(local, published, &everywhere, &proven, password_here);
    outcome.marked = marked;
    Ok(outcome)
}

/// Lists `keys/`: envelopes into `published`, each marker's bytes to
/// `on_marker` with the id its name gives.
async fn read_keys(
    client: &dyn ObjectStore,
    _kek: &ContentKek,
    published: &mut Vec<StoredFidoCredential>,
    on_marker: &mut (dyn FnMut(&[u8], &str) + Send),
) -> Result<(), SyncError> {
    for entry in client.list(KEYS_PREFIX).await? {
        // Storage is untrusted: nothing that size is a marker or an envelope.
        if crate::too_large(entry.size) {
            continue;
        }
        if let Some(name) = entry.key.strip_prefix(REVOKED_PREFIX) {
            let Some(id) = name.strip_suffix(".sealed") else {
                continue;
            };
            let Ok(bytes) = client.get(&entry.key).await else {
                continue;
            };
            on_marker(&bytes, id);
            continue;
        }
        if !entry.key.ends_with(".env") {
            continue;
        }
        let Ok(bytes) = client.get(&entry.key).await else {
            continue;
        };
        if let Ok(key) = serde_json::from_slice::<StoredFidoCredential>(&bytes) {
            published.push(key);
        }
    }
    Ok(())
}

/// This device's own revocations, published before anything else so they
/// reach storage even if the rest of the pass fails. With `dek`, each
/// carries its proof.
async fn publish_own_revocations(
    client: &dyn ObjectStore,
    kek: &ContentKek,
    local: &StoredFidoKeys,
    now: i64,
    dek: Option<&MasterDek>,
    marked: &mut HashSet<String>,
) -> Result<(), SyncError> {
    for key in local.keys.iter().filter(|k| k.revoked) {
        if marked.contains(&key.credential_id) {
            continue;
        }
        let marker = RevocationMarker {
            version: MARKER_VERSION,
            credential_id: key.credential_id.clone(),
            revoked_at: now,
            proof: dek.map(|dek| proof_for(dek, &key.credential_id, now).to_hex().to_string()),
        };
        let json = serde_json::to_vec(&marker).map_err(|e| SyncError::Vault(e.to_string()))?;
        let sealed = seal_with_key(&json, kek.as_bytes())?;
        client.put(&marker_key(&key.credential_id), sealed).await?;
        marked.insert(key.credential_id.clone());
    }
    Ok(())
}

/// Hex, non-empty and of a sane length: what every key kind writes.
pub fn plausible_credential_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 2048 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The decision, apart from storage.
fn merge(
    local: &mut StoredFidoKeys,
    published: Vec<StoredFidoCredential>,
    marked: &HashSet<String>,
    proven: &HashSet<String>,
    password_here: bool,
) -> KeyReconcile {
    let mut outcome = KeyReconcile::default();

    // An organisation's key is retired only with its proof, which a device
    // following someone else's revocation does not hold; the write guard
    // would refuse it, so it is left for that device's own action.
    let follows = |key: &StoredFidoCredential| {
        !key.revoked && !key.managed() && marked.contains(&key.credential_id)
    };
    // Markers are sealed under the content key, which never rotates: anyone
    // who once held it can write one for every key. Followed blindly, that
    // removes every way into the silo on every device. A set of markers
    // that would leave this device no key it can open the silo with is not
    // followed; the device that removed its last key did so knowingly and
    // needs no other device's help. Only keys this device has enrolled or
    // unlocked with count: an envelope planted in storage would otherwise
    // be the one key "left" after every real one was marked. The unlock
    // password counts as a way left, it opens the silo here without a key,
    // but only for removals a holder of the current vault key proved: a
    // forged set would otherwise swap every key for a typed password.
    let would_remain = local
        .usable()
        .filter(|key| !key.unconfirmed && !follows(key))
        .count();
    let all_proven = local
        .usable()
        .filter(|key| follows(key))
        .all(|key| proven.contains(&key.credential_id));
    if would_remain > 0 || (password_here && all_proven) {
        for key in local.keys.iter_mut() {
            if follows(key) {
                key.revoked = true;
                outcome.revoked.push(key.credential_id.clone());
            }
        }
    }

    let org_controlled = local.is_org_controlled();
    for mut key in published {
        let known = local
            .keys
            .iter()
            .any(|k| k.credential_id == key.credential_id);
        if known || key.revoked || marked.contains(&key.credential_id) {
            continue;
        }
        // Every kind writes its credential id as hex. Anything else would
        // go into object names (`keys/<id>.env`), where a `..` or a `/` from
        // an envelope nobody authenticated could reach outside `keys/`.
        if !plausible_credential_id(&key.credential_id) {
            continue;
        }
        // An envelope is not authenticated. A policy arriving on a silo
        // nobody administers would let anyone with write access to storage
        // lock its owner out of changing the recovery code.
        if !org_controlled {
            key.policy.clear();
        }
        // Until this device unlocks with it, nothing says it is real.
        key.unconfirmed = true;
        outcome.added.push(key.credential_id.clone());
        local.keys.push(key);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str) -> StoredFidoCredential {
        StoredFidoCredential {
            kind: "fido2".into(),
            derivation: "hmac-secret-v1".into(),
            policy: String::new(),
            credential_id: id.into(),
            public_key: String::new(),
            key_slot: 0,
            rp_id: "silentsilo.com".into(),
            label: id.into(),
            wrapped_dek: "ef".into(),
            platform: false,
            revoked: false,
            unconfirmed: false,
        }
    }

    #[test]
    fn another_devices_key_is_added_and_a_revoked_one_is_not() {
        let mut local = StoredFidoKeys {
            keys: vec![key("aa11")],
        };
        let marked = HashSet::from(["cc33".to_string()]);
        let outcome = merge(
            &mut local,
            vec![key("aa11"), key("bb22"), key("cc33")],
            &marked,
            &HashSet::new(),
            false,
        );
        assert_eq!(outcome.added, vec!["bb22".to_string()]);
        assert_eq!(local.keys.len(), 2);
    }

    #[test]
    fn a_key_revoked_elsewhere_is_tombstoned_here_but_not_an_organisations() {
        let mut org = key("bb22");
        org.policy = silentsilo_vault::POLICY_ORG.into();
        let mut local = StoredFidoKeys {
            keys: vec![key("aa11"), org, key("cc33")],
        };
        let marked = HashSet::from(["aa11".to_string(), "bb22".to_string()]);
        let outcome = merge(&mut local, Vec::new(), &marked, &HashSet::new(), false);
        assert_eq!(outcome.revoked, vec!["aa11".to_string()]);
        assert!(local.keys[0].revoked);
        assert!(!local.keys[1].revoked, "the organisation key is left alone");
    }

    #[test]
    fn an_envelope_whose_id_is_not_hex_is_not_taken_in() {
        let mut local = StoredFidoKeys {
            keys: vec![key("aa11")],
        };
        let outcome = merge(
            &mut local,
            vec![key("../../ops/x"), key("bb/22"), key("cc33")],
            &HashSet::new(),
            &HashSet::new(),
            false,
        );
        assert_eq!(outcome.added, vec!["cc33".to_string()]);
    }

    #[test]
    fn markers_for_every_key_left_are_not_followed() {
        let mut local = StoredFidoKeys {
            keys: vec![key("aa11"), key("bb22")],
        };
        let marked = HashSet::from(["aa11".to_string(), "bb22".to_string()]);
        let outcome = merge(&mut local, Vec::new(), &marked, &HashSet::new(), false);
        assert!(outcome.revoked.is_empty());
        assert!(local.keys.iter().all(|k| !k.revoked));

        // One of two is still followed.
        let only = HashSet::from(["aa11".to_string()]);
        let outcome = merge(&mut local, Vec::new(), &only, &HashSet::new(), false);
        assert_eq!(outcome.revoked, vec!["aa11".to_string()]);
    }

    #[test]
    fn with_the_password_only_proven_markers_take_the_last_key() {
        let mut local = StoredFidoKeys {
            keys: vec![key("aa11"), key("bb22")],
        };
        let marked = HashSet::from(["aa11".to_string(), "bb22".to_string()]);
        // Sealed by someone who once held the content key: no proof.
        let outcome = merge(&mut local, Vec::new(), &marked, &HashSet::new(), true);
        assert!(outcome.revoked.is_empty());
        // One proven, one not: still not followed.
        let half = HashSet::from(["aa11".to_string()]);
        let outcome = merge(&mut local, Vec::new(), &marked, &half, true);
        assert!(outcome.revoked.is_empty());
        // Both proven by the current vault key: followed.
        let outcome = merge(&mut local, Vec::new(), &marked, &marked, true);
        assert_eq!(outcome.revoked.len(), 2);
    }

    #[test]
    fn a_proof_is_bound_to_the_vault_key_the_key_and_the_date() {
        let dek = silentsilo_crypto::generate_dek();
        let other = silentsilo_crypto::generate_dek();
        let marker = |id: &str, at: i64, by: &MasterDek| RevocationMarker {
            version: MARKER_VERSION,
            credential_id: id.into(),
            revoked_at: at,
            proof: Some(proof_for(by, "aa11", 5).to_hex().to_string()),
        };
        assert!(marker("aa11", 5, &dek).proven_by(&dek));
        assert!(!marker("aa11", 5, &other).proven_by(&dek));
        assert!(!marker("bb22", 5, &dek).proven_by(&dek));
        assert!(!marker("aa11", 6, &dek).proven_by(&dek));
        let mut none = marker("aa11", 5, &dek);
        none.proof = None;
        assert!(!none.proven_by(&dek));
        none.proof = Some("not hex".into());
        assert!(!none.proven_by(&dek));
    }

    #[test]
    fn an_earlier_reader_takes_a_marker_with_a_proof() {
        // What 1.11 and before parse: no proof field.
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct Old {
            version: u32,
            credential_id: String,
            revoked_at: i64,
        }
        let dek = silentsilo_crypto::generate_dek();
        let json = serde_json::to_vec(&RevocationMarker {
            version: MARKER_VERSION,
            credential_id: "aa11".into(),
            revoked_at: 5,
            proof: Some(proof_for(&dek, "aa11", 5).to_hex().to_string()),
        })
        .unwrap();
        let old: Old = serde_json::from_slice(&json).unwrap();
        assert_eq!((old.credential_id.as_str(), old.revoked_at), ("aa11", 5));
    }

    #[test]
    fn a_planted_key_does_not_let_markers_take_every_real_one() {
        let mut local = StoredFidoKeys {
            keys: vec![key("aa11"), key("bb22")],
        };
        // A former holder of the content key plants an envelope, then marks
        // both real keys. The planted key arrives unconfirmed and does not
        // count as one that would remain.
        merge(
            &mut local,
            vec![key("ff99")],
            &HashSet::new(),
            &HashSet::new(),
            false,
        );
        assert!(
            local
                .keys
                .iter()
                .find(|k| k.credential_id == "ff99")
                .unwrap()
                .unconfirmed
        );
        let marked = HashSet::from(["aa11".to_string(), "bb22".to_string()]);
        let outcome = merge(&mut local, Vec::new(), &marked, &HashSet::new(), false);
        assert!(outcome.revoked.is_empty());
        assert!(local.keys.iter().all(|k| !k.revoked));

        // Once this device has unlocked with it, it counts like any other.
        local.keys[2].unconfirmed = false;
        let outcome = merge(&mut local, Vec::new(), &marked, &HashSet::new(), false);
        assert_eq!(outcome.revoked.len(), 2);
    }

    #[test]
    fn an_envelope_cannot_arrive_already_confirmed() {
        let mut local = StoredFidoKeys {
            keys: vec![key("aa11")],
        };
        let mut sent = key("bb22");
        sent.unconfirmed = false;
        merge(
            &mut local,
            vec![sent],
            &HashSet::new(),
            &HashSet::new(),
            false,
        );
        assert!(local.keys[1].unconfirmed);
    }

    #[test]
    fn a_policy_does_not_arrive_on_a_silo_nobody_administers() {
        let mut local = StoredFidoKeys {
            keys: vec![key("aa11")],
        };
        let mut injected = key("bb22");
        injected.policy = silentsilo_vault::POLICY_ORG.into();
        merge(
            &mut local,
            vec![injected.clone()],
            &HashSet::new(),
            &HashSet::new(),
            false,
        );
        assert!(!local.is_org_controlled());

        // On a silo that is administered, a second organisation key is real.
        let mut org = key("aa11");
        org.policy = silentsilo_vault::POLICY_ORG.into();
        let mut administered = StoredFidoKeys { keys: vec![org] };
        injected.credential_id = "cc33".into();
        merge(
            &mut administered,
            vec![injected],
            &HashSet::new(),
            &HashSet::new(),
            false,
        );
        assert_eq!(administered.managed().count(), 2);
    }

    #[test]
    fn with_the_password_here_a_removal_elsewhere_takes_the_last_key_too() {
        // Removed on the other computer, where the password let it go, with
        // that computer's proof. This one follows: the password still opens
        // the silo here.
        let mut local = StoredFidoKeys {
            keys: vec![key("aa11")],
        };
        let marked = HashSet::from(["aa11".to_string()]);
        let outcome = merge(&mut local, Vec::new(), &marked, &marked, false);
        assert!(outcome.revoked.is_empty(), "without the password it stays");
        let outcome = merge(&mut local, Vec::new(), &marked, &marked, true);
        assert_eq!(outcome.revoked, vec!["aa11".to_string()]);
        assert!(local.keys[0].revoked);
    }
}
