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
use silentsilo_crypto::{ContentKek, seal_with_key, unseal_with_key};
use silentsilo_store::ObjectStore;
use silentsilo_vault::{StoredFidoCredential, StoredFidoKeys};

use crate::{KEYS_PREFIX, SyncError};

pub const REVOKED_PREFIX: &str = "keys/revoked/";

const MARKER_VERSION: u32 = 1;

/// `keys/revoked/<credential_id>.sealed`, once opened.
#[derive(Serialize, Deserialize)]
struct RevocationMarker {
    version: u32,
    credential_id: String,
    revoked_at: i64,
}

fn marker_key(credential_id: &str) -> String {
    format!("{REVOKED_PREFIX}{credential_id}.sealed")
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

/// Reads the envelopes and revocation markers `client` holds, writes a
/// marker for every revocation of this device's that lacks one, and folds
/// the rest into `local`. The caller saves `local` when [`KeyReconcile::changed`].
pub async fn reconcile_key_envelopes(
    client: &dyn ObjectStore,
    kek: &ContentKek,
    local: &mut StoredFidoKeys,
    now: i64,
) -> Result<KeyReconcile, SyncError> {
    let mut published = Vec::new();
    let mut marked = HashSet::new();
    for entry in client.list(KEYS_PREFIX).await? {
        if let Some(name) = entry.key.strip_prefix(REVOKED_PREFIX) {
            let Some(id) = name.strip_suffix(".sealed") else {
                continue;
            };
            let Ok(bytes) = client.get(&entry.key).await else {
                continue;
            };
            let opened = unseal_with_key(&bytes, kek.as_bytes())
                .ok()
                .and_then(|plain| serde_json::from_slice::<RevocationMarker>(&plain).ok())
                .filter(|m| m.version == MARKER_VERSION && m.credential_id == id);
            if let Some(marker) = opened {
                marked.insert(marker.credential_id);
            }
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

    // This device's own revocations, published before anything else so
    // they reach storage even if the rest of the pass fails.
    for key in local.keys.iter().filter(|k| k.revoked) {
        if marked.contains(&key.credential_id) {
            continue;
        }
        let marker = RevocationMarker {
            version: MARKER_VERSION,
            credential_id: key.credential_id.clone(),
            revoked_at: now,
        };
        let json = serde_json::to_vec(&marker).map_err(|e| SyncError::Vault(e.to_string()))?;
        let sealed = seal_with_key(&json, kek.as_bytes())?;
        client.put(&marker_key(&key.credential_id), sealed).await?;
        marked.insert(key.credential_id.clone());
    }

    let mut outcome = merge(local, published, &marked);
    outcome.marked = marked;
    Ok(outcome)
}

/// The decision, apart from storage.
fn merge(
    local: &mut StoredFidoKeys,
    published: Vec<StoredFidoCredential>,
    marked: &HashSet<String>,
) -> KeyReconcile {
    let mut outcome = KeyReconcile::default();

    // An organisation's key is retired only with its proof, which a device
    // following someone else's revocation does not hold; the write guard
    // would refuse it, so it is left for that device's own action.
    for key in local.keys.iter_mut() {
        if !key.revoked && !key.managed() && marked.contains(&key.credential_id) {
            key.revoked = true;
            outcome.revoked.push(key.credential_id.clone());
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
        // An envelope is not authenticated. A policy arriving on a silo
        // nobody administers would let anyone with write access to storage
        // lock its owner out of changing the recovery code.
        if !org_controlled {
            key.policy.clear();
        }
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
        let outcome = merge(&mut local, Vec::new(), &marked);
        assert_eq!(outcome.revoked, vec!["aa11".to_string()]);
        assert!(local.keys[0].revoked);
        assert!(!local.keys[1].revoked, "the organisation key is left alone");
    }

    #[test]
    fn a_policy_does_not_arrive_on_a_silo_nobody_administers() {
        let mut local = StoredFidoKeys {
            keys: vec![key("aa11")],
        };
        let mut injected = key("bb22");
        injected.policy = silentsilo_vault::POLICY_ORG.into();
        merge(&mut local, vec![injected.clone()], &HashSet::new());
        assert!(!local.is_org_controlled());

        // On a silo that is administered, a second organisation key is real.
        let mut org = key("aa11");
        org.policy = silentsilo_vault::POLICY_ORG.into();
        let mut administered = StoredFidoKeys { keys: vec![org] };
        injected.credential_id = "cc33".into();
        merge(&mut administered, vec![injected], &HashSet::new());
        assert_eq!(administered.managed().count(), 2);
    }
}
