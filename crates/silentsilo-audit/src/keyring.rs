//! The log's key, as storage holds it, and the policy it is kept under.
//!
//! `audit/keys/<key id>.json` is public on purpose: every device needs the
//! public half to write. The private half is in it only wrapped, once per
//! way in: under each organisation key's wrap key on an administered silo
//! (devices write and cannot read), under the silo's content key on a
//! personal one (whoever opens the silo reads its log).
//!
//! The key is random rather than derived from an organisation key, so
//! losing or retiring that key leaves the logs readable through the others.

use serde::{Deserialize, Serialize};
use silentsilo_crypto::{seal_with_key, unseal_with_key};
use zeroize::Zeroizing;

use crate::record::{KeyId, KeyPair, SUITE, key_id};
use crate::{AUDIT_PREFIX, AuditError};

const KEY_VERSION: u32 = 1;
const POLICY_VERSION: u32 = 1;

/// The `by` of a private key wrapped under the silo's content key.
pub const BY_SILO: &str = "silo";

/// Who the log is kept for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// An organisation's silo: on for good, read with an organisation key.
    Org,
    /// A person's own silo: on by choice, read by whoever opens it.
    Silo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedPrivate {
    /// [`BY_SILO`], or the credential id of the organisation key whose wrap
    /// key it is under.
    pub by: String,
    pub sealed: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditKey {
    pub version: u32,
    pub key_id: String,
    /// The HPKE suite records sealed to this key use.
    pub suite: [u16; 3],
    pub public_key: String,
    pub scope: Scope,
    pub created_at: i64,
    pub wrapped: Vec<WrappedPrivate>,
}

/// A wrap key for this one purpose, so the key that unwraps a DEK envelope
/// is never used as is for anything else.
fn wrapping(wrap_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("silentsilo audit private key v1", wrap_key)
}

pub fn audit_key_path(id: &KeyId) -> String {
    format!("{AUDIT_PREFIX}keys/{}.json", hex::encode(id))
}

impl AuditKey {
    pub fn new(keys: &KeyPair, scope: Scope, created_at: i64) -> Self {
        Self {
            version: KEY_VERSION,
            key_id: hex::encode(keys.id()),
            suite: SUITE,
            public_key: hex::encode(&keys.public),
            scope,
            created_at,
            wrapped: Vec::new(),
        }
    }

    pub fn public(&self) -> Result<Vec<u8>, AuditError> {
        let public = hex::decode(&self.public_key).map_err(|_| AuditError::BadKey)?;
        if hex::encode(key_id(&public)) != self.key_id {
            return Err(AuditError::BadKey);
        }
        Ok(public)
    }

    /// Adds a way to the private key: under `wrap_key`, for `by`. A second
    /// wrapping for the same `by` replaces the first.
    pub fn wrap_for(
        &mut self,
        by: &str,
        private: &[u8],
        wrap_key: &[u8; 32],
    ) -> Result<(), AuditError> {
        let sealed = seal_with_key(private, &wrapping(wrap_key)).map_err(|_| AuditError::Crypto)?;
        self.wrapped.retain(|w| w.by != by);
        self.wrapped.push(WrappedPrivate {
            by: by.to_string(),
            sealed: hex::encode(sealed),
        });
        Ok(())
    }

    pub fn unwrap_with(
        &self,
        by: &str,
        wrap_key: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, AuditError> {
        let wrapped = self
            .wrapped
            .iter()
            .find(|w| w.by == by)
            .ok_or(AuditError::BadKey)?;
        let sealed = hex::decode(&wrapped.sealed).map_err(|_| AuditError::BadKey)?;
        let private = unseal_with_key(&sealed, &wrapping(wrap_key))
            .map(Zeroizing::new)
            .map_err(|_| AuditError::BadKey)?;
        // Sealing does not bind which key this is: a wrapping copied from
        // another log key's entry opens too, and must not be taken as this
        // one's.
        if crate::record::public_of(&private) != Some(self.public()?) {
            return Err(AuditError::BadKey);
        }
        Ok(private)
    }

    /// This key with every way in `other` holds that this one lacks. Two
    /// devices may each add a way at once; whichever copy is read, the
    /// union is kept. A way is never taken away here.
    pub fn merged(&self, other: &AuditKey) -> AuditKey {
        let mut out = self.clone();
        if other.key_id == self.key_id {
            for wrapped in &other.wrapped {
                if !out.wrapped.iter().any(|w| w.by == wrapped.by) {
                    out.wrapped.push(wrapped.clone());
                }
            }
        }
        // One order on every device, or two copies that hold the same ways
        // would each look different and be written again at every pass.
        out.wrapped.sort_by(|x, y| x.by.cmp(&y.by));
        out
    }

    pub fn to_json(&self) -> Result<Vec<u8>, AuditError> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, AuditError> {
        let key: Self = serde_json::from_slice(bytes)?;
        if key.version > KEY_VERSION {
            return Err(AuditError::Newer("log key"));
        }
        // Sealing to a key meant for another suite would write records
        // nobody can open.
        if key.suite != SUITE {
            return Err(AuditError::Newer("log key suite"));
        }
        key.public()?;
        Ok(key)
    }
}

/// Whether a silo keeps a log, and for how long. Sealed under the content
/// key, at [`POLICY_PATH`]. On an organisation's silo the log is on whatever
/// this says; only the retention is read from it, and only the holder of an
/// organisation key ever deletes a segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPolicy {
    pub version: u32,
    pub enabled: bool,
    /// The key events are sealed to, by id (`audit/keys/<id>.json`). A
    /// device pins the first it is told and does not follow a change to
    /// another in silence.
    pub key_id: String,
    /// Segments older than this many days may go; `None` keeps them.
    pub retention_days: Option<u32>,
    pub scope: Scope,
    pub changed_at: i64,
}

pub const POLICY_PATH: &str = "audit/policy.sealed";

impl AuditPolicy {
    pub fn new(
        enabled: bool,
        key_id: &KeyId,
        retention_days: Option<u32>,
        scope: Scope,
        changed_at: i64,
    ) -> Self {
        Self {
            version: POLICY_VERSION,
            enabled,
            key_id: hex::encode(key_id),
            retention_days,
            scope,
            changed_at,
        }
    }

    pub fn seal(&self, content_key: &[u8; 32]) -> Result<Vec<u8>, AuditError> {
        seal_with_key(&serde_json::to_vec(self)?, content_key).map_err(|_| AuditError::Crypto)
    }

    pub fn open(sealed: &[u8], content_key: &[u8; 32]) -> Result<Self, AuditError> {
        let plain = unseal_with_key(sealed, content_key).map_err(|_| AuditError::Crypto)?;
        let policy: Self = serde_json::from_slice(&plain)?;
        if policy.version > POLICY_VERSION {
            return Err(AuditError::Newer("log policy"));
        }
        Ok(policy)
    }
}

#[cfg(test)]
mod merge_tests {
    use super::*;

    #[test]
    fn ways_in_added_on_two_devices_are_both_kept() {
        let keys = KeyPair::generate();
        let mut a = AuditKey::new(&keys, Scope::Org, 1);
        let mut b = a.clone();
        a.wrap_for("key-a", &keys.private, &[1; 32]).unwrap();
        b.wrap_for("key-b", &keys.private, &[2; 32]).unwrap();
        let both = a.merged(&b);
        assert!(both.unwrap_with("key-a", &[1; 32]).is_ok());
        assert!(both.unwrap_with("key-b", &[2; 32]).is_ok());
        assert_eq!(both, b.merged(&a).merged(&both).merged(&a));
        let other = AuditKey::new(&KeyPair::generate(), Scope::Org, 1);
        assert_eq!(a.merged(&other), a, "another key's ways are not taken");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Event, open_event, seal_event};
    use uuid::Uuid;

    #[test]
    fn an_organisation_key_reads_what_devices_wrote() {
        let keys = KeyPair::generate();
        let mut key = AuditKey::new(&keys, Scope::Org, 1);
        let (org_a, org_b) = ([1u8; 32], [2u8; 32]);
        key.wrap_for("aa11", &keys.private, &org_a).unwrap();
        key.wrap_for("bb22", &keys.private, &org_b).unwrap();
        let stored = AuditKey::from_json(&key.to_json().unwrap()).unwrap();

        // A device has only what storage holds: the public key.
        let device = Uuid::new_v4();
        let record = seal_event(&stored.public().unwrap(), device, &Event::new(11, 5)).unwrap();

        // Either organisation key opens it; one retired, the other still does.
        let private = stored.unwrap_with("bb22", &org_b).unwrap();
        assert_eq!(open_event(&private, device, &record).unwrap().c, 11);
        assert!(stored.unwrap_with("aa11", &org_b).is_err());
        assert!(stored.unwrap_with("cc33", &org_a).is_err());
    }

    #[test]
    fn a_planted_public_key_with_the_wrong_id_is_refused() {
        let keys = KeyPair::generate();
        let mut key = AuditKey::new(&keys, Scope::Silo, 1);
        key.public_key = hex::encode(KeyPair::generate().public);
        assert!(AuditKey::from_json(&key.to_json().unwrap()).is_err());
    }

    #[test]
    fn a_private_key_moved_under_another_log_keys_entry_is_refused() {
        let (first, second) = (KeyPair::generate(), KeyPair::generate());
        let mut a = AuditKey::new(&first, Scope::Silo, 1);
        a.wrap_for(BY_SILO, &first.private, &[9; 32]).unwrap();
        let mut b = AuditKey::new(&second, Scope::Silo, 1);
        b.wrapped = a.wrapped.clone();
        let b = AuditKey::from_json(&b.to_json().unwrap()).unwrap();
        assert!(matches!(
            b.unwrap_with(BY_SILO, &[9; 32]),
            Err(AuditError::BadKey)
        ));
        assert!(a.unwrap_with(BY_SILO, &[9; 32]).is_ok());
    }

    #[test]
    fn a_sealed_object_of_another_kind_is_not_a_policy() {
        // A revocation marker, sealed under the same content key.
        let marker = br#"{"version":1,"credential_id":"aa11","revoked_at":5}"#;
        let sealed = seal_with_key(marker, &[9; 32]).unwrap();
        assert!(AuditPolicy::open(&sealed, &[9; 32]).is_err());
        // A private key wrapped for the silo is under a derived key.
        let keys = KeyPair::generate();
        let mut key = AuditKey::new(&keys, Scope::Silo, 1);
        key.wrap_for(BY_SILO, &keys.private, &[9; 32]).unwrap();
        let wrapped = hex::decode(&key.wrapped[0].sealed).unwrap();
        assert!(AuditPolicy::open(&wrapped, &[9; 32]).is_err());
    }

    #[test]
    fn the_policy_opens_with_the_content_key_only() {
        let policy = AuditPolicy::new(true, &[3; 8], Some(365), Scope::Silo, 7);
        let sealed = policy.seal(&[9; 32]).unwrap();
        assert_eq!(AuditPolicy::open(&sealed, &[9; 32]).unwrap(), policy);
        assert!(AuditPolicy::open(&sealed, &[8; 32]).is_err());
    }
}
