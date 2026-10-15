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
    /// Seconds. A policy more than [`MAX_POLICY_AHEAD_SECS`] past a
    /// device's clock is not taken in.
    pub changed_at: i64,
    /// A tag over the fields above under a key derived from the vault DEK
    /// ([`PolicyKey`]), hex. From core 1.10; absent before. A release
    /// before it reads the policy and ignores the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
}

pub const POLICY_PATH: &str = "audit/policy.sealed";

/// How far past a device's clock a policy may say it changed, in seconds.
/// The newest policy wins, so one dated far ahead would win over every
/// later choice.
pub const MAX_POLICY_AHEAD_SECS: i64 = 86_400;

/// The key a policy's `auth` is under, derived from the vault DEK. The DEK
/// changes when a key is removed and the silo key rotated, so whoever held
/// the silo before that, and still has the content key, cannot write a
/// policy this tag checks.
pub struct PolicyKey(Zeroizing<[u8; 32]>);

impl PolicyKey {
    pub fn new(dek: &[u8; 32]) -> Self {
        Self(Zeroizing::new(blake3::derive_key(
            "silentsilo audit policy auth v1",
            dek,
        )))
    }
}

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
            auth: None,
        }
    }

    /// The fields a check covers, in a fixed order, `auth` left out.
    pub(crate) fn canonical(&self, context: &[u8]) -> Vec<u8> {
        let mut out = context.to_vec();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(u8::from(self.enabled));
        out.extend_from_slice(&(self.key_id.len() as u32).to_be_bytes());
        out.extend_from_slice(self.key_id.as_bytes());
        match self.retention_days {
            Some(days) => {
                out.push(1);
                out.extend_from_slice(&days.to_be_bytes());
            }
            None => out.push(0),
        }
        out.push(match self.scope {
            Scope::Org => 1,
            Scope::Silo => 2,
        });
        out.extend_from_slice(&self.changed_at.to_be_bytes());
        out
    }

    fn tag(&self, key: &PolicyKey) -> String {
        let body = self.canonical(b"silentsilo audit policy\0");
        hex::encode(blake3::keyed_hash(&key.0, &body).as_bytes())
    }

    /// This policy with its `auth` under `key`, as this build writes it to
    /// storage.
    pub fn tagged(&self, key: &PolicyKey) -> Self {
        Self {
            auth: Some(self.tag(key)),
            ..self.clone()
        }
    }

    /// Whether `auth` checks under `key`: a holder of the current DEK wrote
    /// it.
    pub fn is_authentic(&self, key: &PolicyKey) -> bool {
        self.auth
            .as_deref()
            .is_some_and(|auth| crate::same_text(auth, &self.tag(key)))
    }

    /// Whether `changed_at` is believable at `now`, in seconds.
    pub fn is_believable_at(&self, now: i64) -> bool {
        self.changed_at <= now.saturating_add(MAX_POLICY_AHEAD_SECS)
    }

    /// The `changed_at` of a policy that replaces this one at `now`: after
    /// it, even on a clock that is behind.
    pub fn next_changed_at(&self, now: i64) -> i64 {
        now.max(self.changed_at.saturating_add(1))
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
    fn a_policy_s_tag_checks_under_its_dek_only_and_covers_every_field() {
        let (key, other) = (PolicyKey::new(&[1; 32]), PolicyKey::new(&[2; 32]));
        let policy = AuditPolicy::new(true, &[3; 8], Some(365), Scope::Org, 7);
        assert!(!policy.is_authentic(&key), "untagged");
        let tagged = policy.tagged(&key);
        assert!(tagged.is_authentic(&key));
        assert!(!tagged.is_authentic(&other), "a DEK before a rotation");
        let back = AuditPolicy::open(&tagged.seal(&[9; 32]).unwrap(), &[9; 32]).unwrap();
        assert!(back.is_authentic(&key), "survives the seal");
        let changes: [fn(&mut AuditPolicy); 5] = [
            |p| p.enabled = false,
            |p| p.key_id = hex::encode([4u8; 8]),
            |p| p.retention_days = None,
            |p| p.scope = Scope::Silo,
            |p| p.changed_at += 1,
        ];
        for change in changes {
            let mut moved = tagged.clone();
            change(&mut moved);
            assert!(!moved.is_authentic(&key), "{moved:?}");
        }
    }

    #[test]
    fn a_policy_dated_far_ahead_is_not_believed_and_never_overflows() {
        let now = 1_789_000_000;
        let soon = AuditPolicy::new(true, &[3; 8], None, Scope::Silo, now + 3_600);
        assert!(soon.is_believable_at(now));
        let far = AuditPolicy::new(true, &[3; 8], None, Scope::Silo, i64::MAX);
        assert!(!far.is_believable_at(now));
        assert_eq!(far.next_changed_at(now), i64::MAX);
        assert_eq!(soon.next_changed_at(now), now + 3_601);
    }

    #[test]
    fn the_policy_opens_with_the_content_key_only() {
        let policy = AuditPolicy::new(true, &[3; 8], Some(365), Scope::Silo, 7);
        let sealed = policy.seal(&[9; 32]).unwrap();
        assert_eq!(AuditPolicy::open(&sealed, &[9; 32]).unwrap(), policy);
        assert!(AuditPolicy::open(&sealed, &[8; 32]).is_err());
    }
}

/// Literal values from 1.10: a change to a context string or to how these
/// keys are derived would leave every log written so far unreadable.
#[cfg(test)]
mod known_answers {
    use super::*;

    #[test]
    fn the_private_key_wrap_and_policy_key_are_fixed() {
        assert_eq!(
            hex::encode(wrapping(&[0x01; 32])),
            "68d787af43966ac901908e2431e662af7ed4e519a3a1842b789f39eb3364d4b4"
        );
        assert_eq!(
            hex::encode(*PolicyKey::new(&[0x02; 32]).0),
            "7a54cda29936474824276d91dc6b3f210ed6e64374a4e14d8d4cda1718890262"
        );
    }
}
