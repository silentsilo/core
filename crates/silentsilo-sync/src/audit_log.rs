//! The activity log in storage: segments sent, the key and policy read.
//!
//! A segment is written once. One a copy already holds is left as it is,
//! whatever this device would write: the log is only ever added to.

use std::collections::HashSet;

use silentsilo_audit::{
    AUDIT_PREFIX, AuditKey, AuditPolicy, BY_SILO, KeyId, POLICY_PATH, Segment, audit_key_path,
    key_id,
};
use silentsilo_crypto::ContentKek;
use silentsilo_store::ObjectStore;
use zeroize::Zeroizing;

use crate::{SyncError, fetch_small, too_large};

/// What a push left: the segments the copy holds as this device wrote
/// them, and those it holds under the same number with other bytes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pushed {
    pub held: HashSet<u64>,
    pub differ: Vec<u64>,
}

/// Puts every segment `client` does not hold. One already there counts as
/// held only when its bytes are this device's: a spool put back from an old
/// backup numbers new events as old ones, and those must not be dropped as
/// delivered.
pub async fn push_audit_segments(
    client: &dyn ObjectStore,
    segments: &[Segment],
) -> Result<Pushed, SyncError> {
    let mut pushed = Pushed::default();
    for segment in segments {
        let key = segment.key();
        let bytes = segment.to_bytes();
        match client.head(&key).await? {
            None => client.put(&key, bytes).await?,
            Some(size) if size == bytes.len() as i64 && client.get(&key).await? == bytes => {}
            Some(_) => {
                pushed.differ.push(segment.seq);
                continue;
            }
        }
        pushed.held.insert(segment.seq);
    }
    Ok(pushed)
}

/// The log's policy, when the silo has one. One that does not open under
/// this silo's content key is an error rather than "no log": storage
/// should not be able to switch a log off by writing noise there.
pub async fn read_audit_policy(
    client: &dyn ObjectStore,
    kek: &ContentKek,
) -> Result<Option<AuditPolicy>, SyncError> {
    let Some(sealed) = fetch_small(client, POLICY_PATH).await? else {
        return Ok(None);
    };
    AuditPolicy::open(&sealed, kek.as_bytes())
        .map(Some)
        .map_err(|e| SyncError::Vault(e.to_string()))
}

pub async fn write_audit_policy(
    client: &dyn ObjectStore,
    kek: &ContentKek,
    policy: &AuditPolicy,
) -> Result<(), SyncError> {
    let sealed = policy
        .seal(kek.as_bytes())
        .map_err(|e| SyncError::Vault(e.to_string()))?;
    client.put(POLICY_PATH, sealed).await?;
    Ok(())
}

/// The log key `key_id` (hex) names, when storage holds it.
pub async fn read_audit_key(
    client: &dyn ObjectStore,
    key_id: &str,
) -> Result<Option<AuditKey>, SyncError> {
    let id: [u8; 8] = hex::decode(key_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| SyncError::Vault("the activity log names a malformed key".into()))?;
    let Some(bytes) = fetch_small(client, &audit_key_path(&id)).await? else {
        return Ok(None);
    };
    AuditKey::from_json(&bytes)
        .map(Some)
        .map_err(|e| SyncError::Vault(e.to_string()))
}

/// Every personal log key `client` holds that the content key opens, by
/// id: the one in use, and any a device started before it heard of that
/// one, whose records name it still.
pub async fn read_silo_keys(
    client: &dyn ObjectStore,
    kek: &ContentKek,
) -> Result<Vec<(KeyId, Zeroizing<Vec<u8>>)>, SyncError> {
    let mut out = Vec::new();
    for object in client.list(&format!("{AUDIT_PREFIX}keys/")).await? {
        if !object.key.ends_with(".json") || too_large(object.size) {
            continue;
        }
        let Some(bytes) = fetch_small(client, &object.key).await? else {
            continue;
        };
        let Ok(key) = AuditKey::from_json(&bytes) else {
            continue;
        };
        if let (Ok(public), Ok(private)) = (key.public(), key.unwrap_with(BY_SILO, kek.as_bytes()))
        {
            out.push((key_id(&public), private));
        }
    }
    Ok(out)
}

pub async fn write_audit_key(client: &dyn ObjectStore, key: &AuditKey) -> Result<(), SyncError> {
    let id: [u8; 8] = hex::decode(&key.key_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| SyncError::Vault("malformed log key id".into()))?;
    let bytes = key.to_json().map_err(|e| SyncError::Vault(e.to_string()))?;
    client.put(&audit_key_path(&id), bytes).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use silentsilo_audit::{Event, KeyPair, Scope, seal_event};
    use silentsilo_store::FolderStore;
    use uuid::Uuid;

    fn segment(device: Uuid, seq: u64, keys: &KeyPair) -> Segment {
        Segment {
            device,
            seq,
            prev: [0; 32],
            closed_at: 1,
            records: vec![seal_event(&keys.public, device, &Event::new(1, 1)).unwrap()],
        }
    }

    #[tokio::test]
    async fn a_segment_a_copy_holds_is_never_written_over() {
        let dir = tempfile::tempdir().unwrap();
        let client = FolderStore::new(dir.path().to_path_buf());
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let first = segment(device, 0, &keys);
        client
            .put(&first.key(), b"already there".to_vec())
            .await
            .unwrap();

        let second = segment(device, 1, &keys);
        let pushed = push_audit_segments(&client, &[first.clone(), second.clone()])
            .await
            .unwrap();
        assert_eq!(pushed.held, HashSet::from([1]));
        assert_eq!(pushed.differ, vec![0], "not taken as delivered");
        // The same bytes already there are held.
        let again = push_audit_segments(&client, &[second]).await.unwrap();
        assert_eq!(again.held, HashSet::from([1]));
        assert!(again.differ.is_empty());
        assert_eq!(client.get(&first.key()).await.unwrap(), b"already there");
        assert!(
            client
                .head(&segment(device, 1, &keys).key())
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn the_key_and_policy_read_back_and_noise_is_not_no_log() {
        let dir = tempfile::tempdir().unwrap();
        let client = FolderStore::new(dir.path().to_path_buf());
        let kek = silentsilo_crypto::generate_content_kek();
        assert!(read_audit_policy(&client, &kek).await.unwrap().is_none());

        let keys = KeyPair::generate();
        let key = AuditKey::new(&keys, Scope::Silo, 1);
        let policy = AuditPolicy::new(true, &keys.id(), None, Scope::Silo, 1);
        write_audit_key(&client, &key).await.unwrap();
        write_audit_policy(&client, &kek, &policy).await.unwrap();
        assert_eq!(
            read_audit_policy(&client, &kek).await.unwrap(),
            Some(policy)
        );
        assert_eq!(
            read_audit_key(&client, &key.key_id).await.unwrap(),
            Some(key)
        );

        client.put(POLICY_PATH, vec![0; 64]).await.unwrap();
        assert!(read_audit_policy(&client, &kek).await.is_err());
    }
}
