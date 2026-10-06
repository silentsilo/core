//! The activity log in storage: segments sent, the key and policy read.
//!
//! A segment is written once. One a copy already holds is left as it is,
//! whatever this device would write: the log is only ever added to.

use std::collections::HashSet;

use silentsilo_audit::{AuditKey, AuditPolicy, POLICY_PATH, Segment, audit_key_path};
use silentsilo_crypto::ContentKek;
use silentsilo_store::ObjectStore;

use crate::{SyncError, fetch_small};

/// Puts every segment `client` does not hold. Returns the sequence numbers
/// it holds afterwards, sent now or already there.
pub async fn push_audit_segments(
    client: &dyn ObjectStore,
    segments: &[Segment],
) -> Result<HashSet<u64>, SyncError> {
    let mut held = HashSet::new();
    for segment in segments {
        let key = segment.key();
        if client.head(&key).await?.is_none() {
            client.put(&key, segment.to_bytes()).await?;
        }
        held.insert(segment.seq);
    }
    Ok(held)
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

        let held = push_audit_segments(&client, &[first.clone(), segment(device, 1, &keys)])
            .await
            .unwrap();
        assert_eq!(held, HashSet::from([0, 1]));
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
