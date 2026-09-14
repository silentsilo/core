//! The inbox: how a device that cannot open the silo still adds to it.
//!
//! A phone backing up photos in the background holds no key that opens the
//! silo. It seals each item to the silo's inbox public key and signs it; an
//! unlocked device later checks, opens and records it as an ordinary file.
//! The cryptography is `silentsilo_crypto::inbox`; this module is the
//! storage layout around it.
//!
//! ```text
//! inbox/keys/<key_id>.sealed        inbox secret, sealed under the content KEK
//! inbox/senders/<sender_id>.sealed  who may send, sealed under the content KEK
//! inbox/items/<item_id>.sslo        the content, an ordinary blob
//! inbox/items/<item_id>.env         the signed envelope naming it
//! ```
//!
//! Sealed under the content KEK, not the DEK, because the KEK never rotates:
//! a rotation by a client that has never heard of the inbox (1.0.0 re-seals
//! `ops/`, `snapshots/` and `keys/content.kek` only) must not strand the
//! items waiting here. Nothing under `inbox/` is listed by the orphan sweep,
//! which only looks at `blobs/`.
//!
//! The import is split the way the orphan sweep is: storage work here, the
//! database write by the caller in between, so no connection is held across
//! an await. For each [`ReadyItem`] from [`scan_inbox`]:
//!
//! 1. if the silo already knows `item_id`, skip to 4;
//! 2. [`stage_item`] copies the content into `blobs/`;
//! 3. the caller records the file (`Vfs::record_imported_file`) and pushes
//!    its records as soon as it can, so no other device's sweep sees the
//!    copied blob unreferenced for two passes;
//! 4. [`finish_item`] removes the item from the inbox.
//!
//! Stopping anywhere loses nothing: the item stays until step 4, and steps
//! 1 to 3 are safe to repeat.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use silentsilo_crypto::inbox::{
    EcSecret, ItemHeader, ItemIds, POINT_LEN, SIGNATURE_LEN, open_item, seal_item, verify_signature,
};
use silentsilo_crypto::{ContentKek, ContentKey, seal_with_key, unseal_with_key};
use silentsilo_store::ObjectStore;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{BLOBS_PREFIX, KEYS_PREFIX, SyncError};

pub const INBOX_KEYS_PREFIX: &str = "inbox/keys/";
pub const INBOX_SENDERS_PREFIX: &str = "inbox/senders/";
pub const INBOX_ITEMS_PREFIX: &str = "inbox/items/";

/// The version of every inbox record. A reader refuses any other value and
/// leaves the object where it is, for a build that knows it.
pub const INBOX_VERSION: u32 = 1;

/// Larger envelopes are not read: one is a few hundred bytes, and a
/// listing is all a sender with bad intentions controls.
const MAX_ENVELOPE_BYTES: i64 = 64 * 1024;

/// `inbox/keys/<key_id>.sealed`, once opened.
#[derive(Serialize, Deserialize)]
struct InboxKeyRecord {
    version: u32,
    key_id: Uuid,
    /// The P-256 private key, hex.
    secret_key: String,
    created_at: i64,
}

impl Drop for InboxKeyRecord {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

/// `inbox/senders/<sender_id>.sealed`, once opened: a device allowed to send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderRecord {
    pub version: u32,
    pub sender_id: Uuid,
    /// The sender's ECDSA P-256 public key, uncompressed, hex.
    pub public_key: String,
    /// The device key this sender belongs to. The sender is accepted only
    /// while `keys/<credential_id>.env` is in storage, so removing that key
    /// from the silo also stops its device sending.
    pub credential_id: String,
    pub label: String,
    pub created_at: i64,
}

/// `inbox/items/<item_id>.env`. It does not name its sender: the storage
/// provider reads this file, and which device took which photo is not its
/// business. The importer finds the sender by the signature instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ItemEnvelope {
    version: u32,
    item_id: Uuid,
    blob_id: Uuid,
    key_id: Uuid,
    sent_at: i64,
    blob_size: u64,
    /// Hex of the ephemeral point.
    ephemeral: String,
    /// Hex of `nonce || ciphertext || tag`.
    sealed: String,
    /// Hex of the raw signature over the header and the sealed bytes.
    signature: String,
}

/// What the sealed part of an item holds.
#[derive(Serialize, Deserialize)]
struct ItemContents {
    /// The blob's content key, hex.
    content_key: String,
    name: String,
    mime_type: Option<String>,
    size_bytes: i64,
    /// BLAKE3 of the plaintext, hex, as a file row records it.
    content_hash: String,
    /// When the photo was taken or the contacts were read, if known.
    taken_at: Option<i64>,
    /// Where it goes, one folder name per element, below the root.
    folder: Vec<String>,
    /// What produced it: `photos` or `contacts`.
    source: String,
}

impl Drop for ItemContents {
    fn drop(&mut self) {
        self.content_key.zeroize();
    }
}

fn key_object(key_id: Uuid) -> String {
    format!("{INBOX_KEYS_PREFIX}{key_id}.sealed")
}

fn sender_object(sender_id: Uuid) -> String {
    format!("{INBOX_SENDERS_PREFIX}{sender_id}.sealed")
}

fn item_blob_object(item_id: Uuid) -> String {
    format!("{INBOX_ITEMS_PREFIX}{item_id}.sslo")
}

fn item_envelope_object(item_id: Uuid) -> String {
    format!("{INBOX_ITEMS_PREFIX}{item_id}.env")
}

fn to_json<T: Serialize>(value: &T) -> Result<Vec<u8>, SyncError> {
    serde_json::to_vec(value).map_err(|e| SyncError::Vault(e.to_string()))
}

fn hex_array<const N: usize>(raw: &str, what: &str) -> Result<[u8; N], String> {
    hex::decode(raw)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("{what} is not {N} bytes of hex"))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── Setup, on an unlocked device ────────────────────────────────────

/// The inbox key senders should seal to: an existing one when storage
/// holds one this silo can open, else a new one. Two devices creating one
/// at the same moment make two keys, which is harmless: every item names
/// its key, and each stays readable.
pub async fn ensure_inbox_key(
    client: &dyn ObjectStore,
    kek: &ContentKek,
) -> Result<(Uuid, [u8; POINT_LEN]), SyncError> {
    let mut keys = load_inbox_keys(client, kek).await?;
    keys.sort_by_key(|(id, _)| *id);
    if let Some((id, secret)) = keys.first() {
        return Ok((*id, secret.public_key()));
    }

    let secret = EcSecret::generate();
    let record = InboxKeyRecord {
        version: INBOX_VERSION,
        key_id: Uuid::now_v7(),
        secret_key: hex::encode(secret.as_bytes()),
        created_at: now(),
    };
    let sealed = seal_with_key(&to_json(&record)?, kek.as_bytes())?;
    client.put(&key_object(record.key_id), sealed).await?;
    Ok((record.key_id, secret.public_key()))
}

/// Every inbox key storage holds that opens under `kek`. One that does not
/// is skipped: it cannot be used, and refusing all of them for it would
/// strand the items sealed to the others.
async fn load_inbox_keys(
    client: &dyn ObjectStore,
    kek: &ContentKek,
) -> Result<Vec<(Uuid, EcSecret)>, SyncError> {
    let mut out = Vec::new();
    for entry in client.list(INBOX_KEYS_PREFIX).await? {
        let Ok(bytes) = client.get(&entry.key).await else {
            continue;
        };
        let Ok(plain) = unseal_with_key(&bytes, kek.as_bytes()) else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<InboxKeyRecord>(&plain) else {
            continue;
        };
        if record.version != INBOX_VERSION || entry.key != key_object(record.key_id) {
            continue;
        }
        let Ok(raw) = hex_array::<32>(&record.secret_key, "the inbox key") else {
            continue;
        };
        if let Ok(secret) = EcSecret::from_bytes(raw) {
            out.push((record.key_id, secret));
        }
    }
    Ok(out)
}

/// Allows a device to send. Written while the silo is unlocked, because
/// only a device holding the KEK can seal the record.
pub async fn register_sender(
    client: &dyn ObjectStore,
    kek: &ContentKek,
    record: &SenderRecord,
) -> Result<(), SyncError> {
    let sealed = seal_with_key(&to_json(record)?, kek.as_bytes())?;
    client.put(&sender_object(record.sender_id), sealed).await?;
    Ok(())
}

/// Stops a device sending. Items it already sent stay, and are refused.
pub async fn remove_sender(client: &dyn ObjectStore, sender_id: Uuid) -> Result<(), SyncError> {
    client.delete(&sender_object(sender_id)).await?;
    Ok(())
}

/// A registered sender: its record, its public key, and why it may not send
/// when it may not.
type Sender = (SenderRecord, [u8; POINT_LEN], Option<String>);

/// Every registered sender.
async fn load_senders(
    client: &dyn ObjectStore,
    kek: &ContentKek,
) -> Result<Vec<Sender>, SyncError> {
    let mut out = Vec::new();
    for entry in client.list(INBOX_SENDERS_PREFIX).await? {
        let bytes = client.get(&entry.key).await?;
        let Ok(plain) = unseal_with_key(&bytes, kek.as_bytes()) else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<SenderRecord>(&plain) else {
            continue;
        };
        if record.version != INBOX_VERSION || entry.key != sender_object(record.sender_id) {
            continue;
        }
        let Ok(public) = hex_array::<POINT_LEN>(&record.public_key, "the sender's key") else {
            continue;
        };
        // Revocation removes the device key's envelope, so its absence is
        // the one signal every client, whatever its version, already gives.
        let envelope = format!("{KEYS_PREFIX}{}.env", record.credential_id);
        let removed = record.credential_id.is_empty()
            || record.credential_id.contains('/')
            || client.head(&envelope).await?.is_none();
        let refusal = removed.then(|| {
            format!(
                "sent by {}, whose key was removed from the silo",
                record.label
            )
        });
        out.push((record, public, refusal));
    }
    Ok(out)
}

// ── Sending, on a device that cannot open the silo ──────────────────

/// What a sender knows about the silo, learned while it was unlocked.
#[derive(Debug, Clone)]
pub struct SenderIdentity {
    pub vault_id: Uuid,
    pub sender_id: Uuid,
    pub key_id: Uuid,
    pub inbox_public: [u8; POINT_LEN],
}

/// One item to send.
#[derive(Debug, Clone)]
pub struct OutgoingItem<'a> {
    /// Chosen by the caller and kept until the import is seen, so a retry
    /// after a failure sends the same item rather than a second one.
    pub item_id: Uuid,
    pub source: &'a Path,
    pub name: String,
    pub mime_type: Option<String>,
    pub taken_at: Option<i64>,
    pub folder: Vec<String>,
    pub source_kind: String,
}

/// Signs an item's header and sealed bytes: a raw P-256 signature, or why
/// the device's key refused.
pub type ItemSigner<'a> = dyn Fn(&[u8]) -> Result<[u8; SIGNATURE_LEN], String> + Sync + 'a;

/// Encrypts and uploads one item: the content first, the envelope last, so
/// an importer never sees an envelope whose content is not there yet.
pub async fn send_item(
    client: &dyn ObjectStore,
    identity: &SenderIdentity,
    item: &OutgoingItem<'_>,
    sign: &ItemSigner<'_>,
) -> Result<(), SyncError> {
    let content_key = silentsilo_crypto::generate_content_key();
    let blob_id = Uuid::new_v4();
    let staged = tempfile::NamedTempFile::new().map_err(|e| SyncError::Vault(e.to_string()))?;
    let encrypted = silentsilo_crypto::encrypt_file(
        item.source,
        staged.path(),
        &content_key,
        item.item_id,
        blob_id,
    )?;
    client
        .put_from_file(&item_blob_object(item.item_id), staged.path())
        .await?;

    let contents = ItemContents {
        content_key: hex::encode(content_key.as_bytes()),
        name: item.name.clone(),
        mime_type: item.mime_type.clone(),
        size_bytes: encrypted.plain_bytes as i64,
        content_hash: hex::encode(encrypted.header.content_hash),
        taken_at: item.taken_at,
        folder: item.folder.clone(),
        source: item.source_kind.clone(),
    };
    let ids = ItemIds {
        item_id: item.item_id,
        blob_id,
        key_id: identity.key_id,
        sender_id: identity.sender_id,
        sent_at: now(),
        blob_size: encrypted.size_bytes,
    };
    let plain = zeroize::Zeroizing::new(to_json(&contents)?);
    let (header, sealed) = seal_item(&identity.inbox_public, identity.vault_id, ids, &plain)?;
    let signature = sign(&header.signed_message(&sealed)).map_err(SyncError::Crypto)?;

    let envelope = ItemEnvelope {
        version: INBOX_VERSION,
        item_id: header.item_id,
        blob_id: header.blob_id,
        key_id: header.key_id,
        sent_at: header.sent_at,
        blob_size: header.blob_size,
        ephemeral: hex::encode(header.ephemeral),
        sealed: hex::encode(&sealed),
        signature: hex::encode(signature),
    };
    client
        .put(&item_envelope_object(item.item_id), to_json(&envelope)?)
        .await?;
    Ok(())
}

// ── Importing, on an unlocked device ────────────────────────────────

/// An item that passed every check and can be recorded.
pub struct ReadyItem {
    pub item_id: Uuid,
    pub blob_id: Uuid,
    pub sender_id: Uuid,
    pub sender_label: String,
    pub name: String,
    pub mime_type: Option<String>,
    pub size_bytes: i64,
    pub content_hash: String,
    pub taken_at: Option<i64>,
    pub folder: Vec<String>,
    pub source: String,
    blob_size: u64,
    content_key: ContentKey,
}

impl ReadyItem {
    /// The content key wrapped under `kek`, for the file's record.
    pub fn blob_key(&self, kek: &ContentKek) -> Result<String, SyncError> {
        Ok(silentsilo_crypto::wrap_content_key(&self.content_key, kek)?)
    }
}

/// An item left in the inbox, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedItem {
    pub object: String,
    pub reason: String,
}

#[derive(Default)]
pub struct InboxScan {
    pub ready: Vec<ReadyItem>,
    pub refused: Vec<RefusedItem>,
}

/// Reads every envelope in the inbox and checks it: version, a registered
/// sender whose signature it carries, that sender's device key still in
/// storage, and that the silo's inbox key opens it. Nothing is written or removed; a refused item stays
/// where it is.
pub async fn scan_inbox(
    client: &dyn ObjectStore,
    vault_id: Uuid,
    kek: &ContentKek,
) -> Result<InboxScan, SyncError> {
    let mut scan = InboxScan::default();
    let envelopes: Vec<_> = client
        .list(INBOX_ITEMS_PREFIX)
        .await?
        .into_iter()
        .filter(|entry| entry.key.ends_with(".env"))
        .collect();
    if envelopes.is_empty() {
        return Ok(scan);
    }

    let inbox_keys: HashMap<Uuid, EcSecret> =
        load_inbox_keys(client, kek).await?.into_iter().collect();
    let senders = load_senders(client, kek).await?;

    for entry in envelopes {
        let refuse = |reason: String| RefusedItem {
            object: entry.key.clone(),
            reason,
        };
        if entry.size > MAX_ENVELOPE_BYTES {
            scan.refused
                .push(refuse("the envelope is too large".into()));
            continue;
        }
        let bytes = client.get(&entry.key).await?;
        let envelope = match serde_json::from_slice::<ItemEnvelope>(&bytes) {
            Ok(envelope) => envelope,
            Err(e) => {
                scan.refused
                    .push(refuse(format!("the envelope cannot be read: {e}")));
                continue;
            }
        };
        if envelope.version != INBOX_VERSION {
            scan.refused.push(refuse(format!(
                "made by a newer version (inbox format {}); update to import it",
                envelope.version
            )));
            continue;
        }
        if entry.key != item_envelope_object(envelope.item_id) {
            scan.refused
                .push(refuse("the envelope names a different item".into()));
            continue;
        }

        match open_envelope(&envelope, &senders, vault_id, &inbox_keys) {
            Ok(item) => scan.ready.push(item),
            Err(reason) => scan.refused.push(refuse(reason)),
        }
    }
    Ok(scan)
}

fn open_envelope(
    envelope: &ItemEnvelope,
    senders: &[Sender],
    vault_id: Uuid,
    inbox_keys: &HashMap<Uuid, EcSecret>,
) -> Result<ReadyItem, String> {
    let ephemeral = hex_array(&envelope.ephemeral, "the ephemeral key")?;
    let sealed = hex::decode(&envelope.sealed).map_err(|_| "the item is not hex".to_string())?;
    let signature: [u8; SIGNATURE_LEN] = hex_array(&envelope.signature, "the signature")?;
    let header_for = |sender_id: Uuid| ItemHeader {
        item_id: envelope.item_id,
        blob_id: envelope.blob_id,
        key_id: envelope.key_id,
        sender_id,
        sent_at: envelope.sent_at,
        blob_size: envelope.blob_size,
        ephemeral,
    };

    // The sender is whoever's key the signature verifies under, with that
    // sender's id in the signed header. A silo has a handful of senders.
    let ((sender, _, refusal), header) = senders
        .iter()
        .find_map(|candidate| {
            let header = header_for(candidate.0.sender_id);
            verify_signature(&candidate.1, &header.signed_message(&sealed), &signature)
                .ok()
                .map(|()| (candidate, header))
        })
        .ok_or_else(|| "not signed by a device allowed to send".to_string())?;
    if let Some(reason) = refusal {
        return Err(reason.clone());
    }

    let secret = inbox_keys
        .get(&envelope.key_id)
        .ok_or_else(|| "sealed to an inbox key this silo does not have".to_string())?;
    let plain = open_item(secret, vault_id, &header, &sealed)
        .map_err(|_| "the silo's inbox key does not open it".to_string())?;
    let contents: ItemContents =
        serde_json::from_slice(&plain).map_err(|e| format!("the item cannot be read: {e}"))?;
    let content_key = ContentKey::from_bytes(hex_array(&contents.content_key, "the content key")?);

    Ok(ReadyItem {
        item_id: envelope.item_id,
        blob_id: envelope.blob_id,
        sender_id: sender.sender_id,
        sender_label: sender.label.clone(),
        name: contents.name.clone(),
        mime_type: contents.mime_type.clone(),
        size_bytes: contents.size_bytes,
        content_hash: contents.content_hash.clone(),
        taken_at: contents.taken_at,
        folder: contents.folder.clone(),
        source: contents.source.clone(),
        blob_size: envelope.blob_size,
        content_key,
    })
}

/// Copies the item's content to where the silo keeps content. Refuses when
/// the object in the inbox is not the size the signed envelope names.
pub async fn stage_item(client: &dyn ObjectStore, item: &ReadyItem) -> Result<(), SyncError> {
    let source = item_blob_object(item.item_id);
    match client.head(&source).await? {
        Some(size) if size >= 0 && size as u64 == item.blob_size => {}
        Some(size) => {
            return Err(SyncError::Storage(format!(
                "{source} is {size} bytes, the envelope says {}",
                item.blob_size
            )));
        }
        None => return Err(SyncError::Storage(format!("{source} is not there"))),
    }
    let dest = format!("{BLOBS_PREFIX}{}.sslo", item.blob_id);
    client.copy(&source, &dest).await?;
    Ok(())
}

/// Removes an item the silo has recorded. The content goes first: an
/// envelope left behind is skipped on the next pass because its id is
/// known, while content left without its envelope would never be found.
pub async fn finish_item(client: &dyn ObjectStore, item_id: Uuid) -> Result<(), SyncError> {
    client.delete(&item_blob_object(item_id)).await?;
    client.delete(&item_envelope_object(item_id)).await?;
    Ok(())
}
