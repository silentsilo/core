//! Moves the operation log between a vault and the user's bucket.
//!
//! The model lives in `silentsilo-vfs::oplog`; this crate is only transport.
//! Every operation becomes one immutable object under `ops/`, so a push is
//! always a create and never an overwrite — which is what lets this work on
//! providers with no conditional-write support, and why two devices pushing
//! at the same moment cannot lose each other's work.
//!
//! Records are sealed with the vault DEK before they leave the machine: an
//! operation carries file and folder names, so the storage provider must see
//! ciphertext, exactly as it does for blob content.

use silentsilo_core::CoreError;
use silentsilo_crypto::{ContentKek, MasterDek, seal, unseal};
use silentsilo_store::{ObjectStore, StoreError};
use silentsilo_vfs::{
    CompactionPolicy, OpRecord, ReplayReport, Snapshot, capture_at, choose_horizon,
    highest_applied_lamport, replay,
};

use rusqlite::Connection;
use silentsilo_vault::{
    RecoveryEnvelope, StoredFidoCredential, StoredFidoKeys, list_undelivered_blob_ids,
    record_blob_delivered, record_blob_present, remove_blob_from_cache,
};
use std::path::Path;
use uuid::Uuid;

mod error;
pub mod inbox;
mod key_sync;
pub use error::SyncError;
pub use key_sync::{
    KeyReconcile, RECOVERY_MARKER_ID, REVOKED_PREFIX, is_key_revoked, mark_recovery_disabled,
    plausible_credential_id, reconcile_key_envelopes, revoked_at,
};

/// Where operation objects live inside the vault prefix.
pub const OPS_PREFIX: &str = "ops/";

/// Key for one record. `.op` keeps the listing readable and leaves room for
/// other object kinds under the same prefix later.
fn op_key(record: &OpRecord) -> String {
    format!("{OPS_PREFIX}{}.op", record.object_key())
}

/// Reads the Lamport counter back out of an object key, so records below a
/// snapshot horizon can be skipped without downloading and decrypting them.
fn lamport_from_key(key: &str) -> Option<u64> {
    key.strip_prefix(OPS_PREFIX)?
        .split('-')
        .next()?
        .parse()
        .ok()
}

/// Reads the op id back out of an object key: the last 36 characters before
/// the extension, since both uuids in the key carry hyphens of their own.
fn op_id_from_key(key: &str) -> Option<Uuid> {
    let rest = key.strip_prefix(OPS_PREFIX)?.strip_suffix(".op")?;
    let tail = rest.get(rest.len().checked_sub(36)?..)?;
    Uuid::parse_str(tail).ok()
}

/// What a sync pass did.
#[derive(Debug, Default, Clone)]
pub struct SyncOutcome {
    pub pushed: usize,
    pub fetched: usize,
    pub replay: ReplayReport,
    /// Readable records held back because an unreadable object sits below
    /// them in the total order. Retried on the next pass.
    pub held_back: usize,
    pub unreadable: Vec<UnreadableOp>,
}

/// Uploads records that aren't in the bucket yet.
///
/// Push before pull, always: a record that exists only locally is the one
/// thing here with no other copy, so it should reach the bucket before
/// anything else can go wrong.
pub async fn push_ops(
    client: &dyn ObjectStore,
    dek: &MasterDek,
    records: &[OpRecord],
) -> Result<usize, SyncError> {
    push_ops_reporting(client, dek, records, &mut |_, _| {}).await
}

/// [`push_ops`], saying how far it got before each record.
pub async fn push_ops_reporting(
    client: &dyn ObjectStore,
    dek: &MasterDek,
    records: &[OpRecord],
    progress: &mut (dyn FnMut(usize, usize) + Send),
) -> Result<usize, SyncError> {
    let mut pushed = 0;
    for (done, record) in records.iter().enumerate() {
        progress(done, records.len());
        let key = op_key(record);
        // Records are immutable, so anything already up there is identical
        // and re-uploading it would only cost bandwidth.
        if client.head(&key).await?.is_some() {
            continue;
        }
        let payload = seal(&record.to_bytes()?, dek)?;
        client.put(&key, payload).await?;
        pushed += 1;
    }
    Ok(pushed)
}

/// An operation object that could not be read: oversized, sealed under a
/// key this silo does not hold, or not a record at all.
#[derive(Debug, Clone)]
pub struct UnreadableOp {
    pub key: String,
    pub op_id: Option<Uuid>,
    pub lamport: Option<u64>,
    pub error: String,
}

/// What a diffing fetch found.
#[derive(Debug, Default)]
pub struct MissingOps {
    pub records: Vec<OpRecord>,
    pub unreadable: Vec<UnreadableOp>,
    /// Records that opened but sit under another record's name: a genuine
    /// record copied by storage to replay it later in the order. Skipped.
    pub misplaced: Vec<String>,
    /// The highest Lamport value any record in the listing carries, read
    /// from the names. After a complete fetch, this device holds every
    /// record storage had up to here.
    pub listed_through: u64,
}

/// Downloads every record the bucket holds that `known` does not name.
/// Diffing on op ids rather than a Lamport watermark is what lets a record
/// pushed late, by a device that was offline while the others moved on,
/// still reach everyone. Anything at or below `above_horizon` is skipped: on
/// a compacted device those records are covered by its base snapshot and
/// must never be applied again.
pub async fn fetch_missing_ops(
    client: &dyn ObjectStore,
    dek: &MasterDek,
    known: &std::collections::HashSet<Uuid>,
    above_horizon: u64,
) -> Result<MissingOps, SyncError> {
    fetch_missing_ops_reporting(client, dek, known, above_horizon, &mut |_, _| {}).await
}

/// The same, calling back with `(done, total)` as each record lands, so a
/// long join can show progress. A callback rather than an event: this crate
/// is transport and knows nothing about the app it runs in.
///
/// An object that will not open is reported rather than raised, so one bad
/// object cannot wedge sync for good; transport errors still fail the pass,
/// because they say nothing about the object. The caller decides how far
/// replay may proceed — see [`usable_prefix`].
pub async fn fetch_missing_ops_reporting(
    client: &dyn ObjectStore,
    dek: &MasterDek,
    known: &std::collections::HashSet<Uuid>,
    above_horizon: u64,
    progress: &mut (dyn FnMut(usize, usize) + Send),
) -> Result<MissingOps, SyncError> {
    let listed = client.list(OPS_PREFIX).await?;
    let listed_through = listed
        .iter()
        .filter_map(|entry| lamport_from_key(&entry.key))
        .max()
        .unwrap_or(0);
    let listing: Vec<_> = listed
        .into_iter()
        .filter(|entry| match lamport_from_key(&entry.key) {
            Some(lamport) => lamport > above_horizon,
            // An unparseable key is something this version doesn't
            // understand. Kept rather than skipped: silently ignoring
            // objects would mean silently losing changes.
            None => true,
        })
        .filter(|entry| match op_id_from_key(&entry.key) {
            Some(id) => !known.contains(&id),
            None => true,
        })
        .collect();

    let total = listing.len();
    let mut out = MissingOps {
        listed_through,
        ..MissingOps::default()
    };
    progress(0, total);

    for (done, entry) in listing.into_iter().enumerate() {
        let mut unreadable = |key: String, error: String| {
            out.unreadable.push(UnreadableOp {
                op_id: op_id_from_key(&key),
                lamport: lamport_from_key(&key),
                key,
                error,
            });
        };
        if entry.size > MAX_OP_BYTES {
            // Checked against the listing, so an object sized to exhaust
            // memory is never downloaded.
            unreadable(
                entry.key,
                format!(
                    "{} bytes is far larger than any operation record",
                    entry.size
                ),
            );
        } else {
            let sealed = client.get(&entry.key).await?;
            match unseal(&sealed, dek) {
                Ok(plain) => match OpRecord::from_bytes(&plain) {
                    // The name is what the order and the horizon filter were
                    // read from. A record under another's name is a copy
                    // storage made, to replay an old change above a snapshot
                    // or later than it happened: never applied.
                    Ok(record) if op_key(&record) != entry.key => out.misplaced.push(entry.key),
                    Ok(record) => out.records.push(record),
                    Err(e) => unreadable(entry.key, e.to_string()),
                },
                Err(_) => unreadable(entry.key, "does not open with this silo's key".into()),
            }
        }
        progress(done + 1, total);
    }
    Ok(out)
}

/// Every record above `horizon`, refusing to answer if any object cannot be
/// read. For joins, rebuilds and restores: a hole there would hand back a
/// smaller vault with nothing to say so.
pub async fn fetch_all_ops_above(
    client: &dyn ObjectStore,
    dek: &MasterDek,
    horizon: u64,
) -> Result<Vec<OpRecord>, SyncError> {
    fetch_all_ops_above_reporting(client, dek, horizon, &mut |_, _| {}).await
}

/// The same, calling back with `(done, total)` while the records come down.
pub async fn fetch_all_ops_above_reporting(
    client: &dyn ObjectStore,
    dek: &MasterDek,
    horizon: u64,
    progress: &mut (dyn FnMut(usize, usize) + Send),
) -> Result<Vec<OpRecord>, SyncError> {
    let known = std::collections::HashSet::new();
    let got = fetch_missing_ops_reporting(client, dek, &known, horizon, progress).await?;
    if let Some(bad) = got.unreadable.first() {
        return Err(SyncError::Vault(format!(
            "{} cannot be read: {}",
            bad.key, bad.error
        )));
    }
    Ok(got.records)
}

/// Cuts fetched records at the first unreadable object, so replay never
/// applies past a hole in the log: an operation applied while its
/// prerequisite is stuck behind the hole would resolve as obsolete and never
/// be retried. Everything at or above the lowest unreadable Lamport value
/// waits for a later pass; an unreadable object with no parseable Lamport
/// value holds nothing back. Returns what may be applied and how many
/// records are waiting.
pub fn usable_prefix(
    mut records: Vec<OpRecord>,
    unreadable: &[UnreadableOp],
) -> (Vec<OpRecord>, usize) {
    let Some(cutoff) = unreadable.iter().filter_map(|u| u.lamport).min() else {
        return (records, 0);
    };
    let before = records.len();
    records.retain(|r| r.lamport < cutoff);
    let held = before - records.len();
    (records, held)
}

/// The most an operation record may weigh before this refuses to read it.
/// The ceiling stops a hostile provider from answering a listing with an
/// object sized to exhaust memory. Checked against the listing, so an
/// oversized object is never downloaded. Blobs get no ceiling: their size is
/// whatever the user stored.
///
/// Writers keep records under 1 MiB, the ceiling every earlier reader
/// applies; reading up to 4 MiB lets this build read a purge record an older
/// build wrote whole.
const MAX_OP_BYTES: i64 = 4 * 1024 * 1024;

/// Ceiling for key envelopes, revocation markers, inbox keys and senders,
/// the manifest, the KEK envelope and `recovery.env`, checked against the
/// listing or a HEAD before download. The largest real one, an envelope with
/// a 2048-character credential id, is a few KiB.
pub const MAX_SMALL_OBJECT_BYTES: i64 = 64 * 1024;

/// Whether storage reports `size` for an object that should be small.
pub(crate) fn too_large(size: i64) -> bool {
    size > MAX_SMALL_OBJECT_BYTES
}

/// A small object whose size storage reported, refused unread when no real
/// one is that large.
pub(crate) async fn get_small(
    client: &dyn ObjectStore,
    key: &str,
    size: i64,
) -> Result<Vec<u8>, SyncError> {
    if too_large(size) {
        return Err(SyncError::Storage(format!(
            "{key} is {size} bytes, far larger than it can be"
        )));
    }
    Ok(client.get(key).await?)
}

/// [`get_small`] after a HEAD. `None` when the object is absent.
pub(crate) async fn fetch_small(
    client: &dyn ObjectStore,
    key: &str,
) -> Result<Option<Vec<u8>>, SyncError> {
    match client.head(key).await? {
        Some(size) => get_small(client, key, size).await.map(Some),
        None => Ok(None),
    }
}

/// One full pass: push what is local-only, pull what is new, replay it.
///
/// Replaying a contiguous run above the local high-water mark is exactly the
/// condition the operation log's convergence guarantee needs — see the
/// `oplog` module docs.
pub async fn sync_ops(
    conn: &Connection,
    client: &dyn ObjectStore,
    dek: &MasterDek,
    pending: &[OpRecord],
) -> Result<SyncOutcome, SyncError> {
    let applied_through = highest_applied_lamport(conn)?;
    check_horizon(client, applied_through).await?;

    let pushed = push_ops(client, dek, pending).await?;
    let known = silentsilo_vfs::all_op_ids(conn)?;
    let local_horizon = silentsilo_vfs::base_horizon(conn)?;
    let got = fetch_missing_ops(client, dek, &known, local_horizon).await?;
    let (incoming, held_back) = usable_prefix(got.records, &got.unreadable);
    let fetched = incoming.len();
    let report = replay(conn, incoming)?;

    Ok(SyncOutcome {
        pushed,
        fetched,
        replay: report,
        held_back,
        unreadable: got.unreadable,
    })
}

/// Refuses to sync a device that has fallen below the snapshot horizon:
/// it is about to be rebuilt, and pushing its pending records first would
/// put changes into the bucket that nobody would ever apply. The bound is
/// `applied_through <= horizon`, deliberately one record strict: Lamport
/// values are not unique across devices, so a device resting exactly on the
/// horizon may still be missing records at it, and those objects can no
/// longer be re-fetched once pruned.
/// The lowest horizon across every target: the right question is whether
/// *anywhere* still has what this device is missing, not whether the most
/// compacted target does. Zero means never compacted, the strongest answer.
/// An unreachable target is skipped rather than treated as zero, or a
/// device would convince itself it is fine and silently miss records.
pub async fn lowest_snapshot_horizon(clients: &[&dyn ObjectStore]) -> Result<u64, SyncError> {
    let mut lowest: Option<u64> = None;
    let mut reached = 0;

    for client in clients {
        let Ok(horizon) = snapshot_horizon(*client).await else {
            continue;
        };
        reached += 1;
        lowest = Some(match lowest {
            Some(current) => current.min(horizon),
            None => horizon,
        });
    }

    if reached == 0 {
        // Nothing answered. Reporting zero would say "no target has been
        // compacted", which is a claim, not an observation.
        return Err(SyncError::Storage(
            "no backup target could be reached".into(),
        ));
    }
    Ok(lowest.unwrap_or(0))
}

async fn check_horizon(client: &dyn ObjectStore, applied_through: u64) -> Result<(), SyncError> {
    let horizon = lowest_snapshot_horizon(&[client]).await?;
    if horizon > 0 && applied_through <= horizon {
        return Err(SyncError::BehindHorizon {
            applied_through,
            horizon,
        });
    }
    Ok(())
}

/// Rebuilds this device from the current state of the silo: the answer to
/// [`SyncError::BehindHorizon`], and how a device joins a compacted silo.
/// The device comes back with a new id;
/// [`silentsilo_vfs::snapshot::rebootstrap`] explains why.
/// For callers that can hold the vault connection across an await. The app
/// cannot, and uses the two phases below directly.
pub async fn rebootstrap_from_snapshot(
    conn: &mut Connection,
    client: &dyn ObjectStore,
    dek: &MasterDek,
) -> Result<RebootstrapOutcome, SyncError> {
    let (snapshot, incoming) = fetch_rebuild(client, dek)
        .await?
        .ok_or_else(|| SyncError::Vault("this silo has no snapshot to rebuild from".into()))?;
    apply_rebuild(conn, &snapshot, incoming)
}

/// Step one: download the state and everything that has happened since.
/// Touches only storage. `None` means never compacted: the whole log is
/// still there and an ordinary replay from the beginning is the way in.
pub async fn fetch_rebuild(
    client: &dyn ObjectStore,
    dek: &MasterDek,
) -> Result<Option<(Snapshot, Vec<OpRecord>)>, SyncError> {
    fetch_rebuild_reporting(client, dek, &mut |_, _| {}).await
}

/// The same, calling back with `(done, total)` while the log above the
/// horizon comes down.
pub async fn fetch_rebuild_reporting(
    client: &dyn ObjectStore,
    dek: &MasterDek,
    progress: &mut (dyn FnMut(usize, usize) + Send),
) -> Result<Option<(Snapshot, Vec<OpRecord>)>, SyncError> {
    let Some(snapshot) = latest_snapshot(client, dek).await? else {
        return Ok(None);
    };
    // Everything above the horizon, which is the whole of what the bucket
    // still holds under `ops/`.
    let incoming = fetch_all_ops_above_reporting(client, dek, snapshot.horizon, progress).await?;
    Ok(Some((snapshot, incoming)))
}

/// How a device that has never held this silo builds its tree.
///
/// The shape is decided by the storage, not by the caller. A silo that has
/// been compacted starts from its snapshot, because the records below the
/// horizon are gone from the bucket and replaying what is left onto an empty
/// tree rebuilds the tail of the history and nothing before it. A silo that
/// has never been compacted replays its whole log.
///
/// One type for every way in, so the security-key join and the recovery-code
/// join cannot disagree about it. They did: the recovery path replayed from
/// zero, which on a compacted silo handed back a partial vault with nothing
/// to say so, and recovery is the one path where there is nothing left to
/// compare the result against.
pub enum JoinPlan {
    /// Compacted: the state as captured, plus everything since.
    FromSnapshot {
        snapshot: Snapshot,
        incoming: Vec<OpRecord>,
    },
    /// Never compacted: the log still starts at the beginning.
    WholeLog(Vec<OpRecord>),
}

impl JoinPlan {
    /// Records this plan will replay, not counting the snapshot.
    pub fn records(&self) -> usize {
        match self {
            Self::FromSnapshot { incoming, .. } => incoming.len(),
            Self::WholeLog(records) => records.len(),
        }
    }

    /// Makes it this device's state. Touches only the database.
    pub fn apply(self, conn: &mut Connection) -> Result<usize, SyncError> {
        match self {
            Self::FromSnapshot { snapshot, incoming } => {
                Ok(apply_rebuild(conn, &snapshot, incoming)?.replay.applied)
            }
            Self::WholeLog(records) => Ok(replay(conn, records)?.applied),
        }
    }
}

/// Reads whichever of the two a bucket calls for.
pub async fn fetch_join_plan(
    client: &dyn ObjectStore,
    dek: &MasterDek,
) -> Result<JoinPlan, SyncError> {
    fetch_join_plan_reporting(client, dek, &mut |_, _| {}).await
}

/// The same, calling back with `(done, total)` while the records come down.
pub async fn fetch_join_plan_reporting(
    client: &dyn ObjectStore,
    dek: &MasterDek,
    progress: &mut (dyn FnMut(usize, usize) + Send),
) -> Result<JoinPlan, SyncError> {
    match fetch_rebuild_reporting(client, dek, progress).await? {
        Some((snapshot, incoming)) => Ok(JoinPlan::FromSnapshot { snapshot, incoming }),
        // Horizon zero fetches the whole log: no record carries Lamport 0.
        None => Ok(JoinPlan::WholeLog(
            fetch_all_ops_above_reporting(client, dek, 0, progress).await?,
        )),
    }
}

/// Step two: make it this device's state. Touches only the database.
pub fn apply_rebuild(
    conn: &mut Connection,
    snapshot: &Snapshot,
    incoming: Vec<OpRecord>,
) -> Result<RebootstrapOutcome, SyncError> {
    let fetched = incoming.len();
    // What this device wrote and no copy has yet. A rebuild used to drop it:
    // work done offline, gone because the others compacted meanwhile.
    let unpushed = silentsilo_vfs::pending_ops(conn)?;
    let device_id = silentsilo_vfs::snapshot::rebootstrap(conn, snapshot)?;
    let replay_report = replay(conn, incoming)?;

    // Written again, under the new identity and after everything fetched, so
    // it sorts as the latest change. A record some copy did hold came back
    // with the fetch and is not written twice.
    let known = silentsilo_vfs::all_op_ids(conn)?;
    let mut kept_local = 0;
    for record in unpushed {
        if known.contains(&record.op_id) {
            continue;
        }
        if let silentsilo_vfs::OpBody::Known(op) = record.op
            && silentsilo_vfs::emit(conn, op).is_ok()
        {
            kept_local += 1;
        }
    }

    Ok(RebootstrapOutcome {
        horizon: snapshot.horizon,
        device_id,
        fetched,
        replay: replay_report,
        kept_local,
    })
}

/// Compacts the silo if the log has grown enough to be worth it. Run
/// straight after a successful [`sync_ops`] and from nowhere else: the
/// device must hold the whole log before declaring records deletable. The
/// order only goes one way: capture the state, put the snapshot in the
/// bucket, delete the records it covers, prune the local log. Stopping
/// between any two steps leaves a silo that still works; deleting before
/// the snapshot is up leaves one nobody can join.
/// `now` comes from the caller so the decision stays testable. For callers
/// that can hold the vault connection across an await; the app cannot, and
/// uses the phases below directly.
pub async fn compact_if_due(
    conn: &mut Connection,
    client: &dyn ObjectStore,
    dek: &MasterDek,
    vault_id: Uuid,
    policy: &CompactionPolicy,
    now: i64,
) -> Result<Option<CompactionOutcome>, SyncError> {
    let Some(snapshot) = plan_compaction(conn, vault_id, policy, now)? else {
        return Ok(None);
    };
    // One target, and it is the one the caller chose to keep tidy, so it
    // prunes. The role-aware path is the multi-target one in the app.
    let published = publish_compaction(client, dek, &snapshot, true).await?;
    let pruned_local = finish_compaction(conn, &snapshot)?;

    Ok(Some(CompactionOutcome {
        horizon: snapshot.horizon,
        pruned_remote: published.deleted,
        pruned_local: pruned_local.dropped,
        stranded: pruned_local.stranded,
    }))
}

/// Step one: decide, and capture the state. Touches only the database.
///
/// `None` when the log should be left alone, which is the answer almost every
/// time it is asked.
pub fn plan_compaction(
    conn: &Connection,
    vault_id: Uuid,
    policy: &CompactionPolicy,
    now: i64,
) -> Result<Option<Snapshot>, SyncError> {
    match choose_horizon(conn, policy, now)? {
        None => Ok(None),
        Some(horizon) => Ok(Some(capture_at(conn, vault_id, horizon)?)),
    }
}

/// Step two: publish the snapshot, then delete what it covers. Touches only
/// storage. Takes the snapshot by reference rather than a horizon, so it
/// cannot be called before one was captured: deleting records before their
/// replacement is readable leaves a silo nobody can join.
/// `prune` is false for an append-only target: the snapshot still goes up
/// (a PUT on a fresh key), but the delete afterwards cannot happen, so that
/// target keeps the whole log for ever.
pub async fn publish_compaction(
    client: &dyn ObjectStore,
    dek: &MasterDek,
    snapshot: &Snapshot,
    prune: bool,
) -> Result<PruneOutcome, SyncError> {
    put_snapshot(client, dek, snapshot).await?;
    if !prune {
        return Ok(PruneOutcome::default());
    }
    // Read back before anything is deleted. This object is about to become
    // the only copy of everything below the horizon on this target, and a
    // write the provider corrupted must not be what the records are traded
    // for; a refused pass costs one retry.
    let echoed = client.get(&snapshot_key(snapshot.horizon)).await?;
    let echoed = Snapshot::from_bytes(&unseal(&echoed, dek)?)?;
    if echoed != *snapshot {
        return Err(SyncError::Storage(
            "the snapshot did not read back as written, so nothing was pruned".into(),
        ));
    }
    prune_ops_below(client, snapshot.horizon).await
}

/// Step three: record the snapshot locally and drop the records it covers.
///
/// Safe to skip if the process dies first: the device simply keeps a log it
/// no longer strictly needs, and the next pass proposes the same work again.
pub fn finish_compaction(
    conn: &mut Connection,
    snapshot: &Snapshot,
) -> Result<silentsilo_vfs::PruneReport, SyncError> {
    Ok(silentsilo_vfs::snapshot::compact_local(conn, snapshot)?)
}

/// What a compaction pass did.
#[derive(Debug, Clone)]
pub struct CompactionOutcome {
    pub horizon: u64,
    pub pruned_remote: usize,
    pub pruned_local: usize,
    /// Local records below the horizon that the bucket never confirmed. They
    /// are kept, and they are a problem: they belong below a line every other
    /// device is about to compact past. Surfaced rather than swallowed.
    pub stranded: usize,
}

/// What a re-bootstrap rebuilt.
#[derive(Debug, Clone)]
pub struct RebootstrapOutcome {
    /// The state the device restarted from.
    pub horizon: u64,
    /// Its new identity. Worth surfacing: the Devices list will show a new
    /// row, and the old one stops changing.
    pub device_id: Uuid,
    pub fetched: usize,
    pub replay: ReplayReport,
    /// Changes this device had not pushed, written again on top.
    pub kept_local: usize,
}

// ── Blob content ────────────────────────────────────────────────────

/// Where file content lives inside the vault prefix.
pub const BLOBS_PREFIX: &str = "blobs/";

fn blob_key(blob_id: Uuid) -> String {
    format!("{BLOBS_PREFIX}{blob_id}.sslo")
}

/// Result of a blob push pass.
#[derive(Debug, Default, Clone)]
pub struct BlobPushOutcome {
    pub uploaded: usize,
    pub already_present: usize,
    /// Blobs that could not be uploaded, with why. A failure here is not
    /// fatal to the pass: the rest still go, and these stay unsynced so the
    /// next attempt retries them.
    pub failed: Vec<(Uuid, String)>,
}

/// Uploads every blob on this device that isn't confirmed in the bucket.
/// Blobs are already ciphertext on disk and their keys are immutable, so
/// this is a byte-for-byte transfer with nothing to merge.
pub async fn push_blobs(
    client: &dyn ObjectStore,
    vault_root: &Path,
    target: Uuid,
    blob_ids: &[Uuid],
) -> Result<BlobPushOutcome, SyncError> {
    push_blobs_reporting(client, vault_root, target, blob_ids, &mut |_, _, _| {}).await
}

/// [`push_blobs`], naming each blob before it is checked and sent, with how
/// many came before it.
pub async fn push_blobs_reporting(
    client: &dyn ObjectStore,
    vault_root: &Path,
    target: Uuid,
    blob_ids: &[Uuid],
    progress: &mut (dyn FnMut(usize, usize, Uuid) + Send),
) -> Result<BlobPushOutcome, SyncError> {
    let mut outcome = BlobPushOutcome::default();

    for (done, blob_id) in blob_ids.iter().enumerate() {
        progress(done, blob_ids.len(), *blob_id);
        let path = vault_root.join("blobs").join(format!("{blob_id}.sslo"));
        if !path.is_file() {
            // Already evicted, or trashed and purged between listing and
            // now. Nothing to send, and nothing to keep owing either: left
            // in place the row would be reported as an upload still pending
            // for as long as the silo exists, for content that is gone.
            let _ = remove_blob_from_cache(vault_root, *blob_id);
            continue;
        }

        let key = blob_key(*blob_id);
        match client.head(&key).await {
            Ok(Some(_)) => {
                // Already up there. Record that so eviction is allowed to
                // reclaim the space — without this the local copy would be
                // pinned forever.
                record_blob_delivered(vault_root, *blob_id, target)
                    .map_err(|e| SyncError::Vault(e.to_string()))?;
                outcome.already_present += 1;
                continue;
            }
            Ok(None) => {}
            Err(e) => {
                outcome.failed.push((*blob_id, e.to_string()));
                continue;
            }
        }

        // Streamed from disk: a blob is whatever size the user stored, and
        // holding it whole in memory capped file size at available RAM.
        match client.put_from_file(&key, &path).await {
            Ok(()) => {
                // Only now: marking a blob synced before the upload lands
                // would make it evictable while the bucket has no copy,
                // which is how you lose a file for good.
                record_blob_delivered(vault_root, *blob_id, target)
                    .map_err(|e| SyncError::Vault(e.to_string()))?;
                outcome.uploaded += 1;
            }
            Err(e) => outcome.failed.push((*blob_id, e.to_string())),
        }
    }

    Ok(outcome)
}

// ── Seeding one target from another ─────────────────────────────────

/// What a seeding pass moved.
#[derive(Debug, Default, Clone)]
pub struct SeedOutcome {
    pub copied: usize,
    /// Objects the destination already held, at the same size. Skipped
    /// rather than rewritten, which is what makes a seed resumable: run it
    /// again after a cable is pulled and it carries on.
    pub skipped: usize,
    pub bytes: u64,
    /// What would not copy, with why. Reported rather than raised: one
    /// unreadable object should not throw away the several hundred gigabytes
    /// that did move.
    pub failed: Vec<(String, String)>,
}

/// Everything a silo keeps in its storage, in the order it is worth
/// copying: content and records first, the manifest last, so an interrupted
/// copy never looks like a silo that lost its history.
const SEED_PREFIXES: [&str; 4] = [BLOBS_PREFIX, OPS_PREFIX, SNAPSHOTS_PREFIX, KEYS_PREFIX];

/// Copies one target's contents into another, on ciphertext throughout: no
/// key needed. Both directions are the same operation. `cancel` is asked
/// between objects; stopping mid-seed is safe, the next run skips what
/// already landed.
pub async fn seed_target(
    from: &dyn ObjectStore,
    to: &dyn ObjectStore,
    progress: &mut (dyn FnMut(usize, usize) + Send),
    cancel: &(dyn Fn() -> bool + Sync),
) -> Result<SeedOutcome, SyncError> {
    let mut outcome = SeedOutcome::default();

    let mut work = Vec::new();
    for prefix in SEED_PREFIXES {
        work.extend(from.list(prefix).await?);
    }
    // The manifest is one fixed key rather than a prefix, and it goes last.
    let manifest_size = from.head(MANIFEST_KEY).await?;

    let total = work.len() + usize::from(manifest_size.is_some());
    progress(0, total);
    let mut done = 0;

    // One staging file, reused: objects pass through disk rather than
    // memory, since a blob is whatever size the user stored.
    let staging = tempfile::Builder::new()
        .prefix("silentsilo-seed")
        .tempdir()
        .map_err(|e| SyncError::Vault(e.to_string()))?;
    let staged = staging.path().join("object");

    for entry in work {
        if cancel() {
            return Err(SyncError::Cancelled);
        }
        // A blob already there at the same size is treated as already
        // there: blob keys are written once and never rewritten, so "same
        // key, same size" is a strong statement, and a deeper check would
        // download both copies of the very objects this exists not to move.
        // Nothing else gets the shortcut. A rotation re-seals records,
        // snapshots and key envelopes in place at exactly the same length,
        // and a size check would skip the one write that matters.
        if entry.key.starts_with(BLOBS_PREFIX) && to.head(&entry.key).await? == Some(entry.size) {
            outcome.skipped += 1;
            done += 1;
            progress(done, total);
            continue;
        }
        match from.get_to_file(&entry.key, &staged).await {
            Ok(()) => {
                let len = std::fs::metadata(&staged).map(|m| m.len()).unwrap_or(0);
                match to.put_from_file(&entry.key, &staged).await {
                    Ok(()) => {
                        outcome.copied += 1;
                        outcome.bytes += len;
                    }
                    Err(e) => outcome.failed.push((entry.key.clone(), e.to_string())),
                }
            }
            Err(e) => outcome.failed.push((entry.key.clone(), e.to_string())),
        }
        done += 1;
        progress(done, total);
    }

    if manifest_size.is_some() {
        match from.get(MANIFEST_KEY).await {
            Ok(bytes) => match to.put(MANIFEST_KEY, bytes).await {
                Ok(()) => outcome.copied += 1,
                Err(e) => outcome
                    .failed
                    .push((MANIFEST_KEY.to_string(), e.to_string())),
            },
            Err(e) => outcome
                .failed
                .push((MANIFEST_KEY.to_string(), e.to_string())),
        }
        done += 1;
        progress(done, total);
    }

    Ok(outcome)
}

// ── Checking a silo against its storage ─────────────────────────────

/// What a scrub found.
///
/// Counts of what was looked at, and a list of what was wrong. The list is the
/// answer; the counts are what makes an empty list mean something, since
/// "nothing wrong" and "nothing checked" read identically otherwise.
#[derive(Debug, Default, Clone)]
pub struct VerifyReport {
    pub records_read: usize,
    pub blobs_checked: usize,
    /// Bytes of content actually read back and authenticated. Zero on a check
    /// that only looked for presence.
    pub bytes_read: u64,
    /// Referenced content storage does not have. The worst finding here: the
    /// silo believes it holds these files and it does not.
    pub missing: Vec<Uuid>,
    /// Objects that are there but wrong, with why. Bit rot, a partial upload,
    /// or something rewritten underneath.
    pub damaged: Vec<(String, String)>,
    /// Content in storage that nothing references. Not a fault: a sweep
    /// clears these, and one that arrived ahead of its record is normal.
    pub unreferenced: usize,
}

impl VerifyReport {
    /// Nothing wrong, as opposed to nothing found.
    pub fn is_sound(&self) -> bool {
        self.missing.is_empty() && self.damaged.is_empty()
    }
}

/// How hard to look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyDepth {
    /// Reads every operation record and checks that each referenced blob is
    /// present. No content is downloaded, so any silo finishes in about the
    /// time a listing takes.
    Listing,
    /// Also reads back every referenced blob and authenticates it. Catches
    /// bit rot, which nothing else does, and costs a download of the silo.
    Content,
}

/// Reads a silo's storage and reports what is wrong with it. `expected` is
/// what the local index says should be there: storage agreeing with itself
/// proves nothing. `open` turns a blob id into its content key, passed in
/// because this crate moves ciphertext and knows no key but the DEK.
pub async fn verify_against(
    client: &dyn ObjectStore,
    dek: &MasterDek,
    expected: &std::collections::HashSet<Uuid>,
    depth: VerifyDepth,
    open: &mut (dyn FnMut(Uuid) -> Option<silentsilo_crypto::ContentKey> + Send),
    progress: &mut (dyn FnMut(usize, usize) + Send),
    cancel: &(dyn Fn() -> bool + Sync),
) -> Result<VerifyReport, SyncError> {
    let mut report = VerifyReport::default();

    let ops = client.list(OPS_PREFIX).await?;
    let blobs = client.list(BLOBS_PREFIX).await?;
    let total = ops.len() + blobs.len();
    let mut done = 0;
    progress(0, total);

    // Every record, opened. Unsealing is the check: the envelope is
    // authenticated, so a record that has been altered fails here rather than
    // replaying into a tree that is quietly wrong.
    for entry in ops {
        if cancel() {
            return Err(SyncError::Cancelled);
        }
        match client.get(&entry.key).await {
            Ok(sealed) => match unseal(&sealed, dek) {
                Ok(plain) => match OpRecord::from_bytes(&plain) {
                    Ok(_) => report.records_read += 1,
                    Err(e) => report.damaged.push((entry.key.clone(), e.to_string())),
                },
                Err(_) => report.damaged.push((
                    entry.key.clone(),
                    "does not open with this silo's key".to_string(),
                )),
            },
            Err(e) => report.damaged.push((entry.key.clone(), e.to_string())),
        }
        done += 1;
        progress(done, total);
    }

    let mut seen: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    for entry in blobs {
        if cancel() {
            return Err(SyncError::Cancelled);
        }
        done += 1;

        let Some(blob_id) = blob_id_from_key(&entry.key) else {
            // A key this build does not understand. Counted as unreferenced
            // rather than damaged: not knowing what something is is not the
            // same as knowing it is broken.
            report.unreferenced += 1;
            progress(done, total);
            continue;
        };
        seen.insert(blob_id);

        if !expected.contains(&blob_id) {
            report.unreferenced += 1;
            progress(done, total);
            continue;
        }

        // Some WebDAV servers omit sizes from listings, so a zero is
        // confirmed with a direct question before it is called damage.
        let size = if entry.size > 0 {
            entry.size
        } else {
            client.head(&entry.key).await.ok().flatten().unwrap_or(0)
        };
        if size <= 0 {
            // An upload that created the object and stopped. Worth catching
            // without downloading anything.
            report
                .damaged
                .push((entry.key.clone(), "the object is empty".to_string()));
        } else if depth == VerifyDepth::Content {
            match open(blob_id) {
                Some(key) => match verify_one(client, &entry.key, &key, blob_id).await {
                    Ok(read) => {
                        report.blobs_checked += 1;
                        report.bytes_read += read;
                    }
                    Err(e) => report.damaged.push((entry.key.clone(), e)),
                },
                None => report.damaged.push((
                    entry.key.clone(),
                    "no content key is recorded for this file".to_string(),
                )),
            }
        } else {
            report.blobs_checked += 1;
        }

        progress(done, total);
    }

    // Content the silo believes it has. Collected last so a missing object,
    // which is the finding that matters most, is not buried among the ones
    // that are merely odd.
    for blob_id in expected {
        if !seen.contains(blob_id) {
            report.missing.push(*blob_id);
        }
    }
    report.missing.sort();

    Ok(report)
}

/// Downloads one blob and authenticates it, returning the bytes read.
///
/// Streamed to a temporary file rather than checked in memory, because a
/// blob is whatever size the user stored and reading ten gigabytes into a
/// buffer would be a poor way to find out a disk is fine.
async fn verify_one(
    client: &dyn ObjectStore,
    key: &str,
    content_key: &silentsilo_crypto::ContentKey,
    blob_id: Uuid,
) -> Result<u64, String> {
    let dir = tempfile::Builder::new()
        .prefix("silentsilo-verify")
        .tempdir()
        .map_err(|e| e.to_string())?;
    let path = dir.path().join("blob.sslo");
    client
        .get_to_file(key, &path)
        .await
        .map_err(|e| e.to_string())?;
    let read = std::fs::metadata(&path).map_err(|e| e.to_string())?.len();

    silentsilo_crypto::verify_blob(&path, content_key, blob_id).map_err(|e| e.to_string())?;
    Ok(read)
}

// ── Rotating the vault key ──────────────────────────────────────────

/// What a re-sealing pass did.
#[derive(Debug, Default, Clone)]
pub struct ResealOutcome {
    pub resealed: usize,
    /// Objects that already opened under the new key, so a pass that was
    /// interrupted picks up where it stopped rather than starting over.
    pub already: usize,
    /// Objects that opened under neither key, with why. Reported rather than
    /// raised: one unreadable object must not abandon a rotation halfway,
    /// which is the state with no good way out.
    pub failed: Vec<(String, String)>,
}

/// Everything in storage that is sealed under the vault DEK.
///
/// Key envelopes are not here: they are wrapped under a credential's key, not
/// the DEK, and rotation rewrites them by a different route. The manifest is
/// plain JSON naming a random id and has nothing to re-seal.
const SEALED_PREFIXES: [&str; 2] = [OPS_PREFIX, SNAPSHOTS_PREFIX];

/// Re-seals every object under the new vault key, leaving their contents
/// exactly as they were: fingerprints hold and the log's chain stays
/// intact. Safe to interrupt and safe to run twice; each object is skipped
/// when it already opens under the new key, and the write happens only
/// after a successful read, so nothing is ever unreadable by both keys.
pub async fn reseal_under_new_key(
    client: &dyn ObjectStore,
    old: &MasterDek,
    new: &MasterDek,
    progress: &mut (dyn FnMut(usize, usize) + Send),
) -> Result<ResealOutcome, SyncError> {
    let mut outcome = ResealOutcome::default();

    let mut work = Vec::new();
    for prefix in SEALED_PREFIXES {
        work.extend(
            client
                .list(prefix)
                .await?
                .into_iter()
                .map(|entry| entry.key),
        );
    }
    // The KEK envelope is sealed under the DEK like the records, and it is
    // the one object that must arrive: without it a joining device has no
    // way to open any content at all.
    if client.head(CONTENT_KEK_KEY).await?.is_some() {
        work.push(CONTENT_KEK_KEY.to_string());
    }

    let total = work.len();
    progress(0, total);

    for (done, key) in work.into_iter().enumerate() {
        let sealed = match client.get(&key).await {
            Ok(bytes) => bytes,
            Err(e) => {
                outcome.failed.push((key, e.to_string()));
                progress(done + 1, total);
                continue;
            }
        };

        // Already done on an earlier pass. Checked by trying the new key
        // rather than by keeping a list, because the object itself is the
        // only record that cannot go out of step with the truth.
        if unseal(&sealed, new).is_ok() {
            outcome.already += 1;
            progress(done + 1, total);
            continue;
        }

        match unseal(&sealed, old) {
            Ok(plain) => match seal(&plain, new) {
                Ok(resealed) => match client.put(&key, resealed).await {
                    Ok(()) => outcome.resealed += 1,
                    Err(e) => outcome.failed.push((key, e.to_string())),
                },
                Err(e) => outcome.failed.push((key, e.to_string())),
            },
            Err(_) => outcome.failed.push((
                key,
                "opens under neither the old key nor the new one".to_string(),
            )),
        }
        progress(done + 1, total);
    }

    Ok(outcome)
}

/// Uploads everything this device holds that the bucket does not.
pub async fn push_pending_blobs(
    client: &dyn ObjectStore,
    vault_root: &Path,
    target: Uuid,
) -> Result<BlobPushOutcome, SyncError> {
    let pending = list_undelivered_blob_ids(vault_root, target);
    push_blobs(client, vault_root, target, &pending).await
}

/// One blob's sealed bytes, streamed into a file the caller chose, without
/// a cache to put them in. For the extraction tool and the trial restore,
/// which must not leave a half-silo on the machine they run on.
pub async fn fetch_blob_to_file(
    client: &dyn ObjectStore,
    blob_id: Uuid,
    dest: &Path,
) -> Result<(), SyncError> {
    Ok(client.get_to_file(&blob_key(blob_id), dest).await?)
}

/// Downloads one blob into the local cache.
///
/// Called when a file is opened whose content isn't here — either because
/// another device uploaded it, or because eviction reclaimed the space.
pub async fn fetch_blob(
    client: &dyn ObjectStore,
    vault_root: &Path,
    blob_id: Uuid,
) -> Result<u64, SyncError> {
    let blobs_dir = vault_root.join("blobs");
    std::fs::create_dir_all(&blobs_dir).map_err(|e| SyncError::Vault(e.to_string()))?;

    // Stream to a temp name and rename, so an interrupted download can't
    // leave a truncated file that later reads as corrupt ciphertext.
    let final_path = blobs_dir.join(format!("{blob_id}.sslo"));
    let temp_path = blobs_dir.join(format!("{blob_id}.sslo.part"));
    client.get_to_file(&blob_key(blob_id), &temp_path).await?;
    let size = std::fs::metadata(&temp_path)
        .map_err(|e| SyncError::Vault(e.to_string()))?
        .len() as i64;
    silentsilo_core::rename_with_retry(&temp_path, &final_path)
        .map_err(|e| SyncError::Vault(e.to_string()))?;
    // Not marked evictable here, even though it plainly exists on the
    // target it came from: eviction needs every target to hold it, and this
    // call does not know the others. The next push settles that with a HEAD
    // per target, and holding the local copy until then errs the safe way.
    record_blob_present(vault_root, blob_id, size, false)
        .map_err(|e| SyncError::Vault(e.to_string()))?;
    Ok(size as u64)
}

/// [`fetch_blob`] tried against every copy in turn: content is the same
/// bytes everywhere, and the first target being an unplugged disk must not
/// fail an export a second copy could serve. Returns the last error when
/// none of them has it.
pub async fn fetch_blob_from_any(
    clients: &[&dyn ObjectStore],
    vault_root: &Path,
    blob_id: Uuid,
) -> Result<u64, SyncError> {
    let mut last = SyncError::Storage("no backup target could be reached".into());
    for client in clients {
        match fetch_blob(*client, vault_root, blob_id).await {
            Ok(size) => return Ok(size),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// [`fetch_blob_from_any`] that also notes which target served the blob.
/// Content that came down from a copy is plainly on that copy, and without
/// the note it counted as waiting to back up until the next push had asked
/// every target about it. Settle with every configured target afterwards
/// (`settle_blob_delivery`) for the count to change.
///
/// `every_copy` says `targets` are all the silo's configured copies. Only
/// then does a blob none of them holds get remembered as absent: a copy
/// that would not open, left out of the list, might be the one that has it.
pub async fn fetch_blob_from_targets(
    targets: &[(Uuid, &dyn ObjectStore)],
    vault_root: &Path,
    blob_id: Uuid,
    every_copy: bool,
) -> Result<u64, SyncError> {
    let mut last = SyncError::Storage("no backup target could be reached".into());
    for (target, client) in targets {
        match fetch_blob(*client, vault_root, blob_id).await {
            Ok(size) => {
                let _ = record_blob_delivered(vault_root, blob_id, *target);
                let _ = silentsilo_vault::clear_blob_absent(vault_root, blob_id);
                return Ok(size);
            }
            Err(e) => last = e,
        }
    }
    // Asked outright: the errors above do not keep whether the object was
    // missing or the target unreachable, and only the first is worth
    // remembering.
    if every_copy && absent_from_every(targets, blob_id).await {
        let _ = silentsilo_vault::record_blob_absent(vault_root, blob_id);
        return Err(SyncError::Storage(
            "this file's content is in none of the backups".into(),
        ));
    }
    Err(last)
}

/// True only when every target answered, and none holds the blob.
async fn absent_from_every(targets: &[(Uuid, &dyn ObjectStore)], blob_id: Uuid) -> bool {
    if targets.is_empty() {
        return false;
    }
    for (_, client) in targets {
        if !matches!(client.head(&blob_key(blob_id)).await, Ok(None)) {
            return false;
        }
    }
    true
}

/// How many remembered-absent blobs one pass asks about again.
const ABSENT_RECHECK_PER_PASS: usize = 100;

/// Asks the targets again about content last found on none of them, since
/// a device that still had it may have uploaded it since. Any one target
/// holding it clears it, so this runs against whichever copies answered.
/// The longest unchecked go first and one still missing goes to the back,
/// so a long list is walked through rather than its head asked forever.
/// Returns how many turned up.
pub async fn recheck_absent_blobs(
    targets: &[(Uuid, &dyn ObjectStore)],
    vault_root: &Path,
) -> usize {
    let mut found = 0;
    for blob_id in silentsilo_vault::list_absent_blob_ids(vault_root)
        .into_iter()
        .take(ABSENT_RECHECK_PER_PASS)
    {
        let mut here = false;
        for (_, client) in targets {
            if let Ok(Some(_)) = client.head(&blob_key(blob_id)).await {
                here = true;
                break;
            }
        }
        if here {
            let _ = silentsilo_vault::clear_blob_absent(vault_root, blob_id);
            found += 1;
        } else {
            let _ = silentsilo_vault::record_blob_absent(vault_root, blob_id);
        }
    }
    found
}

// ── Snapshots ───────────────────────────────────────────────────────

/// Where compaction writes the state of the vault.
pub const SNAPSHOTS_PREFIX: &str = "snapshots/";

/// Zero-padded like op keys, so a listing comes back oldest first and the
/// newest snapshot is the last entry.
fn snapshot_key(horizon: u64) -> String {
    format!("{SNAPSHOTS_PREFIX}{horizon:020}.snap")
}

fn horizon_from_key(key: &str) -> Option<u64> {
    key.strip_prefix(SNAPSHOTS_PREFIX)?
        .strip_suffix(".snap")?
        .parse()
        .ok()
}

/// Publishes the state of the vault at a horizon, sealed with the vault
/// DEK. Write this **before** deleting anything it covers, or there is a
/// window in which the silo cannot be joined.
pub async fn put_snapshot(
    client: &dyn ObjectStore,
    dek: &MasterDek,
    snapshot: &Snapshot,
) -> Result<(), SyncError> {
    let payload = seal(&snapshot.to_bytes()?, dek)?;
    client.put(&snapshot_key(snapshot.horizon), payload).await?;
    Ok(())
}

/// Publishes the local base snapshot unless this target already has one at
/// that horizon. Must run before the first push to a target, or a locally
/// compacted log starts mid-stream in the bucket.
pub async fn publish_base_if_missing(
    client: &dyn ObjectStore,
    dek: &MasterDek,
    base: &Snapshot,
) -> Result<bool, SyncError> {
    if client.head(&snapshot_key(base.horizon)).await?.is_some() {
        return Ok(false);
    }
    put_snapshot(client, dek, base).await?;
    Ok(true)
}

/// The highest horizon the bucket has a snapshot for, or 0 for none.
///
/// Answered from the listing alone, without downloading or decrypting
/// anything: every device asks this on every pass to find out whether it has
/// fallen below the horizon, and the answer is one integer.
pub async fn snapshot_horizon(client: &dyn ObjectStore) -> Result<u64, SyncError> {
    let entries = client.list(SNAPSHOTS_PREFIX).await?;
    Ok(entries
        .iter()
        .filter_map(|entry| horizon_from_key(&entry.key))
        .max()
        .unwrap_or(0))
}

/// Downloads the newest snapshot, for a device joining a compacted silo.
///
/// `None` when the silo has never been compacted, which is the normal case
/// and means the whole log is still there to replay.
pub async fn latest_snapshot(
    client: &dyn ObjectStore,
    dek: &MasterDek,
) -> Result<Option<Snapshot>, SyncError> {
    // No size ceiling here, unlike an operation record. A snapshot's honest
    // size is the size of the vault's index, so there is no bound to pick
    // that is not either useless or a limit on how large a silo may be. The
    // same reasoning as blobs, and the same fix when it matters: read it as
    // a stream rather than whole.
    //
    // Newest first, and only one whose own horizon matches its name. A
    // genuine old snapshot copied under a higher name would otherwise hold
    // every device in "rebuild" for good, and each rebuild lose what it had
    // not pushed. One that will not open is still an error: skipping it for
    // an older one would rebuild without records already pruned.
    let mut horizons: Vec<u64> = client
        .list(SNAPSHOTS_PREFIX)
        .await?
        .iter()
        .filter_map(|entry| horizon_from_key(&entry.key))
        .collect();
    horizons.sort_unstable_by(|a, b| b.cmp(a));
    for horizon in horizons {
        let sealed = client.get(&snapshot_key(horizon)).await?;
        let snapshot = Snapshot::from_bytes(&unseal(&sealed, dek)?)?;
        if snapshot.horizon == horizon {
            return Ok(Some(snapshot));
        }
    }
    Ok(None)
}

/// The horizon of the newest snapshot whose contents agree with its name, or
/// 0. Downloads snapshots, so it is asked only when the listing alone
/// ([`snapshot_horizon`]) says this device has fallen behind.
pub async fn verified_snapshot_horizon(
    client: &dyn ObjectStore,
    dek: &MasterDek,
) -> Result<u64, SyncError> {
    Ok(latest_snapshot(client, dek)
        .await?
        .map_or(0, |snapshot| snapshot.horizon))
}

/// Deletes the operation objects a snapshot has made redundant. Only ever
/// called after [`put_snapshot`] landed; a failure part way through leaves
/// merely redundant objects, so the pass reports rather than unwinds.
pub async fn prune_ops_below(
    client: &dyn ObjectStore,
    horizon: u64,
) -> Result<PruneOutcome, SyncError> {
    let mut outcome = PruneOutcome::default();
    for entry in client.list(OPS_PREFIX).await? {
        match lamport_from_key(&entry.key) {
            // Unparseable keys are left alone. This build does not know what
            // they are, and deleting an object nobody understands is how you
            // lose the thing a newer version was relying on.
            None => continue,
            Some(lamport) if lamport > horizon => continue,
            Some(_) => {}
        }
        match client.delete(&entry.key).await {
            Ok(()) => outcome.deleted += 1,
            Err(e) => outcome.failed.push((entry.key.clone(), e.to_string())),
        }
    }
    Ok(outcome)
}

/// What a bucket-side prune managed.
#[derive(Debug, Default, Clone)]
pub struct PruneOutcome {
    pub deleted: usize,
    /// Objects that would not delete, with why. Redundant rather than
    /// harmful, and the next pass tries them again.
    pub failed: Vec<(String, String)>,
}

// ── Collecting superseded content ───────────────────────────────────

/// What a sweep found and what it did.
#[derive(Debug, Default, Clone)]
pub struct SweepOutcome {
    pub deleted: usize,
    /// Blobs the bucket holds that nothing points at, seen this pass. Held
    /// for the next one rather than deleted now, and the caller has to store
    /// them for that to mean anything.
    pub candidates: Vec<Uuid>,
    pub failed: Vec<(Uuid, String)>,
    /// Every blob the listing held, deleted ones included.
    pub listed: Vec<Uuid>,
}

/// Deletes content nothing points at any more, one pass behind: a blob
/// reaches the bucket before the record naming it, so a sweep only deletes
/// what was already unreferenced on the previous pass and still is.
/// Deleting on sight would destroy a file another device uploaded seconds
/// ago. The caller must run this from a device that has just synced, and
/// must pass the candidates from the previous pass and store the ones
/// returned.
pub async fn sweep_orphan_blobs(
    client: &dyn ObjectStore,
    referenced: &std::collections::HashSet<Uuid>,
    previous_candidates: &std::collections::HashSet<Uuid>,
) -> Result<SweepOutcome, SyncError> {
    let mut outcome = SweepOutcome::default();

    for entry in client.list(BLOBS_PREFIX).await? {
        let Some(blob_id) = blob_id_from_key(&entry.key) else {
            // Not a blob this build recognises. Left alone, like an
            // unreadable operation object.
            continue;
        };
        outcome.listed.push(blob_id);
        if referenced.contains(&blob_id) {
            continue;
        }
        if !previous_candidates.contains(&blob_id) {
            // First sighting. It may be content whose record has not landed
            // yet, so it waits a pass.
            outcome.candidates.push(blob_id);
            continue;
        }
        match client.delete(&entry.key).await {
            Ok(()) => outcome.deleted += 1,
            Err(e) => {
                outcome.failed.push((blob_id, e.to_string()));
                // Still a candidate: a delete that failed is not a delete.
                outcome.candidates.push(blob_id);
            }
        }
    }

    Ok(outcome)
}

/// How many missing blobs one pass puts back per target.
const RESTORE_PER_PASS: usize = 100;

/// What [`restore_missing_blobs`] put back.
#[derive(Debug, Default, Clone)]
pub struct RestoreOutcome {
    pub restored: Vec<Uuid>,
    /// Missing, and neither this device nor another copy had the bytes.
    pub unavailable: Vec<Uuid>,
    pub failed: Vec<(Uuid, String)>,
}

/// Puts back content a file still points at that `target` no longer holds,
/// from this device's cache or from another copy. `missing` comes from a
/// listing of `target` against what this device references; content this
/// device does not reference is never sent. An older version's sweep deletes
/// content it has no row for, and a row can reach a device after the sweep
/// that saw none.
pub async fn restore_missing_blobs(
    target: (Uuid, &dyn ObjectStore),
    others: &[(Uuid, &dyn ObjectStore)],
    vault_root: &Path,
    missing: &[Uuid],
) -> RestoreOutcome {
    let mut outcome = RestoreOutcome::default();
    let (target_id, store) = target;
    for blob_id in missing.iter().copied().take(RESTORE_PER_PASS) {
        let path = vault_root.join("blobs").join(format!("{blob_id}.sslo"));
        if !path.is_file() {
            let mut found = false;
            for (other, client) in others {
                if *other == target_id {
                    continue;
                }
                if fetch_blob(*client, vault_root, blob_id).await.is_ok() {
                    let _ = record_blob_delivered(vault_root, blob_id, *other);
                    found = true;
                    break;
                }
            }
            if !found {
                outcome.unavailable.push(blob_id);
                continue;
            }
        }
        match store.put_from_file(&blob_key(blob_id), &path).await {
            Ok(()) => {
                let _ = record_blob_delivered(vault_root, blob_id, target_id);
                let _ = silentsilo_vault::clear_blob_absent(vault_root, blob_id);
                outcome.restored.push(blob_id);
            }
            Err(e) => outcome.failed.push((blob_id, e.to_string())),
        }
    }
    outcome
}

fn blob_id_from_key(key: &str) -> Option<Uuid> {
    Uuid::parse_str(key.strip_prefix(BLOBS_PREFIX)?.strip_suffix(".sslo")?).ok()
}

// ── Key envelopes and the join manifest ─────────────────────────────

/// Wrapped DEKs, one object per enrolled security key.
pub const KEYS_PREFIX: &str = "keys/";

/// Where the content KEK's envelope lives: one object for the whole silo,
/// sealed under the vault DEK. Every device needs the same one, or files
/// written by one device could not be opened by the others.
pub const CONTENT_KEK_KEY: &str = "keys/content.kek";

/// Publishes the KEK envelope, writing only when it differs. Compared by
/// content, not presence or size: rotation re-wraps to the same length, and
/// skipping that write would leave every other device locked out.
pub async fn publish_content_kek(
    client: &dyn ObjectStore,
    envelope: &[u8],
) -> Result<bool, SyncError> {
    if client
        .head(CONTENT_KEK_KEY)
        .await?
        .is_some_and(|size| !too_large(size))
        && client
            .get(CONTENT_KEK_KEY)
            .await
            .is_ok_and(|held| held == envelope)
    {
        return Ok(false);
    }
    client.put(CONTENT_KEK_KEY, envelope.to_vec()).await?;
    Ok(true)
}

/// Publishes the KEK envelope from a sync pass: written only where there is
/// none. One already there that opens under `dek` is current, whatever its
/// bytes (each wrap takes a fresh nonce, so comparing bytes rewrote it on
/// every pass). One that does not open means the key was rotated since this
/// pass checked, or the object is damaged; either way this device's copy is
/// not the one to put there.
pub async fn publish_content_kek_checked(
    client: &dyn ObjectStore,
    dek: &MasterDek,
    envelope: &[u8],
) -> Result<bool, SyncError> {
    if let Some(held) = fetch_small(client, CONTENT_KEK_KEY).await? {
        if unseal(&held, dek).is_ok() {
            return Ok(false);
        }
        return Err(SyncError::Vault(
            "the silo's content key here does not open with this device's key".into(),
        ));
    }
    client.put(CONTENT_KEK_KEY, envelope.to_vec()).await?;
    Ok(true)
}

/// The KEK envelope as stored, for a device joining the silo.
///
/// `None` when the silo has none, which a joining device must treat as a
/// refusal rather than a reason to mint one: content already there is
/// wrapped under a key this device would then never have.
pub async fn fetch_content_kek(client: &dyn ObjectStore) -> Result<Option<Vec<u8>>, SyncError> {
    fetch_small(client, CONTENT_KEK_KEY).await
}

/// What a target's published KEK envelope says about this device's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KekState {
    /// The target holds none yet: a new silo, or a copy caught between the
    /// removal and the rename of an SFTP overwrite.
    Absent,
    /// It opens under this device's key.
    Current,
    /// It does not open, and neither do the records beside it. The silo's
    /// key was rotated from another device and this one was not kept: it
    /// must rejoin with a current credential, and until then must not push,
    /// because its records would be sealed under a key nobody else holds and
    /// its stale envelope would overwrite the rotated one.
    Rotated,
    /// It does not open, but records here still do. No rotation can leave a
    /// target in that state: `reseal_under_new_key` works through `ops/` and
    /// `snapshots/` first and writes this object last, so an envelope under
    /// a newer key always has records under that key beside it. The object
    /// was replaced or put back from an older copy.
    Replaced,
}

/// How many records are read before deciding. One would do on a healthy
/// target; a handful means a single damaged object does not decide it.
const KEK_WITNESSES: usize = 5;

/// Why this device's vault key does not open the silo's published KEK
/// envelope, when it does not.
///
/// Rolling that object back is cheap for anyone who can write to storage and
/// it used to read as a rotation: every device went to `needs_rejoin`, and
/// the rejoin could not succeed either, because the envelope a joining device
/// fetches is the same broken one. The whole fleet then sat behind a message
/// telling it to do something that does not work. The records are what tell
/// the two apart, and they are already there.
pub async fn kek_envelope_state(
    client: &dyn ObjectStore,
    dek: &MasterDek,
) -> Result<KekState, SyncError> {
    let Some(envelope) = fetch_content_kek(client).await? else {
        return Ok(KekState::Absent);
    };
    if unseal(&envelope, dek).is_ok() {
        return Ok(KekState::Current);
    }

    // The newest records, because a rotation that reached the envelope had
    // already been through all of them. An unreadable one is taken as a
    // rotation, which is what this build did before it asked at all.
    let mut listing = client.list(OPS_PREFIX).await?;
    listing.sort_by(|a, b| a.key.cmp(&b.key));
    let mut witnesses = 0;
    for entry in listing.iter().rev() {
        if witnesses == KEK_WITNESSES {
            break;
        }
        if entry.size > MAX_OP_BYTES {
            continue;
        }
        let Ok(sealed) = client.get(&entry.key).await else {
            continue;
        };
        if unseal(&sealed, dek).is_err() {
            return Ok(KekState::Rotated);
        }
        witnesses += 1;
    }
    // A silo with no readable record to compare against says nothing, so the
    // answer stays the careful one.
    if witnesses == 0 {
        return Ok(KekState::Rotated);
    }
    Ok(KekState::Replaced)
}

/// Whether this device's vault key still opens the silo's published KEK
/// envelope. `None` when the target holds none yet. `false` covers both ways
/// it can fail; [`kek_envelope_state`] is the one that tells them apart.
pub async fn key_still_current(
    client: &dyn ObjectStore,
    dek: &MasterDek,
) -> Result<Option<bool>, SyncError> {
    Ok(match kek_envelope_state(client, dek).await? {
        KekState::Absent => None,
        KekState::Current => Some(true),
        KekState::Rotated | KekState::Replaced => Some(false),
    })
}
/// Identifies which vault a prefix holds, for a device joining it.
pub const MANIFEST_KEY: &str = "vault.json";

/// The only object in the bucket that is not ciphertext.
///
/// It cannot be: a joining device has to know which vault it is looking at
/// *before* it can unwrap anything. A random UUID is all it discloses —
/// nothing about the contents, the owner, or how much is stored.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultManifest {
    pub vault_id: Uuid,
    /// Format version, so a future layout change can be detected rather
    /// than misread as corruption.
    pub version: u32,
}

/// The gate for the whole bucket layout, not just for `vault.json`. A
/// change that redefines what the rest of the bucket means (compaction was
/// the example) bumps this, and an older build refuses to open rather than
/// misread a partial log as the whole vault.
pub const MANIFEST_VERSION: u32 = 1;

pub async fn put_manifest(client: &dyn ObjectStore, vault_id: Uuid) -> Result<(), SyncError> {
    let manifest = VaultManifest {
        vault_id,
        version: MANIFEST_VERSION,
    };
    let bytes = serde_json::to_vec(&manifest).map_err(|e| SyncError::Vault(e.to_string()))?;
    client.put(MANIFEST_KEY, bytes).await?;
    Ok(())
}

/// Writes the manifest only when the bucket does not already say the same
/// thing: on a versioned bucket an unconditional write per pass piles up
/// thousands of versions a day of two fields.
pub async fn ensure_manifest(client: &dyn ObjectStore, vault_id: Uuid) -> Result<bool, SyncError> {
    if let Some(existing) = read_manifest(client).await?
        && existing.vault_id == vault_id
        && existing.version == MANIFEST_VERSION
    {
        return Ok(false);
    }
    put_manifest(client, vault_id).await?;
    Ok(true)
}

/// Refuses a prefix that already holds a different vault.
///
/// Checked when a target is attached, not on the sync pass: by then the pass
/// has overwritten the other vault's manifest, KEK and recovery envelope,
/// which kills that backup even though its records are all still there. An
/// empty prefix and this silo's own old backup both pass.
pub async fn refuse_foreign_vault(
    client: &dyn ObjectStore,
    vault_id: Uuid,
) -> Result<(), SyncError> {
    match read_manifest(client).await? {
        Some(manifest) if manifest.vault_id != vault_id => Err(SyncError::Vault(
            "This location already holds a different silo. \
             Pick an empty folder, or join that silo instead."
                .into(),
        )),
        _ => Ok(()),
    }
}

/// `None` when the prefix holds no vault yet — the normal state when
/// connecting a fresh bucket, not a failure.
pub async fn read_manifest(client: &dyn ObjectStore) -> Result<Option<VaultManifest>, SyncError> {
    let Some(bytes) = fetch_small(client, MANIFEST_KEY).await? else {
        return Ok(None);
    };
    let manifest: VaultManifest =
        serde_json::from_slice(&bytes).map_err(|e| SyncError::Vault(e.to_string()))?;
    if manifest.version > MANIFEST_VERSION {
        return Err(SyncError::Vault(format!(
            "this silo was written by a newer version of SilentSilo (format {}): update to open it",
            manifest.version
        )));
    }
    Ok(Some(manifest))
}

fn key_envelope_key(credential_id: &str) -> String {
    format!("{KEYS_PREFIX}{credential_id}.env")
}

/// Uploads the wrapped DEK for each enrolled security key. The one thing
/// that cannot be sealed with the vault DEK, because it is how a device
/// obtains the DEK. The wrapped key is still ciphertext, but the credential
/// id and label are visible to the provider.
/// What a publishing pass managed to do, so the caller can retire the
/// tombstones storage has now confirmed.
#[derive(Debug, Default)]
pub struct EnvelopeReport {
    /// Envelopes actually written this pass, not enrolled keys. An envelope
    /// the bucket already holds unchanged is left alone, so a steady state
    /// reports zero.
    pub published: usize,
    /// Credential ids whose envelope is now gone from storage.
    pub revoked: Vec<String>,
    /// Credential ids this target was not asked to delete, because it is
    /// append-only. Reported rather than dropped: the envelope is still up
    /// there and still usable by anything holding that key, and calling that
    /// revocation would be a lie the user would act on.
    pub withheld: Vec<String>,
}

/// Publishes the enrolled envelopes and retires the revoked ones.
/// Deliberately not a full reconciliation against a listing of `keys/`:
/// another device may have enrolled a key this one has never heard of, and
/// deleting "everything not in my list" would revoke it. Only credentials
/// this device explicitly revoked are removed, which is what the tombstone
/// is for.
pub async fn publish_key_envelopes(
    client: &dyn ObjectStore,
    keys: &StoredFidoKeys,
    allow_delete: bool,
) -> Result<EnvelopeReport, SyncError> {
    let mut report = EnvelopeReport::default();

    for key in keys.active() {
        if key.wrapped_dek.is_empty() {
            // Nothing to publish: this credential cannot unlock anything on
            // its own, so uploading it would only mislead a joining device.
            continue;
        }
        let bytes = serde_json::to_vec(key).map_err(|e| SyncError::Vault(e.to_string()))?;
        let key_path = key_envelope_key(&key.credential_id);

        // Written only when the bytes differ, compared by content: a
        // re-wrapped DEK has exactly the same length, so a size check would
        // skip the write that matters most after a rotation.
        if client
            .head(&key_path)
            .await?
            .is_some_and(|size| !too_large(size))
            && client.get(&key_path).await.is_ok_and(|held| held == bytes)
        {
            continue;
        }

        client.put(&key_path, bytes).await?;
        report.published += 1;
    }

    for credential_id in keys.revoked_ids() {
        // A credential that is both revoked and enrolled means the same key
        // was put back after being removed offline. Enrolment clears the
        // tombstone, so this should not happen; deleting here anyway would
        // undo the envelope published moments ago, which is worth one check.
        if keys.active().any(|k| k.credential_id == credential_id) {
            continue;
        }
        // On an append-only target the delete is not attempted at all.
        // Trying it and swallowing the refusal would read the same in the
        // report, and this way the caller can tell the two apart and say so.
        if !allow_delete {
            report.withheld.push(credential_id);
            continue;
        }
        client.delete(&key_envelope_key(&credential_id)).await?;
        report.revoked.push(credential_id);
    }

    Ok(report)
}

/// Every published key envelope, for a device joining the vault.
pub async fn fetch_key_envelopes(
    client: &dyn ObjectStore,
) -> Result<Vec<StoredFidoCredential>, SyncError> {
    let mut out = Vec::new();
    for entry in client.list(KEYS_PREFIX).await? {
        if too_large(entry.size) {
            eprintln!("skipping oversized key envelope {}", entry.key);
            continue;
        }
        let bytes = client.get(&entry.key).await?;
        match serde_json::from_slice::<StoredFidoCredential>(&bytes) {
            Ok(credential) => out.push(credential),
            // One unreadable envelope should not stop a device joining with
            // a key whose envelope is fine.
            Err(e) => eprintln!("skipping unreadable key envelope {}: {e}", entry.key),
        }
    }
    Ok(out)
}

/// Removes a key's envelope so it can no longer unlock the vault from any
/// device.
///
/// This is what revocation means once envelopes are shared: deleting the
/// local record alone would leave the bucket copy usable by anything that
/// still has the physical key.
pub async fn revoke_key_envelope(
    client: &dyn ObjectStore,
    credential_id: &str,
) -> Result<(), SyncError> {
    client.delete(&key_envelope_key(credential_id)).await?;
    Ok(())
}

impl From<CoreError> for SyncError {
    fn from(err: CoreError) -> Self {
        SyncError::Vault(err.to_string())
    }
}

impl From<StoreError> for SyncError {
    fn from(err: StoreError) -> Self {
        SyncError::Storage(err.to_string())
    }
}

impl From<silentsilo_crypto::CryptoError> for SyncError {
    fn from(err: silentsilo_crypto::CryptoError) -> Self {
        SyncError::Crypto(err.to_string())
    }
}

// ── The recovery envelope ───────────────────────────────────────────

/// Where the recovery envelope lives in the bucket.
///
/// Beside the key envelopes rather than inside `keys/`, so listing enrolled
/// security keys never has to filter it out.
pub const RECOVERY_KEY: &str = "recovery.env";

/// Publishes the recovery envelope so the code works from any device.
///
/// This is the difference between a recovery code and a spare key: the code
/// has to work on a machine that has never seen this vault, which is the
/// situation someone is in precisely when they need it. Keeping it local
/// would make it useless in the one case it exists for.
pub async fn push_recovery_envelope(
    client: &dyn ObjectStore,
    envelope: &RecoveryEnvelope,
) -> Result<(), SyncError> {
    let bytes = serde_json::to_vec(envelope).map_err(|e| SyncError::Vault(e.to_string()))?;
    client.put(RECOVERY_KEY, bytes).await?;
    Ok(())
}

/// Publishes the recovery envelope if this target does not already have
/// it. Called on every pass so a target added after the code was generated
/// still receives it. Compared by content, so a regenerated envelope
/// replaces the old one instead of being skipped.
///
/// A newer envelope already there is left alone. Every device republishes
/// its own copy on every pass, and one that had not yet heard of a new code
/// put the old one back: the code the user had just written down stopped
/// working, and the one they threw away worked again.
pub async fn ensure_recovery_envelope(
    client: &dyn ObjectStore,
    envelope: &RecoveryEnvelope,
) -> Result<bool, SyncError> {
    let bytes = serde_json::to_vec(envelope).map_err(|e| SyncError::Vault(e.to_string()))?;
    if client
        .head(RECOVERY_KEY)
        .await?
        .is_some_and(|size| !too_large(size))
        && let Ok(held) = client.get(RECOVERY_KEY).await
    {
        if held == bytes {
            return Ok(false);
        }
        if serde_json::from_slice::<RecoveryEnvelope>(&held)
            .is_ok_and(|stored| stored.created_at > envelope.created_at)
        {
            return Ok(false);
        }
    }
    client.put(RECOVERY_KEY, bytes).await?;
    Ok(true)
}

/// The envelope this target holds, when it is newer than `local`: a code
/// made on another device, which this one should keep instead of its own.
pub async fn newer_recovery_envelope(
    client: &dyn ObjectStore,
    local: &RecoveryEnvelope,
) -> Result<Option<RecoveryEnvelope>, SyncError> {
    Ok(fetch_recovery_envelope(client)
        .await?
        .filter(|stored| stored.created_at > local.created_at))
}

/// What a pass decided about the silo's recovery envelope.
#[derive(Debug, Default, Clone)]
pub struct RecoverySettlement {
    /// The envelope this device holds afterwards, which is the one to
    /// publish. `None` when the silo has no recovery code.
    pub envelope: Option<RecoveryEnvelope>,
    /// A newer envelope in a target was left where it was because it carries
    /// no tag this silo's KEK verifies, while the local one does. Either a
    /// client older than core 1.6.0 rewrote it, or someone with write access
    /// to storage did. The two are indistinguishable, so the local envelope
    /// is kept and the caller says so.
    pub refused_unauthenticated: bool,
}

/// Brings this device's recovery envelope in line with storage before a push,
/// and returns the one to publish.
///
/// A code turned off on another device stays off: an envelope made at or
/// before the marker is dropped here and removed from every copy that
/// allows it, so a device that had not heard does not put it back. A code
/// made on another device since is kept here instead of this device's older
/// one. `targets` pairs each store with whether it allows deletes.
///
/// What decides adoption is the envelope's tag, not its date. `created_at`
/// is chosen by whoever wrote the object, so on its own it let a writer in
/// the bucket bring back a code that had been turned off, or replace the
/// envelope on every device with one that opens nothing. A tag needs the
/// content KEK, which storage never sees. An untagged envelope is adopted
/// only while this device's own is untagged too, which is a silo where no
/// device has run core 1.6.0 yet and nothing has been lost either way.
pub async fn settle_recovery_envelope(
    targets: &[(&dyn ObjectStore, bool)],
    kek: &ContentKek,
    vault_root: &std::path::Path,
) -> RecoverySettlement {
    let mut settlement = RecoverySettlement::default();
    let mut recovery = silentsilo_vault::load_recovery_envelope(vault_root).ok();

    let mut disabled_at: Option<i64> = None;
    for (store, _) in targets {
        if let Ok(Some(at)) = revoked_at(*store, kek, RECOVERY_MARKER_ID).await {
            disabled_at = Some(disabled_at.map_or(at, |d| d.max(at)));
        }
    }
    if let Some(off) = disabled_at {
        if recovery.as_ref().is_some_and(|r| r.created_at <= off) {
            silentsilo_vault::clear_recovery_envelope(vault_root);
            recovery = None;
        }
        for (store, allows_delete) in targets {
            if *allows_delete
                && let Ok(Some(held)) = fetch_recovery_envelope(*store).await
                && held.created_at <= off
            {
                let _ = revoke_recovery_envelope(*store).await;
            }
        }
    }

    if let Some(local) = recovery.as_ref() {
        // A silo whose local envelope carries no tag has not met core 1.6.0
        // yet, so an untagged one in storage is the ordinary case there.
        let require_tag = local.is_authentic(kek);
        let mut newest: Option<RecoveryEnvelope> = None;
        for (store, _) in targets {
            if let Ok(Some(found)) = newer_recovery_envelope(*store, local).await
                && newest
                    .as_ref()
                    .is_none_or(|n| found.created_at > n.created_at)
                && disabled_at.is_none_or(|off| found.created_at > off)
            {
                if require_tag && !found.is_authentic(kek) {
                    settlement.refused_unauthenticated = true;
                    continue;
                }
                newest = Some(found);
            }
        }
        if let Some(newer) = newest
            && silentsilo_vault::save_recovery_envelope(vault_root, &newer).is_ok()
        {
            recovery = Some(newer);
        }
    }

    // The upgrade path for a silo written before core 1.6.0: this device
    // tags the envelope it already holds, which is as trustworthy as the
    // disk it sits on, so the code on paper stays the one that works. Only
    // a missing tag is filled in; a tag that does not verify is left alone
    // and reported, because this device is not the one to bless it.
    if let Some(envelope) = recovery.as_mut()
        && envelope.auth.is_none()
    {
        envelope.authenticate(kek);
        let _ = silentsilo_vault::save_recovery_envelope(vault_root, envelope);
    }

    settlement.envelope = recovery;
    settlement
}

/// `None` when no recovery code has been set up for this vault.
pub async fn fetch_recovery_envelope(
    client: &dyn ObjectStore,
) -> Result<Option<RecoveryEnvelope>, SyncError> {
    let Some(bytes) = fetch_small(client, RECOVERY_KEY).await? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| SyncError::Vault(e.to_string()))
}

/// Removes the published envelope, so the written-down code stops working
/// everywhere rather than only on the device that revoked it.
pub async fn revoke_recovery_envelope(client: &dyn ObjectStore) -> Result<(), SyncError> {
    client.delete(RECOVERY_KEY).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_carries_its_lamport_value() {
        assert_eq!(
            lamport_from_key("ops/00000000000000000042-abc-def.op"),
            Some(42)
        );
    }

    #[test]
    fn a_key_without_the_prefix_is_not_ours() {
        assert_eq!(lamport_from_key("blobs/00000000000000000042-x.sslo"), None);
    }

    #[test]
    fn an_unparseable_key_yields_nothing_rather_than_a_wrong_number() {
        // Callers treat `None` as "fetch it anyway", so guessing here would
        // mean quietly skipping records.
        assert_eq!(lamport_from_key("ops/not-a-number-x-y.op"), None);
    }

    #[test]
    fn padding_keeps_ordering_lexicographic_across_magnitudes() {
        let mut keys = [
            "ops/00000000000000000100-a-b.op",
            "ops/00000000000000000002-a-b.op",
            "ops/00000000000000000011-a-b.op",
        ];
        keys.sort();
        let values: Vec<u64> = keys.iter().filter_map(|k| lamport_from_key(k)).collect();
        assert_eq!(values, vec![2, 11, 100]);
    }

    #[test]
    fn a_key_carries_its_op_id() {
        // Through the same formatter that writes real keys, so the parser
        // cannot drift from the writer.
        let record = silentsilo_vfs::OpRecord::authored(
            Uuid::new_v4(),
            42,
            Uuid::new_v4(),
            1_700_000_000,
            0,
            None,
            silentsilo_vfs::VaultOp::TrashFile { id: Uuid::new_v4() },
        );
        assert_eq!(op_id_from_key(&op_key(&record)), Some(record.op_id));
    }

    #[test]
    fn a_mangled_key_yields_no_op_id_rather_than_a_wrong_one() {
        assert_eq!(op_id_from_key("ops/short.op"), None);
        assert_eq!(op_id_from_key("blobs/x.sslo"), None);
        // Multibyte tail: must not panic on a byte slice boundary.
        assert_eq!(op_id_from_key(&format!("ops/{}.op", "ă".repeat(40))), None);
    }

    fn record_at(lamport: u64) -> OpRecord {
        silentsilo_vfs::OpRecord::authored(
            Uuid::new_v4(),
            lamport,
            Uuid::new_v4(),
            1_700_000_000,
            0,
            None,
            silentsilo_vfs::VaultOp::TrashFile { id: Uuid::new_v4() },
        )
    }

    fn unreadable_at(lamport: Option<u64>) -> UnreadableOp {
        UnreadableOp {
            key: "ops/broken.op".into(),
            op_id: None,
            lamport,
            error: "test".into(),
        }
    }

    #[test]
    fn replay_stops_below_the_first_unreadable_object() {
        let records = vec![record_at(1), record_at(5), record_at(9)];
        let (usable, held) = usable_prefix(records, &[unreadable_at(Some(5))]);
        assert_eq!(
            usable.iter().map(|r| r.lamport).collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(held, 2, "records at and above the hole wait");
    }

    #[test]
    fn an_unreadable_object_with_no_lamport_holds_nothing_back() {
        let records = vec![record_at(1), record_at(2)];
        let (usable, held) = usable_prefix(records, &[unreadable_at(None)]);
        assert_eq!(usable.len(), 2);
        assert_eq!(held, 0);
    }

    #[test]
    fn nothing_unreadable_means_everything_applies() {
        let (usable, held) = usable_prefix(vec![record_at(3)], &[]);
        assert_eq!(usable.len(), 1);
        assert_eq!(held, 0);
    }
}

// ── One target, everything it is owed ───────────────────────────────

/// What a copy needs before it can be joined from, and what it is owed.
///
/// Gathered into one struct so the pass below can be called from a test as
/// easily as from the app. The bug this exists to prevent lived in the
/// orchestration rather than in any function it calls, and orchestration
/// that only the app can run is orchestration nothing checks.
pub struct TargetPush<'a> {
    pub id: Uuid,
    pub store: &'a dyn ObjectStore,
    /// False for an append-only copy, which is never sent a delete.
    pub allows_delete: bool,
    /// Records this copy does not have, from `pending_ops_for`.
    pub owed: &'a [OpRecord],
}

/// Everything a silo has to hand a copy, besides the records themselves.
pub struct SiloState<'a> {
    pub vault_id: Uuid,
    pub dek: &'a MasterDek,
    /// Wrapped under the DEK before it goes up.
    pub kek_envelope: &'a [u8],
    pub recovery: Option<&'a RecoveryEnvelope>,
    pub keys: Option<&'a StoredFidoKeys>,
    /// The snapshot a compacted log starts from, if there is one.
    pub base: Option<&'a Snapshot>,
    /// Where the blobs live on this machine.
    pub vault_root: &'a Path,
}

/// What one target's pass managed.
#[derive(Debug, Default, Clone)]
pub struct TargetPushOutcome {
    pub ops_pushed: usize,
    pub blobs_uploaded: usize,
    pub blobs_failed: usize,
    /// Credential ids whose published envelope this pass removed, so the
    /// caller can drop the tombstones storage has now confirmed.
    pub revoked: Vec<String>,
    /// Why this copy got nothing further. `None` means it kept up.
    pub failed: Option<String>,
}

/// Sends one copy everything it is owed, in the order a joining device
/// needs it.
///
/// The order is the part worth being careful about. What a device needs to
/// recognise and open the silo goes first (manifest, content key, recovery
/// code, key envelopes), then the base snapshot, and only then the records:
/// a log that starts part way through, with no snapshot in front of it,
/// reads to a joining device as a smaller vault rather than an incomplete
/// copy. Content goes last, because a record naming a blob that has not
/// arrived is self-correcting on the next pass while the reverse looks like
/// an orphan.
///
/// The first failure stops the rest for this copy: everything after it
/// would fail the same way, and one reason is more use than six.
pub async fn push_everything_to(
    target: &TargetPush<'_>,
    silo: &SiloState<'_>,
) -> TargetPushOutcome {
    push_everything_to_reporting(target, silo, &mut |_| {}).await
}

/// Where a push to one target is, for a status line.
#[derive(Debug, Clone, Copy)]
pub enum PushStep {
    /// About to send record `done + 1` of `total`.
    Ops { done: usize, total: usize },
    /// About to check, and if missing send, this blob.
    Blob {
        done: usize,
        total: usize,
        blob_id: Uuid,
    },
}

/// [`push_everything_to`], reporting each record and blob as it goes.
pub async fn push_everything_to_reporting(
    target: &TargetPush<'_>,
    silo: &SiloState<'_>,
    progress: &mut (dyn FnMut(PushStep) + Send),
) -> TargetPushOutcome {
    let mut outcome = TargetPushOutcome::default();
    macro_rules! attempt {
        ($e:expr) => {
            if let Err(e) = $e.await {
                outcome.failed = Some(e.to_string());
                return outcome;
            }
        };
    }

    attempt!(ensure_manifest(target.store, silo.vault_id));
    attempt!(publish_content_kek_checked(
        target.store,
        silo.dek,
        silo.kek_envelope
    ));
    if let Some(recovery) = silo.recovery {
        attempt!(ensure_recovery_envelope(target.store, recovery));
    }
    if let Some(base) = silo.base {
        attempt!(publish_base_if_missing(target.store, silo.dek, base));
    }
    if let Some(keys) = silo.keys {
        match publish_key_envelopes(target.store, keys, target.allows_delete).await {
            Ok(report) => outcome.revoked = report.revoked,
            Err(e) => {
                outcome.failed = Some(e.to_string());
                return outcome;
            }
        }
    }

    match push_ops_reporting(target.store, silo.dek, target.owed, &mut |done, total| {
        progress(PushStep::Ops { done, total })
    })
    .await
    {
        Ok(count) => outcome.ops_pushed = count,
        Err(e) => {
            outcome.failed = Some(e.to_string());
            return outcome;
        }
    }

    let pending = list_undelivered_blob_ids(silo.vault_root, target.id);
    match push_blobs_reporting(
        target.store,
        silo.vault_root,
        target.id,
        &pending,
        &mut |done, total, blob_id| {
            progress(PushStep::Blob {
                done,
                total,
                blob_id,
            })
        },
    )
    .await
    {
        Ok(blobs) => {
            outcome.blobs_uploaded = blobs.uploaded;
            outcome.blobs_failed = blobs.failed.len();
        }
        Err(e) => outcome.failed = Some(e.to_string()),
    }

    outcome
}
