//! Reading a silo's activity log: every segment on the copies and on this
//! computer, opened with the log's private key and checked for holes.
//!
//! A segment never changes once written, so one fetched is kept beside the
//! silo (`audit-cache/<device>/<seq>.seg`, the storage layout) and not
//! fetched again. It is sealed: the cache holds nothing a copy does not.

use std::collections::{BTreeMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

pub use silentsilo_audit::reading::{DeviceTrail, LogEntry, LogRead};
use silentsilo_audit::{
    AUDIT_PREFIX, BY_SILO, KeyId, MAX_SEGMENT_BYTES, Segment, key_id, parse_segment_key,
};
use silentsilo_vault::SiloEntry;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{AppState, Host};

pub const CACHE_DIR: &str = "audit-cache";

/// Who is reading, which decides the wrapping the private key is taken from.
pub enum Reader {
    /// Whoever opened a personal silo: the key is under its content key.
    Silo,
    /// The holder of an organisation key: its credential id, and the wrap
    /// key its touch gave.
    Organisation {
        credential_id: String,
        wrap_key: Zeroizing<[u8; 32]>,
    },
}

/// How long one copy may take to give its part of the log. One that does
/// not answer in time is named in `copies_unread` rather than holding the
/// page; what it gave before then is cached, so the next read carries on.
pub const COPY_READ_LIMIT: Duration = Duration::from_secs(30);

/// What a read starts from: this computer's part of the log and the keys.
struct Local {
    kek: silentsilo_crypto::ContentKek,
    cache: PathBuf,
    keys: Vec<(KeyId, Zeroizing<Vec<u8>>)>,
    segments: BTreeMap<(Uuid, u64), Segment>,
    pending: Vec<(Uuid, Vec<u8>)>,
}

/// Reads the open silo's log from this computer only: what was fetched
/// before and what is waiting to go out. No storage is touched, so it
/// answers at once; the copies are read by [`read_audit_log`].
pub fn read_audit_log_local(
    state: &AppState,
    silo: &SiloEntry,
    reader: &Reader,
) -> Result<LogRead, String> {
    let local = gather_local(state, silo, reader)?;
    finish(state, silo, local, Vec::new())
}

/// Reads the open silo's log from this computer and every copy, the
/// copies together, each within [`COPY_READ_LIMIT`].
pub async fn read_audit_log(
    state: &AppState,
    host: &dyn Host,
    silo: &SiloEntry,
    reader: &Reader,
) -> Result<LogRead, String> {
    read_audit_log_within(state, host, silo, reader, COPY_READ_LIMIT).await
}

/// [`read_audit_log`] with each copy given `limit`.
pub async fn read_audit_log_within(
    state: &AppState,
    host: &dyn Host,
    silo: &SiloEntry,
    reader: &Reader,
    limit: Duration,
) -> Result<LogRead, String> {
    let mut local = gather_local(state, silo, reader)?;
    let held: HashSet<(Uuid, u64)> = local.segments.keys().copied().collect();
    let silo_keys = matches!(reader, Reader::Silo).then_some(&local.kek);
    let reads: Vec<_> = host
        .targets(silo.id)
        .into_iter()
        .map(|target| read_copy(target, &held, &local.cache, silo_keys, limit))
        .collect();
    let copies = join_all(reads).await;

    let mut copies_unread = Vec::new();
    for copy in copies {
        for (id, private) in copy.keys {
            if !local.keys.iter().any(|(known, _)| *known == id) {
                local.keys.push((id, private));
            }
        }
        for segment in copy.segments {
            local
                .segments
                .entry((segment.device, segment.seq))
                .or_insert(segment);
        }
        if !copy.complete {
            copies_unread.push(copy.label);
        }
    }
    finish(state, silo, local, copies_unread)
}

fn gather_local(state: &AppState, silo: &SiloEntry, reader: &Reader) -> Result<Local, String> {
    let (root, kek, this_device) = {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        let session = sessions.get(&silo.id).ok_or("That silo is not open.")?;
        (
            session.paths.root.clone(),
            session.kek.clone(),
            silentsilo_vfs::device_id(&session.conn).map_err(|e| e.to_string())?,
        )
    };
    let (key, outbox, pending) = {
        let spool = state.audit_spool(silo.id)?;
        let key = spool
            .key()
            .map_err(|e| e.to_string())?
            .ok_or("This silo keeps no activity log.")?;
        (
            key,
            spool.outbox().map_err(|e| e.to_string())?,
            spool.pending().map_err(|e| e.to_string())?,
        )
    };
    let private = match reader {
        Reader::Silo => key.unwrap_with(BY_SILO, kek.as_bytes()),
        Reader::Organisation {
            credential_id,
            wrap_key,
        } => key.unwrap_with(credential_id, wrap_key),
    }
    .map_err(|_| "This key cannot read the activity log.".to_string())?;
    let pinned_id = key
        .public()
        .map(|public| key_id(&public))
        .map_err(|_| "The activity log's key is damaged.".to_string())?;

    let cache = root.join(CACHE_DIR);
    let mut segments: BTreeMap<(Uuid, u64), Segment> = BTreeMap::new();
    for segment in read_cache(&cache) {
        segments.insert((segment.device, segment.seq), segment);
    }
    for segment in outbox {
        segments.insert((segment.device, segment.seq), segment);
    }
    let pending = pending
        .into_iter()
        .map(|(_, record)| (this_device, record))
        .collect();
    Ok(Local {
        kek,
        cache,
        // A personal log may have had an earlier key, from a device that
        // started it before it heard of this one: its records open with
        // it. Those keys live on the copies.
        keys: vec![(pinned_id, private)],
        segments,
        pending,
    })
}

/// One copy's part of the log.
struct CopyRead {
    label: String,
    segments: Vec<Segment>,
    keys: Vec<(KeyId, Zeroizing<Vec<u8>>)>,
    /// False when the copy did not open, list, answer every fetch, or
    /// answer in time.
    complete: bool,
}

async fn read_copy(
    target: silentsilo_vault::BackupTarget,
    held: &HashSet<(Uuid, u64)>,
    cache: &Path,
    silo_keys: Option<&silentsilo_crypto::ContentKek>,
    limit: Duration,
) -> CopyRead {
    let store = match target.config.open() {
        Ok(store) => store,
        Err(_) => {
            return CopyRead {
                // Unnamed and not opened: nothing better to call it by.
                label: if target.label.is_empty() {
                    "a copy".to_string()
                } else {
                    target.label.clone()
                },
                segments: Vec::new(),
                keys: Vec::new(),
                complete: false,
            };
        }
    };
    let label = if target.label.is_empty() {
        store.describe()
    } else {
        target.label.clone()
    };
    let mut segments = Vec::new();
    let mut keys = Vec::new();
    // Filled as it goes, so a copy cut off by the limit still gives what
    // it fetched before then.
    let complete = tokio::time::timeout(limit, async {
        let Ok(listed) = store.list(AUDIT_PREFIX).await else {
            return false;
        };
        if let Some(kek) = silo_keys
            && let Ok(more) = silentsilo_sync::audit_log::read_silo_keys(&*store, kek).await
        {
            keys.extend(more);
        }
        let mut complete = true;
        for object in listed {
            let Some((device, seq)) = parse_segment_key(&object.key) else {
                continue;
            };
            if held.contains(&(device, seq)) || object.size as u64 > MAX_SEGMENT_BYTES {
                continue;
            }
            let Ok(bytes) = store.get(&object.key).await else {
                complete = false;
                continue;
            };
            // One that does not parse, or names another place, is left out:
            // the chain check then reports it missing.
            if let Ok(segment) = Segment::from_bytes(&bytes)
                && segment.device == device
                && segment.seq == seq
            {
                keep(cache, &object.key, &bytes);
                segments.push(segment);
            }
        }
        complete
    })
    .await
    .unwrap_or(false);
    CopyRead {
        label,
        segments,
        keys,
        complete,
    }
}

fn finish(
    state: &AppState,
    silo: &SiloEntry,
    local: Local,
    copies_unread: Vec<String>,
) -> Result<LogRead, String> {
    // What was opened before is opened again only if its bytes changed.
    let mut opened = state
        .audit_opened
        .lock()
        .map_err(|e| e.to_string())?
        .remove(&silo.id)
        .unwrap_or_default();
    let held: Vec<(KeyId, &[u8])> = local.keys.iter().map(|(id, k)| (*id, &k[..])).collect();
    let mut read = silentsilo_audit::reading::read_log_with(
        local.segments.into_values(),
        &local.pending,
        &held,
        &mut opened,
    );
    read.copies_unread = copies_unread;
    // Put back only while the silo is still open, checked and kept under
    // the sessions lock: a close removes the session first and forgets the
    // read after, so a lock during the read leaves nothing in memory.
    if let Ok(sessions) = state.sessions.lock()
        && sessions.contains_key(&silo.id)
        && let Ok(mut held) = state.audit_opened.lock()
    {
        held.insert(silo.id, opened);
    }
    Ok(read)
}

/// A future being polled and, once it is done, what it gave.
type Slot<F> = (Pin<Box<F>>, Option<<F as Future>::Output>);

/// Polls every future on this task until all are done, in order.
async fn join_all<F: Future>(futures: Vec<F>) -> Vec<F::Output> {
    let mut slots: Vec<Slot<F>> = futures.into_iter().map(|f| (Box::pin(f), None)).collect();
    std::future::poll_fn(|cx| {
        let mut done = true;
        for (future, out) in slots.iter_mut() {
            if out.is_none() {
                match future.as_mut().poll(cx) {
                    Poll::Ready(value) => *out = Some(value),
                    Poll::Pending => done = false,
                }
            }
        }
        if done { Poll::Ready(()) } else { Poll::Pending }
    })
    .await;
    slots.into_iter().filter_map(|(_, out)| out).collect()
}

/// Segments fetched before. One that will not read is fetched again.
fn read_cache(cache: &Path) -> Vec<Segment> {
    let mut out = Vec::new();
    let Ok(devices) = std::fs::read_dir(cache) else {
        return out;
    };
    for device in devices.flatten() {
        let Ok(files) = std::fs::read_dir(device.path()) else {
            continue;
        };
        for file in files.flatten() {
            let name = format!(
                "{AUDIT_PREFIX}{}/{}",
                device.file_name().to_string_lossy(),
                file.file_name().to_string_lossy()
            );
            let Some((id, seq)) = parse_segment_key(&name) else {
                continue;
            };
            if let Ok(bytes) = std::fs::read(file.path())
                && let Ok(segment) = Segment::from_bytes(&bytes)
                && segment.device == id
                && segment.seq == seq
            {
                out.push(segment);
            }
        }
    }
    out
}

/// Keeps a fetched segment. Best effort: without it, the next read fetches
/// it again.
fn keep(cache: &Path, key: &str, bytes: &[u8]) {
    let Some(relative) = key.strip_prefix(AUDIT_PREFIX) else {
        return;
    };
    let path = cache.join(relative);
    if let Some(dir) = path.parent()
        && std::fs::create_dir_all(dir).is_ok()
    {
        let _ = std::fs::write(path, bytes);
    }
}
