//! Reading a silo's activity log: every segment on the copies and on this
//! computer, opened with the log's private key and checked for holes.
//!
//! A segment never changes once written, so one fetched is kept beside the
//! silo (`audit-cache/<device>/<seq>.seg`, the storage layout) and not
//! fetched again. It is sealed: the cache holds nothing a copy does not.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::Serialize;
use silentsilo_audit::{
    AUDIT_PREFIX, BY_SILO, Event, MAX_SEGMENT_BYTES, Segment, check_chain, counter_gaps, describe,
    open_event, parse_segment_key,
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

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub device: Uuid,
    /// The code's name, as this build knows it.
    pub what: String,
    #[serde(flatten)]
    pub event: Event,
}

/// One device's part of the log, and what is missing from it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DeviceTrail {
    pub device: Uuid,
    pub events: usize,
    /// Runs of event numbers that should be there and are not, inclusive.
    pub missing_events: Vec<(u64, u64)>,
    pub missing_segments: Vec<u64>,
    /// Segments that do not follow the one before them.
    pub broken_segments: Vec<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LogRead {
    /// Newest first.
    pub entries: Vec<LogEntry>,
    pub devices: Vec<DeviceTrail>,
    /// Records that do not open with this log's key.
    pub unreadable: usize,
    /// Copies that could not be read, by name: what only they hold is not
    /// here.
    pub copies_unread: Vec<String>,
}

/// Reads the open silo's log from this computer and every copy.
pub async fn read_audit_log(
    state: &AppState,
    host: &dyn Host,
    silo: &SiloEntry,
    reader: Reader,
) -> Result<LogRead, String> {
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
    let private = match &reader {
        Reader::Silo => key.unwrap_with(BY_SILO, kek.as_bytes()),
        Reader::Organisation {
            credential_id,
            wrap_key,
        } => key.unwrap_with(credential_id, wrap_key),
    }
    .map_err(|_| "This key cannot read the activity log.".to_string())?;

    let cache = root.join(CACHE_DIR);
    let mut segments: BTreeMap<(Uuid, u64), Segment> = BTreeMap::new();
    for segment in read_cache(&cache) {
        segments.insert((segment.device, segment.seq), segment);
    }
    for segment in outbox {
        segments.insert((segment.device, segment.seq), segment);
    }

    let mut copies_unread = Vec::new();
    for target in host.targets(silo.id) {
        let store = match target.config.open() {
            Ok(store) => store,
            Err(_) => {
                copies_unread.push(target.label.clone());
                continue;
            }
        };
        let label = if target.label.is_empty() {
            store.describe()
        } else {
            target.label.clone()
        };
        let listed = match store.list(AUDIT_PREFIX).await {
            Ok(listed) => listed,
            Err(_) => {
                copies_unread.push(label);
                continue;
            }
        };
        let mut failed = false;
        for object in listed {
            let Some((device, seq)) = parse_segment_key(&object.key) else {
                continue;
            };
            if segments.contains_key(&(device, seq)) || object.size as u64 > MAX_SEGMENT_BYTES {
                continue;
            }
            let Ok(bytes) = store.get(&object.key).await else {
                failed = true;
                continue;
            };
            // One that does not parse, or names another place, is left out:
            // the chain check then reports it missing.
            if let Ok(segment) = Segment::from_bytes(&bytes)
                && segment.device == device
                && segment.seq == seq
            {
                keep(&cache, &object.key, &bytes);
                segments.insert((device, seq), segment);
            }
        }
        if failed {
            copies_unread.push(label);
        }
    }

    let mut by_device: BTreeMap<Uuid, Vec<Segment>> = BTreeMap::new();
    for ((device, _), segment) in segments {
        by_device.entry(device).or_default().push(segment);
    }
    by_device.entry(this_device).or_default();

    let mut read = LogRead {
        copies_unread,
        ..LogRead::default()
    };
    for (device, segments) in by_device {
        let from = segments.iter().map(|s| s.seq).min().unwrap_or(0);
        let chain = check_chain(&segments, from);
        let mut events = Vec::new();
        let records = segments.iter().flat_map(|s| s.records.iter());
        let unsent = pending
            .iter()
            .filter(|_| device == this_device)
            .map(|(_, record)| record);
        let mut seen = HashSet::new();
        for record in records.chain(unsent) {
            match open_event(&private, device, record) {
                Ok(event) => {
                    if seen.insert(event.i) {
                        events.push(event);
                    }
                }
                Err(_) => read.unreadable += 1,
            }
        }
        if events.is_empty() && segments.is_empty() {
            continue;
        }
        let first = events.iter().map(|e| e.i).min().unwrap_or(0);
        read.devices.push(DeviceTrail {
            device,
            events: events.len(),
            missing_events: counter_gaps(&events, first),
            missing_segments: chain.missing,
            broken_segments: chain.broken,
        });
        read.entries
            .extend(events.into_iter().map(|event| LogEntry {
                device,
                what: describe(event.c),
                event,
            }));
    }
    read.entries
        .sort_by_key(|e| std::cmp::Reverse((e.event.t, e.event.i)));
    Ok(read)
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
