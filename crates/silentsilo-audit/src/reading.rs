//! Reading a log once its segments are gathered: every record opened with
//! the log's private key, each device's run checked for holes, and the
//! result written out as CSV or JSON lines.
//!
//! Gathering is the caller's: the app reads every copy and this computer's
//! queue, the extract tool reads one backup folder. What they make of the
//! segments is this one function, so the two cannot disagree.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;
use uuid::Uuid;

use crate::{Event, KeyId, Segment, check_chain, counter_gaps, describe, open_event, record_key};

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
    /// here. Filled by the caller, which is the one that reached for them.
    pub copies_unread: Vec<String>,
}

/// Records already opened, by the segment they came from, so a later read
/// of the same log opens only what is new. A segment never changes once
/// written, and each is matched by its bytes as well. Kept by the caller in
/// memory while the silo is open, never written anywhere: it is the log in
/// clear.
#[derive(Default)]
pub struct Opened {
    /// Which keys opened them: another reader starts over.
    key: Option<[u8; 32]>,
    segments: HashMap<(Uuid, u64), OpenedSegment>,
}

/// A segment's bytes, by hash, and its records opened, `None` for one that
/// did not open.
type OpenedSegment = ([u8; 32], Vec<Option<Event>>);

impl Opened {
    /// How many segments are held, for tests and diagnostics.
    pub fn segments(&self) -> usize {
        self.segments.len()
    }
}

/// The private keys a reader holds, each by the id records name it with.
/// A personal log can have had more than one: two devices that started it
/// at once, before either heard of the other's.
pub type ReadKeys<'a> = [(KeyId, &'a [u8])];

/// Opens `record` with the key it names, if the reader holds it.
fn open_with(keys: &ReadKeys, device: Uuid, record: &[u8]) -> Option<Event> {
    let id = record_key(record).ok()?;
    let (_, private) = keys.iter().find(|(held, _)| *held == id)?;
    open_event(private, device, record).ok()
}

/// Opens every record of `jobs`, each a device and its records, on all the
/// cores there are. One record is about 150 microseconds of X25519 and
/// AES-GCM, so a year of a busy log takes seconds on one core.
fn open_all(keys: &ReadKeys, jobs: &[(Uuid, &[Vec<u8>])]) -> Vec<Vec<Option<Event>>> {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let total: usize = jobs.iter().map(|(_, r)| r.len()).sum();
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(total.div_ceil(256).max(1));
    let results: Vec<Mutex<Vec<Option<Event>>>> =
        jobs.iter().map(|_| Mutex::new(Vec::new())).collect();
    let next = AtomicUsize::new(0);
    let work = || {
        loop {
            let job = next.fetch_add(1, Ordering::Relaxed);
            let Some((device, records)) = jobs.get(job) else {
                return;
            };
            let opened: Vec<Option<Event>> = records
                .iter()
                .map(|record| open_with(keys, *device, record))
                .collect();
            if let Ok(mut slot) = results[job].lock() {
                *slot = opened;
            }
        }
    };
    if threads <= 1 {
        work();
    } else {
        std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(work);
            }
        });
    }
    results
        .into_iter()
        .map(|slot| slot.into_inner().unwrap_or_default())
        .collect()
}

/// Opens and checks `segments`, from anywhere and in any order, one per
/// device and number. `unsent` are records not in a segment yet, by device.
pub fn read_log(
    segments: impl IntoIterator<Item = Segment>,
    unsent: &[(Uuid, Vec<u8>)],
    keys: &ReadKeys,
) -> LogRead {
    read_log_with(segments, unsent, keys, &mut Opened::default())
}

/// [`read_log`], opening only the segments `opened` does not hold yet, and
/// keeping those it opens there.
pub fn read_log_with(
    segments: impl IntoIterator<Item = Segment>,
    unsent: &[(Uuid, Vec<u8>)],
    keys: &ReadKeys,
    opened: &mut Opened,
) -> LogRead {
    let key = {
        let mut held: Vec<&(KeyId, &[u8])> = keys.iter().collect();
        held.sort_by_key(|(id, _)| *id);
        let mut hasher = blake3::Hasher::new();
        for (id, private) in held {
            hasher.update(id);
            hasher.update(private);
        }
        *hasher.finalize().as_bytes()
    };
    if opened.key != Some(key) {
        opened.segments.clear();
        opened.key = Some(key);
    }

    let mut by_device: BTreeMap<Uuid, BTreeMap<u64, Segment>> = BTreeMap::new();
    for segment in segments {
        by_device
            .entry(segment.device)
            .or_default()
            .insert(segment.seq, segment);
    }
    for (device, _) in unsent {
        by_device.entry(*device).or_default();
    }

    // What is new: segments not opened before, or whose bytes differ.
    let hashes: HashMap<(Uuid, u64), [u8; 32]> = by_device
        .values()
        .flat_map(|segments| segments.values())
        .map(|s| ((s.device, s.seq), *blake3::hash(&s.to_bytes()).as_bytes()))
        .collect();
    let fresh: Vec<&Segment> = by_device
        .values()
        .flat_map(|segments| segments.values())
        .filter(|s| {
            opened
                .segments
                .get(&(s.device, s.seq))
                .is_none_or(|(hash, _)| *hash != hashes[&(s.device, s.seq)])
        })
        .collect();
    let jobs: Vec<(Uuid, &[Vec<u8>])> = fresh
        .iter()
        .map(|s| (s.device, s.records.as_slice()))
        .collect();
    for (segment, events) in fresh.iter().zip(open_all(keys, &jobs)) {
        let id = (segment.device, segment.seq);
        opened.segments.insert(id, (hashes[&id], events));
    }

    let mut read = LogRead::default();
    for (device, segments) in by_device {
        let segments: Vec<Segment> = segments.into_values().collect();
        let from = segments.iter().map(|s| s.seq).min().unwrap_or(0);
        let chain = check_chain(&segments, from);
        let mut events = Vec::new();
        let mut seen = HashSet::new();
        let pending: Vec<Option<Event>> = unsent
            .iter()
            .filter(|(d, _)| *d == device)
            .map(|(_, record)| open_with(keys, device, record))
            .collect();
        let held = segments
            .iter()
            .flat_map(|s| opened.segments[&(s.device, s.seq)].1.iter().cloned());
        for event in held.chain(pending) {
            match event {
                Some(event) => {
                    if seen.insert(event.i) {
                        events.push(event);
                    }
                }
                None => read.unreadable += 1,
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
    read
}

/// UTC to the millisecond, the way spreadsheets and log tools read it.
/// Worked out here rather than with a date library: this is the one date
/// this crate ever writes.
pub fn utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// One CSV cell. A label is whatever someone typed, so one starting like a
/// formula is kept as text rather than run by the spreadsheet.
fn cell(value: &str) -> String {
    let value = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_string()
    };
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value
    }
}

/// The log as CSV, one event per row. `names` are what each device is
/// called, where the caller knows.
pub fn to_csv(entries: &[LogEntry], names: &HashMap<Uuid, String>) -> String {
    let mut out =
        String::from("time_utc,device,device_name,event,code,count,object,label,details,number\n");
    for entry in entries {
        let e = &entry.event;
        let details = if e.x.is_empty() {
            String::new()
        } else {
            serde_json::to_string(&e.x).unwrap_or_default()
        };
        let row = [
            utc(e.t),
            entry.device.to_string(),
            names.get(&entry.device).cloned().unwrap_or_default(),
            entry.what.clone(),
            e.c.to_string(),
            e.n.to_string(),
            e.o.clone().unwrap_or_default(),
            e.l.clone().unwrap_or_default(),
            details,
            e.i.to_string(),
        ];
        out.push_str(&row.iter().map(|v| cell(v)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

/// The log as JSON lines, one event per line, the record as it was sealed.
pub fn to_jsonl(entries: &[LogEntry], names: &HashMap<Uuid, String>) -> String {
    let mut out = String::new();
    for entry in entries {
        let line = serde_json::json!({
            "time_utc": utc(entry.event.t),
            "device": entry.device,
            "device_name": names.get(&entry.device),
            "event": entry.what,
            "record": entry.event,
        });
        out.push_str(&line.to_string());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyPair, codes, seal_event};

    #[test]
    fn dates_come_out_as_utc() {
        assert_eq!(utc(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(utc(1_789_000_000_123), "2026-09-10T00:26:40.123Z");
        assert_eq!(utc(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(utc(-1), "1969-12-31T23:59:59.999Z");
    }

    #[test]
    fn an_export_keeps_a_typed_formula_as_text() {
        assert_eq!(cell("Bank"), "Bank");
        assert_eq!(cell("=HYPERLINK(1)"), "'=HYPERLINK(1)");
        assert_eq!(cell("a, \"b\""), "\"a, \"\"b\"\"\"");
    }

    #[test]
    fn records_from_segments_and_the_queue_read_as_one_log() {
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let sealed = |i: u64, t: i64| {
            let mut event = Event::new(codes::SECRET_COPIED, t)
                .on("e1", "Bank")
                .with("field", "password");
            event.i = i;
            seal_event(&keys.public, device, &event).unwrap()
        };
        let segment = Segment {
            device,
            seq: 0,
            prev: [0; 32],
            closed_at: 1,
            records: vec![sealed(0, 10), sealed(1, 20)],
        };
        let read = read_log([segment], &[(device, sealed(3, 40))], &one(&keys));
        assert_eq!(read.entries.len(), 3);
        assert_eq!(read.entries[0].event.i, 3, "newest first");
        assert_eq!(read.devices[0].missing_events, vec![(2, 2)]);

        let names = HashMap::from([(device, "Laptop".to_string())]);
        let csv = to_csv(&read.entries, &names);
        let row = csv.lines().nth(1).unwrap();
        assert!(row.contains(",Laptop,Secret copied,11,1,e1,Bank,"));
        assert!(row.contains("\"{\"\"field\"\":\"\"password\"\"}\""));
        let line = to_jsonl(&read.entries[..1], &names);
        let parsed: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(parsed["device_name"], "Laptop");
        assert_eq!(parsed["record"]["l"], "Bank");
    }

    fn one(keys: &KeyPair) -> [(KeyId, &[u8]); 1] {
        [(keys.id(), &keys.private[..])]
    }

    #[test]
    fn records_under_an_earlier_key_open_with_it() {
        let first = KeyPair::generate();
        let second = KeyPair::generate();
        let device = Uuid::new_v4();
        let mut a = log(&first, device, 1, 2);
        let b = log(&second, device, 2, 2);
        a.push(b[1].clone());
        let both = [
            (first.id(), &first.private[..]),
            (second.id(), &second.private[..]),
        ];
        let read = read_log(a.clone(), &[], &both);
        assert_eq!((read.entries.len(), read.unreadable), (4, 0));
        let only = read_log(a, &[], &one(&second));
        assert_eq!((only.entries.len(), only.unreadable), (2, 2));
    }

    fn log(keys: &KeyPair, device: Uuid, segments: u64, per: u64) -> Vec<Segment> {
        (0..segments)
            .map(|seq| Segment {
                device,
                seq,
                prev: [0; 32],
                closed_at: 1,
                records: (0..per)
                    .map(|k| {
                        let i = seq * per + k;
                        let mut event = Event::new(codes::UNLOCKED, 1000 + i as i64);
                        event.i = i;
                        seal_event(&keys.public, device, &event).unwrap()
                    })
                    .collect(),
            })
            .collect()
    }

    #[test]
    fn a_second_read_opens_only_what_is_new_and_reads_the_same() {
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let all = log(&keys, device, 6, 50);
        let plain = read_log(all.clone(), &[], &one(&keys));
        assert_eq!(plain.entries.len(), 300);
        assert_eq!(
            plain.entries[0].event.i, 299,
            "newest first, across threads"
        );

        let mut opened = Opened::default();
        let first = read_log_with(all[..4].to_vec(), &[], &one(&keys), &mut opened);
        assert_eq!((first.entries.len(), opened.segments()), (200, 4));
        let second = read_log_with(all.clone(), &[], &one(&keys), &mut opened);
        assert_eq!(opened.segments(), 6);
        let ids = |r: &LogRead| r.entries.iter().map(|e| e.event.i).collect::<Vec<_>>();
        assert_eq!(ids(&second), ids(&plain));
        assert_eq!(second.devices, plain.devices);
    }

    #[test]
    fn a_segment_whose_bytes_changed_is_opened_again() {
        let keys = KeyPair::generate();
        let device = Uuid::new_v4();
        let mut all = log(&keys, device, 2, 3);
        let mut opened = Opened::default();
        read_log_with(all.clone(), &[], &one(&keys), &mut opened);
        // Same place, other records: a copy that does not hold what was read.
        all[1].records.truncate(1);
        let again = read_log_with(all, &[], &one(&keys), &mut opened);
        assert_eq!(again.entries.len(), 4);
    }

    #[test]
    fn another_key_starts_over() {
        let keys = KeyPair::generate();
        let other = KeyPair::generate();
        let device = Uuid::new_v4();
        let all = log(&keys, device, 2, 3);
        let mut opened = Opened::default();
        read_log_with(all.clone(), &[], &one(&keys), &mut opened);
        let wrong = read_log_with(all, &[], &one(&other), &mut opened);
        assert_eq!((wrong.entries.len(), wrong.unreadable), (0, 6));
    }
}
