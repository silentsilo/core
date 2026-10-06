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

use crate::{Event, Segment, check_chain, counter_gaps, describe, open_event};

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

/// Opens and checks `segments`, from anywhere and in any order, one per
/// device and number. `unsent` are records not in a segment yet, by device.
pub fn read_log(
    segments: impl IntoIterator<Item = Segment>,
    unsent: &[(Uuid, Vec<u8>)],
    private: &[u8],
) -> LogRead {
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

    let mut read = LogRead::default();
    for (device, segments) in by_device {
        let segments: Vec<Segment> = segments.into_values().collect();
        let from = segments.iter().map(|s| s.seq).min().unwrap_or(0);
        let chain = check_chain(&segments, from);
        let mut events = Vec::new();
        let mut seen = HashSet::new();
        let records = segments.iter().flat_map(|s| s.records.iter());
        let pending = unsent
            .iter()
            .filter(|(d, _)| *d == device)
            .map(|(_, record)| record);
        for record in records.chain(pending) {
            match open_event(private, device, record) {
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
        let read = read_log([segment], &[(device, sealed(3, 40))], &keys.private);
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
}
