//! A batch of one device's sealed events, as it goes to storage.
//!
//! `audit/<device>/<seq>.seg`: numbered from 0 per device, each naming the
//! BLAKE3 of the one before, so a missing or replaced segment breaks the
//! chain where a reader sees it. The device assembles a segment from records
//! it cannot open; nothing in the header is secret.

use uuid::Uuid;

use crate::{AuditError, Reader};

/// Where the log lives in a silo's storage. Never under `ops/`: a 1.0.0
/// client drops record types it does not know when it compacts.
pub const AUDIT_PREFIX: &str = "audit/";

const SEGMENT_MAGIC: &[u8; 4] = b"SSAS";
const SEGMENT_VERSION: u8 = 1;

/// Storage is untrusted: nothing larger is downloaded, nor holds more.
pub const MAX_SEGMENT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub device: Uuid,
    pub seq: u64,
    /// BLAKE3 of the previous segment's bytes; zeros for the first.
    pub prev: [u8; 32],
    /// When the device closed it, by its clock, in milliseconds.
    pub closed_at: i64,
    pub records: Vec<Vec<u8>>,
}

impl Segment {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SEGMENT_MAGIC);
        out.push(SEGMENT_VERSION);
        out.extend_from_slice(self.device.as_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.prev);
        out.extend_from_slice(&self.closed_at.to_be_bytes());
        out.extend_from_slice(&(self.records.len() as u32).to_be_bytes());
        for record in &self.records {
            out.extend_from_slice(&(record.len() as u32).to_be_bytes());
            out.extend_from_slice(record);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuditError> {
        if bytes.len() as u64 > MAX_SEGMENT_BYTES {
            return Err(AuditError::TooLarge("segment"));
        }
        let mut r = Reader::new(bytes);
        if r.take(4)? != SEGMENT_MAGIC {
            return Err(AuditError::Malformed("not an audit segment"));
        }
        if r.u8()? != SEGMENT_VERSION {
            return Err(AuditError::Newer("segment"));
        }
        let device = Uuid::from_slice(r.take(16)?).map_err(|_| AuditError::Malformed("device"))?;
        let seq = r.u64()?;
        let mut prev = [0u8; 32];
        prev.copy_from_slice(r.take(32)?);
        let closed_at = r.u64()? as i64;
        let count = r.u32()? as usize;
        if count > MAX_RECORDS {
            return Err(AuditError::TooLarge("segment"));
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let len = r.u32()? as usize;
            records.push(r.take(len)?.to_vec());
        }
        r.end()?;
        Ok(Self {
            device,
            seq,
            prev,
            closed_at,
            records,
        })
    }

    /// What the next segment names as its `prev`.
    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(&self.to_bytes()).as_bytes()
    }

    /// `audit/<device>/<seq>.seg`, the sequence zero-padded so a listing
    /// sorts in order.
    pub fn key(&self) -> String {
        segment_key(self.device, self.seq)
    }
}

pub fn segment_key(device: Uuid, seq: u64) -> String {
    format!("{AUDIT_PREFIX}{device}/{seq:012}.seg")
}

/// The device and sequence a storage key names, if it is a segment's.
pub fn parse_segment_key(key: &str) -> Option<(Uuid, u64)> {
    let rest = key.strip_prefix(AUDIT_PREFIX)?;
    let (device, name) = rest.split_once('/')?;
    let seq = name.strip_suffix(".seg")?;
    if seq.len() != 12 || !seq.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((Uuid::parse_str(device).ok()?, seq.parse().ok()?))
}

/// What is wrong with one device's run of segments.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ChainReport {
    /// Sequence numbers that should be there and are not.
    pub missing: Vec<u64>,
    /// Segments whose `prev` is not the hash of the one before them.
    pub broken: Vec<u64>,
}

impl ChainReport {
    pub fn is_whole(&self) -> bool {
        self.missing.is_empty() && self.broken.is_empty()
    }
}

/// Checks one device's segments, in any order, from its first. Segments
/// before `from` may have expired under a retention; the chain is checked
/// from there.
pub fn check_chain(segments: &[Segment], from: u64) -> ChainReport {
    let mut sorted: Vec<&Segment> = segments.iter().filter(|s| s.seq >= from).collect();
    sorted.sort_by_key(|s| s.seq);
    let mut report = ChainReport::default();
    let mut expected = from;
    let mut previous: Option<&Segment> = None;
    for segment in sorted {
        while expected < segment.seq {
            report.missing.push(expected);
            expected += 1;
        }
        // What `prev` must be, when the segment before is here to say.
        let expected_prev = match previous {
            Some(prev) if prev.seq + 1 == segment.seq => Some(prev.hash()),
            None if segment.seq == 0 => Some([0u8; 32]),
            _ => None,
        };
        if expected_prev.is_some_and(|hash| hash != segment.prev) {
            report.broken.push(segment.seq);
        }
        expected = segment.seq + 1;
        previous = Some(segment);
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(device: Uuid, n: u64) -> Vec<Segment> {
        let mut out: Vec<Segment> = Vec::new();
        for seq in 0..n {
            let prev = out.last().map(|s| s.hash()).unwrap_or([0u8; 32]);
            out.push(Segment {
                device,
                seq,
                prev,
                closed_at: seq as i64,
                records: vec![vec![seq as u8; 3]],
            });
        }
        out
    }

    #[test]
    fn a_segment_round_trips_and_names_itself() {
        let device = Uuid::new_v4();
        let segment = chain(device, 2).pop().unwrap();
        assert_eq!(Segment::from_bytes(&segment.to_bytes()).unwrap(), segment);
        assert_eq!(parse_segment_key(&segment.key()), Some((device, 1)));
        assert!(segment.key().ends_with("/000000000001.seg"));
    }

    #[test]
    fn a_whole_chain_reads_whole() {
        assert!(check_chain(&chain(Uuid::new_v4(), 5), 0).is_whole());
    }

    #[test]
    fn a_missing_segment_is_named() {
        let mut segments = chain(Uuid::new_v4(), 5);
        segments.remove(2);
        let report = check_chain(&segments, 0);
        assert_eq!(report.missing, vec![2]);
    }

    #[test]
    fn a_replaced_segment_breaks_the_one_after() {
        let mut segments = chain(Uuid::new_v4(), 4);
        segments[1].records.clear();
        let report = check_chain(&segments, 0);
        assert_eq!(report.broken, vec![2]);
    }

    #[test]
    fn segments_expired_under_a_retention_are_not_missing() {
        let segments = chain(Uuid::new_v4(), 6);
        assert!(check_chain(&segments[3..], 3).is_whole());
    }

    #[test]
    fn a_key_that_is_not_a_segment_is_not_read_as_one() {
        for key in [
            "audit/keys/abc.json",
            "audit/not-a-uuid/000000000001.seg",
            "audit/0190a0a0-0000-7000-8000-000000000000/1.seg",
            "ops/x.op",
        ] {
            assert_eq!(parse_segment_key(key), None, "{key}");
        }
    }
}
