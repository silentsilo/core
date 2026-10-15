//! A batch of one device's sealed events, as it goes to storage.
//!
//! `audit/<device>/<seq>.seg`: numbered from 0 per device, each naming the
//! BLAKE3 of the one before, so a missing or replaced segment breaks the
//! chain where a reader sees it. The device assembles a segment from records
//! it cannot open; nothing in the header is secret.
//!
//! From version 2 a segment ends with a tag under a key derived from the
//! silo's content key ([`SegmentKey`]), so storage alone can neither write
//! one nor change one. Version 1, written before core 1.10, has no tag and
//! still reads.

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{AuditError, Reader};

/// Where the log lives in a silo's storage. Never under `ops/`: a 1.0.0
/// client drops record types it does not know when it compacts.
pub const AUDIT_PREFIX: &str = "audit/";

const SEGMENT_MAGIC: &[u8; 4] = b"SSAS";
/// Written before core 1.10: no tag.
const SEGMENT_VERSION_UNTAGGED: u8 = 1;
/// What this build writes: the same, then a 32-byte tag.
const SEGMENT_VERSION: u8 = 2;

/// The tag at the end of a version 2 segment.
pub const TAG_BYTES: usize = 32;

/// Storage is untrusted: nothing larger is downloaded, nor holds more.
pub const MAX_SEGMENT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_RECORDS: usize = 100_000;

/// How many missing segments a chain check names one by one. A gap wider
/// than this is counted, not listed: a number written by storage must not
/// decide how much memory a reader takes.
pub const MAX_NAMED_MISSING: usize = 10_000;

/// The key segments are tagged under, derived from the silo's content key.
/// Every device that writes the log and every reader holds it; storage does
/// not. The content key never rotates, which is what lets a segment written
/// years ago still check.
pub struct SegmentKey(Zeroizing<[u8; 32]>);

impl SegmentKey {
    pub fn new(content_key: &[u8; 32]) -> Self {
        Self(Zeroizing::new(blake3::derive_key(
            "silentsilo audit segment v2",
            content_key,
        )))
    }

    fn tag(&self, body: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(&self.0, body).as_bytes()
    }
}

/// What a segment's tag says about who wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    /// Tagged under this silo's key: written by one of its devices.
    Tagged,
    /// A version 1 segment, from before tags: nothing says who wrote it.
    Untagged,
    /// Tagged, and the tag does not check: not written by this silo.
    Forged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub device: Uuid,
    pub seq: u64,
    /// BLAKE3 of the previous segment's bytes; zeros for the first.
    pub prev: [u8; 32],
    /// When the device closed it, by its clock, in milliseconds.
    pub closed_at: i64,
    pub records: Vec<Vec<u8>>,
    /// The version 2 tag; `None` for a version 1 segment. Set by
    /// [`Segment::tag_with`].
    pub tag: Option<[u8; 32]>,
}

impl Segment {
    /// The bytes before the tag, under `version`.
    fn body(&self, version: u8) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SEGMENT_MAGIC);
        out.push(version);
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

    /// Version 2 with its tag when it has one, version 1 otherwise.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.tag {
            Some(tag) => {
                let mut out = self.body(SEGMENT_VERSION);
                out.extend_from_slice(&tag);
                out
            }
            None => self.body(SEGMENT_VERSION_UNTAGGED),
        }
    }

    /// This segment tagged under `key`, as this build writes it.
    pub fn tag_with(mut self, key: &SegmentKey) -> Self {
        self.tag = Some(key.tag(&self.body(SEGMENT_VERSION)));
        self
    }

    /// Whether `key`'s silo wrote it.
    pub fn proof(&self, key: &SegmentKey) -> Proof {
        match self.tag {
            None => Proof::Untagged,
            Some(tag) => {
                let expected = key.tag(&self.body(SEGMENT_VERSION));
                if crate::same_bytes(&tag, &expected) {
                    Proof::Tagged
                } else {
                    Proof::Forged
                }
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuditError> {
        if bytes.len() as u64 > MAX_SEGMENT_BYTES {
            return Err(AuditError::TooLarge("segment"));
        }
        let mut r = Reader::new(bytes);
        if r.take(4)? != SEGMENT_MAGIC {
            return Err(AuditError::Malformed("not an audit segment"));
        }
        let tagged = match r.u8()? {
            SEGMENT_VERSION_UNTAGGED => false,
            SEGMENT_VERSION => true,
            _ => return Err(AuditError::Newer("segment")),
        };
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
        let tag = if tagged {
            let mut tag = [0u8; 32];
            tag.copy_from_slice(r.take(TAG_BYTES)?);
            Some(tag)
        } else {
            None
        };
        r.end()?;
        Ok(Self {
            device,
            seq,
            prev,
            closed_at,
            records,
            tag,
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
    /// Sequence numbers that should be there and are not, at most
    /// [`MAX_NAMED_MISSING`] of them.
    pub missing: Vec<u64>,
    /// Missing beyond those named in `missing`.
    pub missing_not_named: u64,
    /// Segments whose `prev` is not the hash of the one before them.
    pub broken: Vec<u64>,
}

impl ChainReport {
    pub fn is_whole(&self) -> bool {
        self.missing.is_empty() && self.missing_not_named == 0 && self.broken.is_empty()
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
        if expected < segment.seq {
            let gap = segment.seq - expected;
            let room = (MAX_NAMED_MISSING - report.missing.len()) as u64;
            let named = gap.min(room);
            report.missing.extend(expected..expected + named);
            report.missing_not_named += gap - named;
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
        expected = segment.seq.saturating_add(1);
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
                tag: None,
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
    fn a_tagged_segment_round_trips_and_checks_under_its_silo_s_key_only() {
        let key = SegmentKey::new(&[7; 32]);
        let segment = chain(Uuid::new_v4(), 1).pop().unwrap().tag_with(&key);
        let bytes = segment.to_bytes();
        assert_eq!(bytes[4], 2, "version 2");
        let back = Segment::from_bytes(&bytes).unwrap();
        assert_eq!(back, segment);
        assert_eq!(back.proof(&key), Proof::Tagged);
        assert_eq!(back.proof(&SegmentKey::new(&[8; 32])), Proof::Forged);
        let untagged = Segment { tag: None, ..back };
        assert_eq!(untagged.proof(&key), Proof::Untagged);
        assert_eq!(untagged.to_bytes()[4], 1, "version 1 as before");
    }

    #[test]
    fn a_changed_byte_or_a_moved_segment_does_not_check() {
        let key = SegmentKey::new(&[7; 32]);
        let segment = chain(Uuid::new_v4(), 1).pop().unwrap().tag_with(&key);
        let mut bytes = segment.to_bytes();
        // A byte of the record.
        let at = bytes.len() - TAG_BYTES - 1;
        bytes[at] ^= 1;
        assert_eq!(
            Segment::from_bytes(&bytes).unwrap().proof(&key),
            Proof::Forged
        );
        // The same records under another device or number.
        let moved = Segment {
            seq: 5,
            ..segment.clone()
        };
        assert_eq!(moved.proof(&key), Proof::Forged);
        let other = Segment {
            device: Uuid::new_v4(),
            ..segment
        };
        assert_eq!(other.proof(&key), Proof::Forged);
    }

    #[test]
    fn a_later_version_is_named_not_misread() {
        let mut bytes = chain(Uuid::new_v4(), 1).pop().unwrap().to_bytes();
        bytes[4] = 3;
        assert!(matches!(
            Segment::from_bytes(&bytes),
            Err(AuditError::Newer("segment"))
        ));
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
    fn a_huge_gap_is_counted_not_listed() {
        let mut segments = chain(Uuid::new_v4(), 2);
        segments[1].seq = 999_999_999_999;
        let report = check_chain(&segments, 0);
        assert_eq!(report.missing.len(), MAX_NAMED_MISSING);
        assert_eq!(report.missing[0], 1);
        assert_eq!(
            report.missing.len() as u64 + report.missing_not_named,
            999_999_999_998
        );
        assert!(!report.is_whole());
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

/// Literal values from 1.10: segments written years ago must still check.
#[cfg(test)]
mod known_answers {
    use super::*;

    #[test]
    fn the_segment_key_and_its_tag_are_fixed() {
        let key = SegmentKey::new(&[0x03; 32]);
        assert_eq!(
            hex::encode(*key.0),
            "c93150d6c6d1050526d7ecb02b4952866fc0b1aab5a5da66c7b42fc5ce6507c3"
        );
        assert_eq!(
            hex::encode(key.tag(b"segment body")),
            "43578e4a247c3578564dcfe4777015213bb33cbf21485b1915a78d3d5dda7795"
        );
    }
}
