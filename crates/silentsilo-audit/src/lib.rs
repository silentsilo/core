//! The activity log: what was done in a silo, by which device, kept apart
//! from the operation log and sealed so that, on an organisation's silo,
//! the devices that write it cannot read it.
//!
//! - [`events`]: what an event says, and the stable codes;
//! - [`record`]: one event sealed with HPKE to the log's public key;
//! - [`segment`]: a device's batch of records under `audit/`, chained;
//! - [`keyring`]: the log's key and policy as storage holds them;
//! - [`spool`]: a device's queue of sealed events until storage holds them;
//! - [`reading`]: a gathered log opened, checked and written out.
//!
//! The format is in `FORMATS.md`, "The activity log".

pub mod events;
pub mod keyring;
pub mod reading;
pub mod record;
pub mod segment;
pub mod spool;

pub use events::{Event, codes, describe};
pub use keyring::{AuditKey, AuditPolicy, BY_SILO, POLICY_PATH, Scope, audit_key_path};
pub use record::{KeyId, KeyPair, open_event, record_key, seal_event};
pub use segment::{
    AUDIT_PREFIX, ChainReport, MAX_SEGMENT_BYTES, Segment, check_chain, parse_segment_key,
    segment_key,
};
pub use spool::{Pinned, PolicyRead, QUEUE_DIR, Spool, SpoolError};

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("the activity log is damaged: {0}")]
    Malformed(&'static str),
    #[error("this {0} was written by a newer version of SilentSilo. Update to read it.")]
    Newer(&'static str),
    #[error("this {0} is larger than any SilentSilo writes")]
    TooLarge(&'static str),
    #[error("the activity log's key does not fit")]
    BadKey,
    #[error("an activity log record does not open")]
    Crypto,
    #[error("an activity log event is not readable: {0}")]
    Json(#[from] serde_json::Error),
}

/// Gaps in one device's own event count, after its records are opened:
/// each `(from, to)` is a run of events that should be there and are not.
/// `first` is where the readable log starts (a retention may have removed
/// what came before).
pub fn counter_gaps(events: &[Event], first: u64) -> Vec<(u64, u64)> {
    let mut seen: Vec<u64> = events.iter().map(|e| e.i).filter(|i| *i >= first).collect();
    seen.sort_unstable();
    seen.dedup();
    let mut gaps = Vec::new();
    let mut expected = first;
    for i in seen {
        if i > expected {
            gaps.push((expected, i - 1));
        }
        expected = i + 1;
    }
    gaps
}

/// Reads a byte buffer front to back, refusing to run past its end.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], AuditError> {
        if self.bytes.len() < n {
            return Err(AuditError::Malformed("cut short"));
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, AuditError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, AuditError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, AuditError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, AuditError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }

    pub(crate) fn end(&self) -> Result<(), AuditError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(AuditError::Malformed("trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(i: u64) -> Event {
        let mut e = Event::new(codes::UNLOCKED, 0);
        e.i = i;
        e
    }

    #[test]
    fn a_hole_in_the_count_is_named() {
        let events: Vec<Event> = [0, 1, 4, 5, 7].into_iter().map(at).collect();
        assert_eq!(counter_gaps(&events, 0), vec![(2, 3), (6, 6)]);
        assert!(counter_gaps(&events[2..4], 4).is_empty());
    }

    /// The whole path, as a device writes and an organisation reads.
    #[test]
    fn a_device_writes_what_only_the_key_holder_reads() {
        let keys = KeyPair::generate();
        let device = uuid::Uuid::new_v4();
        let records: Vec<Vec<u8>> = (0..3)
            .map(|i| {
                let mut e = Event::new(codes::SECRET_COPIED, 100 + i as i64).on("e1", "Bank");
                e.i = i;
                seal_event(&keys.public, device, &e).unwrap()
            })
            .collect();
        let segment = Segment {
            device,
            seq: 0,
            prev: [0; 32],
            closed_at: 200,
            records,
        };
        let stored = Segment::from_bytes(&segment.to_bytes()).unwrap();
        let events: Vec<Event> = stored
            .records
            .iter()
            .map(|r| open_event(&keys.private, device, r).unwrap())
            .collect();
        assert!(counter_gaps(&events, 0).is_empty());
        assert_eq!(events[2].l.as_deref(), Some("Bank"));
    }
}
