//! The activity log's bytes as 1.9.0 first wrote them. Whatever the code
//! becomes, a later build has to open exactly this: a segment, the record in
//! it and the event in the record. Generated once; never regenerate it.

use silentsilo_audit::{Segment, check_chain, codes, open_event, record_key};
use uuid::Uuid;

const PRIVATE_KEY: &str = "21c2682feb58de270cb9e03714e30a1697b4d83085e7074855e7780d0951f91c";
const PUBLIC_KEY: &str = "de7ef088735b5d85c98845e78ae5dea392fdecc850f5bfec7970315b9048d23f";
const SEGMENT: [&str; 5] = [
    "53534153010190a0a000007000800000000000a0d10000000000000003ababababababababababababababababababab",
    "ababababababababababababab000001a088b5a5e8000000010000009653534152010020000100022dcab9dd9104ec45",
    "0020906759bd8d19183e90181bbc3458a2e9a7df390d034a35d1bdc827364950ac050000005de250b2b1dd247589d016",
    "c3086cb71ac4a7e02bfe09f135c80070a540e25ee96d8ad70e7d36f0027dd4ae0854123907db9b7a265e69c76b71bc54",
    "39b00b1d2ff4bbe91bf9e09f4bcdf2304168ca98ca159455f7aa3463c025639f5cb473",
];

#[test]
fn a_1_9_0_segment_opens_as_it_was_written() {
    let bytes = hex::decode(SEGMENT.concat()).unwrap();
    let segment = Segment::from_bytes(&bytes).unwrap();
    let device = Uuid::parse_str("0190a0a0-0000-7000-8000-00000000a0d1").unwrap();
    assert_eq!(segment.device, device);
    assert_eq!(segment.seq, 3);
    assert_eq!(segment.prev, [0xab; 32]);
    assert_eq!(segment.closed_at, 1_789_000_001_000);
    assert_eq!(segment.records.len(), 1);
    assert_eq!(segment.to_bytes(), bytes, "re-encoded byte for byte");

    let public = hex::decode(PUBLIC_KEY).unwrap();
    assert_eq!(
        record_key(&segment.records[0]).unwrap(),
        silentsilo_audit::record::key_id(&public)
    );

    let private = hex::decode(PRIVATE_KEY).unwrap();
    let event = open_event(&private, device, &segment.records[0]).unwrap();
    assert_eq!(event.i, 7);
    assert_eq!(event.t, 1_789_000_000_000);
    assert_eq!(event.c, codes::SECRET_COPIED);
    assert_eq!(event.o.as_deref(), Some("e1"));
    assert_eq!(event.l.as_deref(), Some("Bank"));
    assert_eq!(event.x["field"], "password");

    // A run that starts at 3 checks from 3.
    assert!(check_chain(&[segment], 3).is_whole());
}
