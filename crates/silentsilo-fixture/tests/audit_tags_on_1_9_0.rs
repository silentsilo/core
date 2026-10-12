//! What 1.9.0, the first release with the activity log, does with what
//! this build writes: tagged segments (version 2), a policy carrying
//! `auth`, and a queue whose pin and policy carry a check. Answered by its
//! own code.

use silentsilo_audit::{
    AuditKey, AuditPolicy, Event, KeyPair, PolicyKey, Scope, Segment, SegmentKey, Spool, Unchecked,
    codes, seal_event,
};
use silentsilo_audit_v1_9_0 as old;
use uuid::Uuid;

const KEK: [u8; 32] = [4; 32];

/// A run of three segments from one device, the middle one tagged, chained.
fn run(keys: &KeyPair, device: Uuid) -> Vec<Segment> {
    let mut out: Vec<Segment> = Vec::new();
    for seq in 0..3u64 {
        let mut event = Event::new(codes::UNLOCKED, 1_000 + seq as i64);
        event.i = seq;
        let segment = Segment {
            device,
            seq,
            prev: out.last().map_or([0; 32], |s| s.hash()),
            closed_at: 1,
            records: vec![seal_event(&keys.public, device, &event).unwrap()],
            tag: None,
        };
        out.push(if seq == 1 {
            segment.tag_with(&SegmentKey::new(&KEK))
        } else {
            segment
        });
    }
    out
}

#[test]
fn a_tagged_segment_is_refused_by_name_and_left_out_as_missing() {
    let keys = KeyPair::generate();
    let device = Uuid::new_v4();
    let run = run(&keys, device);

    let err = old::Segment::from_bytes(&run[1].to_bytes()).unwrap_err();
    assert!(matches!(err, old::AuditError::Newer("segment")), "{err}");
    assert!(err.to_string().contains("newer version"), "{err}");

    // What it reads around it: the untagged ones, and the hole named.
    let read: Vec<old::Segment> = [&run[0], &run[2]]
        .iter()
        .map(|s| old::Segment::from_bytes(&s.to_bytes()).unwrap())
        .collect();
    let report = old::check_chain(&read, 0);
    assert_eq!(report.missing, vec![1]);
    assert!(report.broken.is_empty());
    let private = &keys.private;
    for segment in &read {
        old::open_event(private, device, &segment.records[0]).unwrap();
    }
}

#[test]
fn a_policy_carrying_its_tag_reads_as_before() {
    let keys = KeyPair::generate();
    let policy = AuditPolicy::new(true, &keys.id(), Some(365), Scope::Org, 1_789_000_000)
        .tagged(&PolicyKey::new(&[8; 32]));
    assert!(policy.auth.is_some());
    let sealed = policy.seal(&KEK).unwrap();
    let read = old::AuditPolicy::open(&sealed, &KEK).unwrap();
    assert!(read.enabled);
    assert_eq!(read.key_id, policy.key_id);
    assert_eq!(read.retention_days, Some(365));
    assert_eq!(read.scope, old::Scope::Org);
    assert_eq!(read.changed_at, policy.changed_at);
}

#[test]
fn a_queue_this_build_wrote_opens_on_1_9_0_and_comes_back_whole() {
    let dir = tempfile::tempdir().unwrap();
    let device = Uuid::new_v4();
    let keys = KeyPair::generate();
    let key = AuditKey::new(&keys, Scope::Silo, 1);
    let on = AuditPolicy::new(true, &keys.id(), None, Scope::Silo, 1);
    {
        let mut spool = Spool::open(dir.path(), device, &KEK, Unchecked::Refuse).unwrap();
        spool.apply_policy(&on, &key, 10).unwrap();
        spool.record(Event::new(codes::UNLOCKED, 1)).unwrap();
        spool.close(2).unwrap();
    }

    // 1.9.0 opens it, goes on sealing to the same key, and sets aside the
    // tagged segment it cannot read, keeping it on disk.
    {
        let mut spool = old::Spool::open(dir.path(), device).unwrap();
        assert_eq!(spool.pinned().unwrap().key_id, hex::encode(keys.id()));
        assert_eq!(
            spool.policy().unwrap().unwrap().key_id,
            hex::encode(keys.id())
        );
        assert!(spool.outbox().unwrap().is_empty());
        spool
            .record(old::Event::new(old::codes::LOCKED, 3))
            .unwrap()
            .unwrap();
    }
    let outbox = dir.path().join(silentsilo_audit::QUEUE_DIR).join("outbox");
    assert!(outbox.join(format!("{:012}.damaged", 0)).exists());

    // Back on this build: the pin 1.9.0 saved without its check is made
    // again from the kept policy, and the set-aside segment goes out.
    let mut spool = Spool::open(dir.path(), device, &KEK, Unchecked::Refuse).unwrap();
    assert_eq!(spool.pinned().unwrap().key_id, hex::encode(keys.id()));
    let segments = spool.outbox().unwrap();
    assert_eq!(segments.iter().map(|s| s.seq).collect::<Vec<_>>(), vec![0]);
    let closed = spool.close(4).unwrap().unwrap();
    assert_eq!(closed.seq, 1);
    assert_eq!(closed.prev, segments[0].hash());
}
