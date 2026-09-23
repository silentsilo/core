//! A compaction snapshot once unsealed, as a rebuild or a join reads it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silentsilo_fuzz::{shaped, valid_silo};
use silentsilo_vfs::Snapshot;

fuzz_target!(|data: &[u8]| {
    let _ = Snapshot::from_bytes(&shaped(&valid_silo().snapshot, data));
});
