//! An operation record once unsealed. Authenticated by then, but written by
//! another device on another version.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silentsilo_fuzz::{shaped, valid_silo};
use silentsilo_vfs::OpRecord;

fuzz_target!(|data: &[u8]| {
    let records = &valid_silo().records;
    let pick = data.get(1).copied().unwrap_or(0) as usize % records.len();
    if let Ok(record) = OpRecord::from_bytes(&shaped(&records[pick], data)) {
        // What decodes must encode again.
        record.to_bytes().expect("a decoded record encodes");
    }
});
