//! A `.sslo` blob as storage returns it: the header on its own, then the
//! whole file through both readers.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silentsilo_crypto::{BlobHeader, decrypt_blob, verify_blob};
use silentsilo_fuzz::{BLOB_ID, content_key, scratch, shaped, valid_blob};

fuzz_target!(|data: &[u8]| {
    let bytes = shaped(valid_blob(), data);
    let _ = BlobHeader::from_bytes(&bytes);

    let source = scratch().join("blob.sslo");
    let out = scratch().join("plain.bin");
    std::fs::write(&source, &bytes).unwrap();
    let _ = decrypt_blob(&source, &out, &content_key(), BLOB_ID);
    let _ = verify_blob(&source, &content_key(), BLOB_ID);
});
