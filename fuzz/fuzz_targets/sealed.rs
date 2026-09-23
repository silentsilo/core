//! A sealed record, key envelope or snapshot as storage returns it. The
//! header is parsed before anything is authenticated.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use silentsilo_crypto::{seal, unseal, unseal_with_key};
use silentsilo_fuzz::{DEK, dek, shaped};

fn valid() -> &'static [u8] {
    static SEALED: OnceLock<Vec<u8>> = OnceLock::new();
    SEALED.get_or_init(|| seal(b"a record, about this long, sealed under the key", &dek()).unwrap())
}

fuzz_target!(|data: &[u8]| {
    let bytes = shaped(valid(), data);
    let _ = unseal(&bytes, &dek());
    let _ = unseal_with_key(&bytes, &DEK);
});
