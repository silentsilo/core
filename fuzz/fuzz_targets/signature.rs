//! What arrives from a phone before its signature is checked: the DER
//! signature and the recovery code someone types.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = silentsilo_crypto::inbox::signature_from_der(data);
    let _ = silentsilo_vault::recovery::normalize_code(&String::from_utf8_lossy(data));
});
