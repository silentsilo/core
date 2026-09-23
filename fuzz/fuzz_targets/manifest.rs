//! The manifest a joining device reads before it can unwrap anything.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silentsilo_fuzz::shaped;

const VALID: &[u8] =
    include_bytes!("../../crates/silentsilo-fixture/fixtures/v1.0.0/store/vault.json");

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<silentsilo_sync::VaultManifest>(&shaped(VALID, data));
});
