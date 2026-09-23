//! The files in the silo root, from wherever that folder has been: one file
//! per input, written and read back by its loader.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use silentsilo_crypto::ContentKek;
use silentsilo_fuzz::{dek, scratch, shaped};
use silentsilo_vault as vault;

const RECOVERY: &[u8] =
    include_bytes!("../../crates/silentsilo-fixture/fixtures/v1.0.0/silo/keys/recovery.json");
const WRAP: [u8; 32] = [5; 32];

/// A valid copy of each file, written by this build's own savers.
struct Valid {
    dek: Vec<u8>,
    kek: Vec<u8>,
    keys: Vec<u8>,
    registry: Vec<u8>,
}

fn valid() -> &'static Valid {
    static VALID: OnceLock<Valid> = OnceLock::new();
    VALID.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("keys")).unwrap();
        vault::save_dek(root, &dek(), &WRAP).unwrap();
        vault::save_kek(root, &ContentKek::from_bytes([4; 32]), &dek()).unwrap();
        Valid {
            dek: std::fs::read(vault::dek_path(root)).unwrap(),
            kek: std::fs::read(vault::kek_path(root)).unwrap(),
            keys: vault::format::encode(&vault::StoredFidoKeys { keys: Vec::new() }).unwrap(),
            registry: vault::format::encode(&vault::SiloRegistry::default()).unwrap(),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let root = scratch();
    std::fs::create_dir_all(root.join("keys")).unwrap();
    let v = valid();
    match data.get(1).copied().unwrap_or(0) % 6 {
        0 => {
            std::fs::write(vault::fido_keys_path(root), shaped(&v.keys, data)).unwrap();
            let _ = vault::load_fido_keys(root);
        }
        1 => {
            std::fs::write(vault::recovery::recovery_path(root), shaped(RECOVERY, data)).unwrap();
            let _ = vault::load_recovery_envelope(root);
        }
        2 => {
            std::fs::write(vault::dek_path(root), shaped(&v.dek, data)).unwrap();
            let _ = vault::load_dek(root, &WRAP);
        }
        3 => {
            std::fs::write(vault::kek_path(root), shaped(&v.kek, data)).unwrap();
            let _ = vault::load_kek(root, &dek());
        }
        4 => {
            std::fs::write(vault::registry_path(root), shaped(&v.registry, data)).unwrap();
            let _ = vault::load_registry(root);
        }
        _ => {
            let _ = vault::format::decode::<Vec<vault::BackupTarget>>("targets", data);
            let _ = vault::format::decode::<silentsilo_store::StoreConfig>("storage", data);
        }
    }
});
