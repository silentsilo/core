//! A client-supplied protector for the local secret files, where there is
//! no DPAPI. Its own test binary: the protector is set once per process.
#![cfg(not(windows))]

use silentsilo_vault::{
    LocalProtector, SiloEntry, SiloRegistry, load_registry, registry_path, save_registry,
    set_local_protector,
};
use uuid::Uuid;

/// Stands in for a platform key: reversible, and not the plaintext.
struct Xor;

impl LocalProtector for Xor {
    fn protect(&self, data: &[u8]) -> Option<Vec<u8>> {
        Some(data.iter().map(|b| b ^ 0x5a).collect())
    }
    fn unprotect(&self, data: &[u8]) -> Option<Vec<u8>> {
        self.protect(data)
    }
}

fn registry(name: &str) -> SiloRegistry {
    let mut registry = SiloRegistry::default();
    registry.upsert(SiloEntry {
        id: Uuid::new_v4(),
        name: name.into(),
        path: "/data/silo".into(),
        last_opened: 0,
        auto_lock_minutes: None,
    });
    registry
}

#[test]
fn files_are_sealed_by_the_protector_and_old_plaintext_still_reads() {
    let dir = tempfile::tempdir().unwrap();

    // Written before the protector existed, as a phone on the last build did.
    save_registry(dir.path(), &registry("Before")).unwrap();
    assert!(
        !std::fs::read(registry_path(dir.path()))
            .unwrap()
            .starts_with(b"SSDPAPI1")
    );

    assert!(set_local_protector(Box::new(Xor)));
    assert!(!set_local_protector(Box::new(Xor)), "set once");
    assert_eq!(load_registry(dir.path()).silos[0].name, "Before");

    save_registry(dir.path(), &registry("Second family")).unwrap();
    let raw = std::fs::read(registry_path(dir.path())).unwrap();
    assert!(raw.starts_with(b"SSDPAPI1"));
    assert!(!raw.windows(6).any(|w| w == b"Second"));
    assert_eq!(load_registry(dir.path()).silos[0].name, "Second family");
}
