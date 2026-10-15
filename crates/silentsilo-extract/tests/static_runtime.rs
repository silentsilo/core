//! The extractor runs on a Windows where SilentSilo was never installed, so
//! it must not import the Visual C++ runtime, which such a machine lacks.
//! `build.rs` links it statically; this reads the binary's import table to
//! prove it. The binary is the one this test run built, so a debug build is
//! covered as well as a release one.

#![cfg(all(windows, target_env = "msvc"))]

fn u16_at(bytes: &[u8], at: usize) -> usize {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap()) as usize
}

fn u32_at(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
}

/// The DLL names in a PE file's import directory.
fn imported_dlls(pe: &[u8]) -> Vec<String> {
    assert_eq!(&pe[..2], b"MZ", "not a PE file");
    let nt = u32_at(pe, 0x3C);
    assert_eq!(&pe[nt..nt + 4], b"PE\0\0", "no PE signature");
    let coff = nt + 4;
    let sections = u16_at(pe, coff + 2);
    let optional = coff + 20;
    let optional_len = u16_at(pe, coff + 16);
    // The data directories start after the fields of PE32+ or PE32.
    let directories = match u16_at(pe, optional) {
        0x20B => optional + 112,
        0x10B => optional + 96,
        magic => panic!("unknown optional header {magic:#x}"),
    };
    let import_rva = u32_at(pe, directories + 8);
    assert_ne!(import_rva, 0, "no import directory");

    let table = optional + optional_len;
    let offset_of = |rva: usize| -> usize {
        (0..sections)
            .map(|i| table + i * 40)
            .find_map(|s| {
                let size = u32_at(pe, s + 8).max(u32_at(pe, s + 16));
                let start = u32_at(pe, s + 12);
                (start..start + size)
                    .contains(&rva)
                    .then(|| rva - start + u32_at(pe, s + 20))
            })
            .unwrap_or_else(|| panic!("RVA {rva:#x} is in no section"))
    };

    let mut names = Vec::new();
    let mut descriptor = offset_of(import_rva);
    // Twenty bytes each, the name's RVA at 12, ended by one of zeros.
    while pe[descriptor..descriptor + 20].iter().any(|&b| b != 0) {
        let name = offset_of(u32_at(pe, descriptor + 12));
        let end = pe[name..].iter().position(|&b| b == 0).unwrap();
        names.push(String::from_utf8_lossy(&pe[name..name + end]).into_owned());
        descriptor += 20;
    }
    names
}

#[test]
fn the_extractor_does_not_import_the_visual_cpp_runtime() {
    let pe = std::fs::read(env!("CARGO_BIN_EXE_silentsilo-extract")).unwrap();
    let dlls = imported_dlls(&pe);
    // The table was read, not missed.
    assert!(
        dlls.iter().any(|d| d.eq_ignore_ascii_case("kernel32.dll")),
        "{dlls:?}"
    );
    for dll in &dlls {
        let upper = dll.to_ascii_uppercase();
        assert!(
            !upper.starts_with("VCRUNTIME") && !upper.starts_with("MSVCP"),
            "{dll} is not on a clean Windows: {dlls:?}"
        );
    }
}
