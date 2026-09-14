//! Windows DPAPI wrapping for the credential-file fallback path in
//! `device_store.rs`. Not a defence against software running as the same
//! user, which can call `CryptUnprotectData` itself; what it closes off is
//! the file being readable outside this user's live Windows logon: a cloned
//! disk, an offline mount, another account, a restored profile backup.
//!
//! Elsewhere the client may supply a [`LocalProtector`] that plays the same
//! part, under the same file prefix.

#[cfg(windows)]
mod imp {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use windows::core::PCWSTR;

    /// Encrypt `data` under the current Windows user's DPAPI master key.
    /// Returns `None` on any failure (caller falls back to writing plaintext
    /// so provisioning still succeeds, matching the existing keyring-fallback
    /// behavior this sits alongside).
    pub fn protect(data: &[u8]) -> Option<Vec<u8>> {
        let mut input = data.to_vec();
        let blob_in = CRYPT_INTEGER_BLOB {
            cbData: input.len() as u32,
            pbData: input.as_mut_ptr(),
        };
        let mut blob_out = CRYPT_INTEGER_BLOB::default();

        unsafe {
            CryptProtectData(
                &blob_in,
                PCWSTR::null(),
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut blob_out,
            )
            .ok()?;
            let out =
                std::slice::from_raw_parts(blob_out.pbData, blob_out.cbData as usize).to_vec();
            let _ = LocalFree(Some(HLOCAL(blob_out.pbData as *mut core::ffi::c_void)));
            Some(out)
        }
    }

    /// Reverse of [`protect`]. Only succeeds for the same Windows user
    /// account that originally called `protect`.
    pub fn unprotect(data: &[u8]) -> Option<Vec<u8>> {
        let mut input = data.to_vec();
        let blob_in = CRYPT_INTEGER_BLOB {
            cbData: input.len() as u32,
            pbData: input.as_mut_ptr(),
        };
        let mut blob_out = CRYPT_INTEGER_BLOB::default();

        unsafe {
            CryptUnprotectData(
                &blob_in,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut blob_out,
            )
            .ok()?;
            let out =
                std::slice::from_raw_parts(blob_out.pbData, blob_out.cbData as usize).to_vec();
            let _ = LocalFree(Some(HLOCAL(blob_out.pbData as *mut core::ffi::c_void)));
            Some(out)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn roundtrips() {
            let plaintext = b"device secret goes here";
            let protected = protect(plaintext).expect("CryptProtectData should succeed in CI");
            assert_ne!(protected, plaintext);
            let unprotected = unprotect(&protected).expect("CryptUnprotectData should succeed");
            assert_eq!(unprotected, plaintext);
        }

        #[test]
        fn rejects_tampered_blob() {
            let protected = protect(b"hello").unwrap();
            let mut tampered = protected.clone();
            *tampered.last_mut().unwrap() ^= 0xFF;
            assert!(unprotect(&tampered).is_none());
        }
    }
}

#[cfg(windows)]
pub use imp::{protect, unprotect};

/// Seals the local secret files where there is no DPAPI, supplied by the
/// client: on Android, a Keystore key that never leaves the phone. Without
/// one those files are written in the clear, private to the app or user.
pub trait LocalProtector: Send + Sync {
    fn protect(&self, data: &[u8]) -> Option<Vec<u8>>;
    fn unprotect(&self, data: &[u8]) -> Option<Vec<u8>>;
}

#[cfg(not(windows))]
static PROTECTOR: std::sync::OnceLock<Box<dyn LocalProtector>> = std::sync::OnceLock::new();

/// Set once, before the first secret is read or written. Returns false when
/// one was already set, or on Windows, which keeps DPAPI.
pub fn set_local_protector(protector: Box<dyn LocalProtector>) -> bool {
    #[cfg(not(windows))]
    {
        PROTECTOR.set(protector).is_ok()
    }
    #[cfg(windows)]
    {
        drop(protector);
        false
    }
}

#[cfg(not(windows))]
pub fn protect(data: &[u8]) -> Option<Vec<u8>> {
    PROTECTOR.get()?.protect(data)
}

#[cfg(not(windows))]
pub fn unprotect(data: &[u8]) -> Option<Vec<u8>> {
    PROTECTOR.get()?.unprotect(data)
}
