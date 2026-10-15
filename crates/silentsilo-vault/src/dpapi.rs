//! Sealing for the local secret files: the fallback for credentials, storage
//! settings and cloud tokens when the OS keyring will not hold them.
//!
//! On Windows the seal is DPAPI. Not a defence against software running as
//! the same user, which can call `CryptUnprotectData` itself; what it closes
//! off is the file being readable outside this user's live Windows logon: a
//! cloned disk, an offline mount, another account, a restored profile backup.
//! Elsewhere the client may supply a [`LocalProtector`] that plays the same
//! part, under the same file prefix.
//!
//! Fails closed. A protector that is there and refuses is an error, never a
//! file in the clear. Where there is no protector at all (Linux or a Mac
//! without a keyring), a secret is written in the clear only once the user
//! has agreed to it ([`allow_unprotected_secrets`]); until then the write is
//! refused with [`VaultError::SecretsUnprotected`], which the app turns into
//! that question.

use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::error::VaultError;

/// The prefix of a sealed file. A file without it was written in the clear,
/// by an earlier release or with the user's consent.
pub(crate) const SEALED: &[u8] = b"SSDPAPI1";

#[cfg(windows)]
mod imp {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use windows::core::PCWSTR;
    use zeroize::Zeroizing;

    /// Encrypts `data` under the current Windows user's DPAPI master key.
    /// `None` on any failure, which the caller refuses.
    pub fn protect(data: &[u8]) -> Option<Vec<u8>> {
        let mut input = Zeroizing::new(data.to_vec());
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
    /// account that originally called `protect`. The buffer Windows hands
    /// back is wiped before it is freed.
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
            std::ptr::write_bytes(blob_out.pbData, 0, blob_out.cbData as usize);
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
use imp::{protect, unprotect};

/// Seals the local secret files where there is no DPAPI, supplied by the
/// client: on Android, a Keystore key that never leaves the phone; on an
/// iPhone, a key in its Keychain. A protector that returns `None` refuses the
/// write: nothing is written in the clear in its place.
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
fn protect(data: &[u8]) -> Option<Vec<u8>> {
    PROTECTOR.get()?.protect(data)
}

#[cfg(not(windows))]
fn unprotect(data: &[u8]) -> Option<Vec<u8>> {
    PROTECTOR.get()?.unprotect(data)
}

/// Whether this device can seal a secret file: DPAPI on Windows, a
/// [`LocalProtector`] elsewhere. Without one, a secret the keyring will not
/// hold is written only with the user's consent.
pub fn local_secrets_protected() -> bool {
    #[cfg(windows)]
    {
        true
    }
    #[cfg(not(windows))]
    {
        PROTECTOR.get().is_some()
    }
}

/// The marker that records the user's consent. Machine-local, beside the
/// files it is about; its content is not read.
fn consent_path() -> PathBuf {
    crate::workdir::work_base()
        .join("secrets")
        .join("allow-unprotected")
}

/// Records whether the user agreed to keep secrets in files only their
/// account can read, on a device with no keyring and no protector. Asked
/// after a write failed with [`VaultError::SecretsUnprotected`]; the write is
/// then tried again. Kept across restarts until withdrawn.
pub fn allow_unprotected_secrets(allowed: bool) -> Result<(), VaultError> {
    let path = consent_path();
    if allowed {
        crate::workdir::write_private(&path, b"1")?;
    } else {
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
    }
    Ok(())
}

/// Whether [`allow_unprotected_secrets`] was given.
pub fn unprotected_secrets_allowed() -> bool {
    consent_path().is_file()
}

/// Seals bytes for this device, or `None` when it cannot.
type Seal = fn(&[u8]) -> Option<Vec<u8>>;

/// What goes into a secret file: the bytes sealed, or in the clear only
/// where there is no protector and the user agreed.
pub(crate) fn seal_secret(data: &[u8]) -> Result<Vec<u8>, VaultError> {
    seal_with(
        data,
        local_secrets_protected().then_some(protect as Seal),
        unprotected_secrets_allowed(),
    )
}

/// What goes into a file that holds nothing secret but is sealed where it
/// can be: sealed when there is a protector, which must then work, and in
/// the clear otherwise.
pub(crate) fn seal_if_possible(data: &[u8]) -> Result<Vec<u8>, VaultError> {
    seal_with(
        data,
        local_secrets_protected().then_some(protect as Seal),
        true,
    )
}

fn seal_with(
    data: &[u8],
    protector: Option<Seal>,
    clear_allowed: bool,
) -> Result<Vec<u8>, VaultError> {
    match protector {
        Some(protect) => {
            let sealed = protect(data).ok_or_else(|| {
                VaultError::Crypto(
                    "this device's key for local secrets did not answer, so nothing was written"
                        .into(),
                )
            })?;
            let mut out = SEALED.to_vec();
            out.extend_from_slice(&sealed);
            Ok(out)
        }
        None if clear_allowed => Ok(data.to_vec()),
        None => Err(VaultError::SecretsUnprotected),
    }
}

/// The content of a local secret file: unsealed, or as it is when it was
/// written in the clear. `None` when it is sealed and this device cannot
/// open it.
pub(crate) fn open_sealed(raw: Vec<u8>) -> Option<Zeroizing<Vec<u8>>> {
    match raw.strip_prefix(SEALED) {
        Some(sealed) => unprotect(sealed).map(Zeroizing::new),
        None => Some(Zeroizing::new(raw)),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Installs a stand-in protector where the platform has none, so the
    /// tests of the fallback files run the sealed path everywhere. Windows
    /// keeps DPAPI.
    pub(crate) fn test_protector() {
        #[cfg(not(windows))]
        {
            struct Flip;
            impl LocalProtector for Flip {
                fn protect(&self, data: &[u8]) -> Option<Vec<u8>> {
                    Some(data.iter().map(|b| b ^ 0x5a).collect())
                }
                fn unprotect(&self, data: &[u8]) -> Option<Vec<u8>> {
                    self.protect(data)
                }
            }
            let _ = set_local_protector(Box::new(Flip));
        }
    }

    fn refuses(_: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn reverses(data: &[u8]) -> Option<Vec<u8>> {
        Some(data.iter().rev().copied().collect())
    }

    #[test]
    fn a_protector_that_refuses_writes_nothing_in_the_clear() {
        for allowed in [false, true] {
            let err = seal_with(b"secret", Some(refuses as Seal), allowed).unwrap_err();
            assert!(matches!(err, VaultError::Crypto(_)), "{err:?}");
        }
    }

    #[test]
    fn without_a_protector_a_secret_needs_consent() {
        let err = seal_with(b"secret", None, false).unwrap_err();
        assert!(matches!(err, VaultError::SecretsUnprotected), "{err:?}");
        assert!(
            err.to_string().contains("err.secrets_unprotected"),
            "the app translates it by its key: {err}"
        );
        assert_eq!(seal_with(b"secret", None, true).unwrap(), b"secret");
    }

    #[test]
    fn a_sealed_file_carries_the_prefix() {
        let out = seal_with(b"abc", Some(reverses as Seal), false).unwrap();
        assert_eq!(out, [SEALED, b"cba"].concat());
        // The prefix sealed files carry, taken from release 1.10.x. A change
        // means every sealed secret file reads as one written in the clear.
        assert_eq!(out, b"SSDPAPI1cba");
    }

    #[test]
    fn a_file_in_the_clear_reads_as_it_is() {
        assert_eq!(
            open_sealed(b"{\"a\":1}".to_vec())
                .as_deref()
                .map(Vec::as_slice),
            Some(&b"{\"a\":1}"[..])
        );
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_seals_every_secret_file_here() {
        let sealed = seal_secret(b"secret").unwrap();
        assert!(sealed.starts_with(SEALED));
        assert_eq!(
            open_sealed(sealed).as_deref().map(Vec::as_slice),
            Some(&b"secret"[..])
        );
    }

    #[test]
    fn consent_is_kept_and_withdrawn() {
        let _serial = crate::s3_store::tests::keyring_lock();
        let before = unprotected_secrets_allowed();
        allow_unprotected_secrets(true).unwrap();
        assert!(unprotected_secrets_allowed());
        allow_unprotected_secrets(false).unwrap();
        assert!(!unprotected_secrets_allowed());
        allow_unprotected_secrets(before).unwrap();
    }
}
