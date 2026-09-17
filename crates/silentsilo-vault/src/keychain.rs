//! Writes to the OS keyring. Reads go through `keyring` unchanged.
//!
//! On Windows `keyring` writes with `CRED_PERSIST_ENTERPRISE`, which roams
//! with a domain profile to every machine the user signs in on. The device
//! secret and the storage secrets are machine-local by design, so they are
//! written here with `CRED_PERSIST_LOCAL_MACHINE`, in the layout `keyring`
//! reads. An entry written by an earlier build is rewritten on its next save.

/// Stores `password` under the entry `keyring::Entry::new(service, user)`
/// names.
pub(crate) fn set_password(service: &str, user: &str, password: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        windows_local::write(service, user, password)
    }
    #[cfg(not(windows))]
    {
        keyring::Entry::new(service, user)
            .and_then(|entry| entry.set_password(password))
            .map_err(|e| e.to_string())
    }
}

#[cfg(windows)]
mod windows_local {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::Security::Credentials::{
        CRED_FLAGS, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredWriteW,
    };
    use windows::core::PWSTR;
    use zeroize::Zeroize;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Same target name, user name, comment and UTF-16 blob as `keyring`
    /// 3.6, so its reads find the entry.
    pub(super) fn write(service: &str, user: &str, password: &str) -> Result<(), String> {
        let mut target = wide(&format!("{user}.{service}"));
        let mut username = wide(user);
        let mut alias = wide("");
        let mut comment = wide("keyring v3.6.3");
        let mut blob: Vec<u8> = password
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let credential = CREDENTIALW {
            Flags: CRED_FLAGS(0),
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(target.as_mut_ptr()),
            Comment: PWSTR(comment.as_mut_ptr()),
            LastWritten: FILETIME::default(),
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: PWSTR(alias.as_mut_ptr()),
            UserName: PWSTR(username.as_mut_ptr()),
        };
        // Safety: every pointer above outlives the call.
        let result = unsafe { CredWriteW(&credential, 0) }.map_err(|e| e.to_string());
        blob.zeroize();
        result
    }
}

#[cfg(all(test, windows))]
mod tests {
    use keyring::Entry;
    use windows::Win32::Security::Credentials::{
        CRED_PERSIST, CRED_PERSIST_ENTERPRISE, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
        CREDENTIALW, CredFree, CredReadW,
    };
    use windows::core::HSTRING;

    const SERVICE: &str = "com.silentsilo.test";

    fn persistence(user: &str) -> CRED_PERSIST {
        let target = HSTRING::from(format!("{user}.{SERVICE}"));
        let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
        // Safety: CredReadW allocates the credential, freed right after.
        unsafe {
            CredReadW(&target, CRED_TYPE_GENERIC, None, &mut credential).unwrap();
            let persist = (*credential).Persist;
            CredFree(credential as *const _);
            persist
        }
    }

    #[test]
    fn a_write_stays_on_this_machine_and_keyring_reads_it() {
        let user = format!("roundtrip:{}", uuid::Uuid::new_v4());
        let entry = Entry::new(SERVICE, &user).unwrap();

        // What an earlier build left: keyring's own write, which roams.
        entry.set_password("from 1.5.0").unwrap();
        assert_eq!(persistence(&user), CRED_PERSIST_ENTERPRISE);
        assert_eq!(entry.get_password().unwrap(), "from 1.5.0");

        super::set_password(SERVICE, &user, "{\"secret\":\"ünïcödé ✓\"}").unwrap();
        assert_eq!(persistence(&user), CRED_PERSIST_LOCAL_MACHINE);
        assert_eq!(
            Entry::new(SERVICE, &user).unwrap().get_password().unwrap(),
            "{\"secret\":\"ünïcödé ✓\"}"
        );

        entry.delete_credential().unwrap();
    }
}
