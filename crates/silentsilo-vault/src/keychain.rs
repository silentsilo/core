//! Writes to the OS keyring. Reads go through `keyring`.
//!
//! On an iPhone every entry is written "this device only", so it stays out
//! of iCloud and computer backups; entries an earlier release wrote are moved
//! there on their first read. On a Mac `keyring` writes to the login
//! keychain, which neither syncs to iCloud Keychain nor moves to another Mac
//! except as a whole, under the login password.
//!
//! On Windows `keyring` writes with `CRED_PERSIST_ENTERPRISE`, which roams
//! with a domain profile to every machine the user signs in on. The device
//! secret and the storage secrets are machine-local by design, so they are
//! written here with `CRED_PERSIST_LOCAL_MACHINE`, in the layout `keyring`
//! reads. An entry written by an earlier build is rewritten on its next save.

/// The keyring service every entry is stored under.
///
/// Test runs get one of their own, by the same switch that moves their files
/// to `target/test-work` (debug builds only, see `workdir::work_base`): they
/// wrote into the app's entries, left hundreds behind on a developer machine,
/// and a full roaming store made Credential Manager refuse writes.
pub(crate) fn service() -> &'static str {
    #[cfg(debug_assertions)]
    if std::env::var_os("SILENTSILO_TEST_WORK_BASE").is_some_and(|d| !d.is_empty()) {
        return "com.silentsilo.test";
    }
    "com.silentsilo.desktop"
}

/// What this run has seen of the keyring: 0 nothing yet, 1 it kept a
/// secret, 2 it refused or lost one.
static SEEN: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Records whether the keyring kept a secret just written to it.
pub(crate) fn note(kept: bool) {
    SEEN.store(
        if kept { 1 } else { 2 },
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// Whether the OS keyring kept the last device secret written to it in this
/// run (`save_credentials`, the write every new silo makes), or `None`
/// before the first. Storage settings and cloud tokens are not counted:
/// Credential Manager refuses a large one by size, which says nothing about
/// the keyring. On Linux this is what tells a desktop
/// with a working Secret Service from one without (a bare window manager,
/// KWallet without its Secret Service API), where secrets need a file and
/// the user's consent to one.
pub fn keyring_keeps_secrets() -> Option<bool> {
    match SEEN.load(std::sync::atomic::Ordering::Relaxed) {
        1 => Some(true),
        2 => Some(false),
        _ => None,
    }
}

/// Stores `password` under the entry `keyring::Entry::new(service, user)`
/// names.
pub(crate) fn set_password(service: &str, user: &str, password: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        windows_local::write(service, user, password)
    }
    #[cfg(target_os = "ios")]
    {
        ios::write(service, user, password)
    }
    #[cfg(not(any(windows, target_os = "ios")))]
    {
        keyring::Entry::new(service, user)
            .and_then(|entry| entry.set_password(password))
            .map_err(|e| e.to_string())
    }
}

/// Reads the entry `user` under [`service`].
///
/// On an iPhone the first read of an entry in a process also makes it
/// "this device only": an earlier release wrote it with the default class,
/// which goes into an iCloud or computer backup and comes back on another
/// phone restored from it.
pub(crate) fn get_password(user: &str) -> Result<String, keyring::Error> {
    let value = keyring::Entry::new(service(), user)?.get_password()?;
    #[cfg(target_os = "ios")]
    ios::keep_on_this_device_once(service(), user);
    Ok(value)
}

/// The iOS Keychain, written directly rather than through `keyring`, which
/// takes the default accessibility class. `AfterFirstUnlockThisDeviceOnly`:
/// readable by a sync started in the background once the phone has been
/// unlocked since boot, and never restored from a backup onto another
/// phone. Same class, service and account as `keyring` reads.
///
/// Not compiled on the machines this crate is tested on; type-checked
/// against the macOS SDK bindings, which share every symbol used here.
#[cfg(target_os = "ios")]
mod ios {
    use std::collections::HashSet;
    use std::sync::Mutex;

    use core_foundation::base::{CFType, TCFType};
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::{CFString, CFStringRef};
    use security_framework_sys::access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    use security_framework_sys::base::errSecItemNotFound;
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecValueData,
    };
    use security_framework_sys::keychain_item::{SecItemAdd, SecItemUpdate};

    // The attribute key itself, which the sys crate does not export.
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecAttrAccessible: CFStringRef;
    }

    fn query(service: &str, user: &str) -> Vec<(CFString, CFType)> {
        // SAFETY: Security.framework statics, valid for the life of the
        // process and only borrowed here.
        unsafe {
            vec![
                (
                    CFString::wrap_under_get_rule(kSecClass),
                    CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrService),
                    CFString::new(service).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrAccount),
                    CFString::new(user).into_CFType(),
                ),
            ]
        }
    }

    fn this_device_only() -> (CFString, CFType) {
        // SAFETY: as above.
        unsafe {
            (
                CFString::wrap_under_get_rule(kSecAttrAccessible),
                CFString::wrap_under_get_rule(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
                    .into_CFType(),
            )
        }
    }

    fn update(service: &str, user: &str, changes: &[(CFString, CFType)]) -> i32 {
        let query = CFDictionary::from_CFType_pairs(&query(service, user));
        let changes = CFDictionary::from_CFType_pairs(changes);
        // SAFETY: both dictionaries are live for the call.
        unsafe { SecItemUpdate(query.as_concrete_TypeRef(), changes.as_concrete_TypeRef()) }
    }

    /// Replaces the entry in place, or adds it: never deleted first, so a
    /// failed write cannot leave the entry gone.
    pub(super) fn write(service: &str, user: &str, password: &str) -> Result<(), String> {
        let data = CFData::from_buffer(password.as_bytes());
        // SAFETY: as above.
        let value = (
            unsafe { CFString::wrap_under_get_rule(kSecValueData) },
            data.into_CFType(),
        );
        let changes = [value, this_device_only()];
        let mut status = update(service, user, &changes);
        if status == errSecItemNotFound {
            let mut item = query(service, user);
            item.extend(changes);
            let item = CFDictionary::from_CFType_pairs(&item);
            // SAFETY: the dictionary is live for the call; no result wanted.
            status = unsafe { SecItemAdd(item.as_concrete_TypeRef(), std::ptr::null_mut()) };
        }
        if status == 0 {
            Ok(())
        } else {
            Err(format!("the keychain refused the write ({status})"))
        }
    }

    /// Moves an entry an earlier release wrote to this device only. Once per
    /// entry and process; best effort, the next launch tries again.
    pub(super) fn keep_on_this_device_once(service: &str, user: &str) {
        static DONE: Mutex<Option<HashSet<String>>> = Mutex::new(None);
        let Ok(mut done) = DONE.lock() else { return };
        let done = done.get_or_insert_with(HashSet::new);
        if done.contains(user) {
            return;
        }
        if update(service, user, &[this_device_only()]) == 0 {
            done.insert(user.to_string());
        }
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
        let _cleanup = Cleanup(&user);

        // What an earlier build left: keyring's own write, which roams.
        // Opt-in: a roaming entry comes back from the profile after the
        // delete, and those filled the user's store once already.
        if std::env::var_os("SILENTSILO_TEST_ROAMING").is_some() {
            entry.set_password("from 1.5.0").unwrap();
            assert_eq!(persistence(&user), CRED_PERSIST_ENTERPRISE);
            assert_eq!(entry.get_password().unwrap(), "from 1.5.0");
        }

        super::set_password(SERVICE, &user, "{\"secret\":\"ünïcödé ✓\"}").unwrap();
        assert_eq!(persistence(&user), CRED_PERSIST_LOCAL_MACHINE);
        assert_eq!(
            Entry::new(SERVICE, &user).unwrap().get_password().unwrap(),
            "{\"secret\":\"ünïcödé ✓\"}"
        );
    }

    /// Deletes the test entry even when an assertion fails, and retries:
    /// Credential Manager now and then drops a delete, and what is left
    /// piles up in the user's own store.
    struct Cleanup<'a>(&'a str);

    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            for _ in 0..5 {
                let Ok(entry) = Entry::new(SERVICE, self.0) else {
                    return;
                };
                let _ = entry.delete_credential();
                if matches!(entry.get_password(), Err(keyring::Error::NoEntry)) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(30));
            }
        }
    }
}
