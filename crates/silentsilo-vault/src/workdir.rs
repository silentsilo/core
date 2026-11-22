//! Where a silo's working copy and opened files live. Not in the silo
//! folder, which the user may have put on a NAS, an external drive or a
//! OneDrive-redirected Documents. Anything decrypted lives here on the
//! local machine and is wiped when the silo locks; the ciphered working copy
//! and its sealed key stay, so the next unlock reuses them. What stays in
//! the silo folder is ciphertext, a public salt and wrapped keys.

use std::path::{Path, PathBuf};

use uuid::Uuid;

/// Distinguishes this app's derived directory names from anyone else's.
const WORK_NAMESPACE: Uuid = Uuid::from_bytes([
    0x5c, 0x1e, 0x7a, 0x30, 0x9b, 0x44, 0x4e, 0x1a, 0xa2, 0x77, 0x63, 0x0f, 0x8d, 0x21, 0x4b, 0x90,
]);

static WORK_BASE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Sets where [`work_base`] points, for a platform with no per-user local
/// directory of its own, such as a phone app's private storage. The first
/// call wins; the desktop never calls it.
pub fn set_work_base(dir: PathBuf) -> bool {
    WORK_BASE.set(dir).is_ok()
}

/// The machine-local base for every silo's scratch space.
///
/// Local rather than roaming on Windows: a roaming profile is copied to a
/// domain server at logon, which would defeat the point of moving plaintext
/// out of a synced folder in the first place.
pub fn work_base() -> PathBuf {
    if let Some(dir) = WORK_BASE.get() {
        return dir.clone();
    }
    // Debug builds only: the test suites point this at a directory of their
    // own (`.cargo/config.toml`), so a test run never leaves a working copy
    // or a secret in the real one. A release build has no switch that moves
    // plaintext somewhere else.
    #[cfg(debug_assertions)]
    if let Some(dir) = std::env::var_os("SILENTSILO_TEST_WORK_BASE").filter(|d| !d.is_empty()) {
        return PathBuf::from(dir);
    }
    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(local).join("SilentSilo").join("work");
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(cache) = std::env::var("XDG_CACHE_HOME") {
            return PathBuf::from(cache).join("silentsilo").join("work");
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home)
                .join(".cache")
                .join("silentsilo")
                .join("work");
        }
    }
    std::env::temp_dir().join("silentsilo-work")
}

/// The base for one silo. In a debug build a silo in the system's temp
/// folder, which is where tests make theirs, keeps its scratch there too:
/// a suite without `SILENTSILO_TEST_WORK_BASE` (desktop, mobile) left
/// thousands of working copies under the real one. No real silo lives in
/// the temp folder, and a release build always takes `work_base`.
fn base_for(silo_root: &Path) -> PathBuf {
    #[cfg(debug_assertions)]
    if std::env::var_os("SILENTSILO_TEST_WORK_BASE").is_none()
        && silo_root.starts_with(std::env::temp_dir())
    {
        return std::env::temp_dir().join("silentsilo-test-work");
    }
    let _ = silo_root;
    work_base()
}

/// The scratch directory for the silo stored at `silo_root`.
///
/// Derived from the path rather than from the silo's id, so it can be
/// answered without opening anything: `VaultPaths::exists()` needs it
/// before there is a session to ask. Moving a silo folder simply earns it a
/// new scratch directory; nothing here is more than `vault.db.enc` rebuilds.
pub fn work_dir_for(silo_root: &Path) -> PathBuf {
    let key = silo_root.to_string_lossy().to_lowercase();
    base_for(silo_root)
        .join("open")
        .join(Uuid::new_v5(&WORK_NAMESPACE, key.as_bytes()).to_string())
}

/// Where a silo's secrets go when the OS keyring will not hold them.
/// Keyed by the silo's id rather than its path, unlike everything else
/// here: a silo moved to another drive must not look unprovisioned.
/// Outside the silo folder, because the folder alone is not supposed to
/// open the vault.
pub fn secrets_dir_for(silo_id: Uuid) -> PathBuf {
    work_base().join("secrets").join(silo_id.to_string())
}

/// Writes a file only this user can read, creating its directory first.
///
/// Atomic and durable: the bytes go to a sibling temp file, are synced, and
/// take the path by rename. Everything routed through here is a key
/// envelope, a registry or a salt, files whose truncate-in-place corruption
/// during a crash is a lockout, and for a FIDO-only silo with no recovery
/// code, a permanent one.
///
/// The mode matters on Unix alone: Windows inherits a per-user ACL from
/// `LOCALAPPDATA`, while a fresh file under `~/.cache` is world-readable by
/// default on most distributions.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // Only a missing parent is created and narrowed. An existing directory
    // keeps its permissions: several callers write into the silo folder,
    // which is the user's own and not this function's to re-mode.
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        create_private_dir(parent)?;
    }

    silentsilo_core::write_replacing(path, bytes, |at| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(at)
    })
}

/// Creates a directory no other local user can enter. Everything this
/// module hands out holds plaintext, and `create_dir_all` leaves 0755
/// under a default umask. Only the leaf is narrowed; the directories above
/// it hold nothing but derived names.
pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }

    Ok(())
}

/// Keeps `dir` and everything in it out of Time Machine on a Mac and out of
/// iCloud and computer backups on an iPhone, the way `tmutil addexclusion`
/// does. Nothing to do elsewhere. Best effort: returns whether it took.
///
/// The working copy is ciphered, but the files a person opens are
/// decrypted into this folder until the silo locks, and a backup taken in
/// between would keep them for as long as the backup lives.
pub fn exclude_from_backup(dir: &Path) -> bool {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        apple::exclude_from_backup(dir)
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        let _ = dir;
        true
    }
}

/// `NSURLIsExcludedFromBackupKey`, through Core Foundation. A sticky
/// exclusion: it is an attribute of the folder, so it holds for what is
/// created inside it later and survives the folder being moved.
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple {
    use std::path::Path;

    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::url::CFURL;
    use core_foundation_sys::base::CFRelease;
    use core_foundation_sys::string::CFStringRef;
    use core_foundation_sys::url::CFURLSetResourcePropertyForKey;

    // Behind a feature flag in the sys crate; every macOS and iOS this
    // build supports has it.
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFURLIsExcludedFromBackupKey: CFStringRef;
    }

    pub(super) fn exclude_from_backup(dir: &Path) -> bool {
        let Some(url) = CFURL::from_path(dir, true) else {
            return false;
        };
        let mut error = std::ptr::null_mut();
        // SAFETY: the URL and the boolean are live for the call, the key is
        // a framework static, and `error` is a valid out-pointer whose
        // result, when set, is ours to release.
        unsafe {
            let done = CFURLSetResourcePropertyForKey(
                url.as_concrete_TypeRef(),
                kCFURLIsExcludedFromBackupKey,
                CFBoolean::true_value().as_CFTypeRef(),
                &mut error,
            ) != 0;
            if !error.is_null() {
                CFRelease(error as _);
            }
            done
        }
    }
}

/// Marks a file the app just decrypted as read-only.
///
/// Read-only is wanted for one reason: an editor must not save into a copy
/// that is about to be wiped. `Permissions::set_readonly(true)` achieves that
/// on Unix by clearing the write bits alone, so a file created under the
/// usual umask lands on 0444 and every account on the machine can read it.
/// 0400 stops the editor just as well and stops the neighbours too.
pub fn seal_readonly(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400));
    }

    #[cfg(not(unix))]
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_readonly(true);
        let _ = std::fs::set_permissions(path, perms);
    }
}

/// The name a decrypted copy gets on disk: random, with the original
/// extension so the OS still picks the right application.
///
/// The original name stays out of the file system entirely. NTFS keeps a
/// name in its change journal from the moment the file is created, for
/// weeks, so renaming it before deletion would hide nothing; viewers add
/// the path to their recent lists too. An extension that is not short and
/// plain is dropped rather than carried.
pub fn opened_file_name(original: &str) -> String {
    use rand::Rng;
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    let stem: String = (0..16)
        .map(|_| LETTERS[rng.random_range(0..LETTERS.len())] as char)
        .collect();
    let ext = Path::new(original)
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| (1..=16).contains(&e.len()) && e.chars().all(|c| c.is_ascii_alphanumeric()));
    match ext {
        Some(ext) => format!("{stem}.{ext}"),
        None => stem,
    }
}

/// Overwrites a decrypted file with random bytes, flushes that to the disk,
/// then deletes it. A plain delete leaves the content in its clusters for an
/// undelete tool, and a small file whole in its MFT record (both seen on an
/// unencrypted NTFS volume on SSDs, November 2026).
///
/// What the flash keeps underneath is out of reach: this defeats recovery
/// through the file system, not a lab reading the chips. Fails without
/// touching the file when another application has it open on Windows, which
/// is how a caller learns it is still in use.
///
/// Only the file itself is overwritten. A link (symbolic, junction) loses its
/// name and its target is left alone, as `remove_dir_all` does; a file with
/// another hard link loses this name only.
pub fn shred_file(path: &Path) -> std::io::Result<()> {
    use rand::RngCore;
    use std::io::Write;
    const CHUNK: u64 = 1 << 20;

    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return remove_link(path);
    }
    clear_readonly(path);
    let mut file = open_to_shred(path)?;
    let meta = file.metadata()?;
    let len = meta.len();
    if meta.file_type().is_file() && link_count(&file, &meta) == 1 && len > 0 {
        let mut buf = vec![0u8; len.min(CHUNK) as usize];
        let mut rng = rand::rng();
        let mut left = len;
        while left > 0 {
            let n = left.min(CHUNK) as usize;
            rng.fill_bytes(&mut buf[..n]);
            file.write_all(&buf[..n])?;
            left -= n as u64;
        }
        file.sync_all()?;
    }
    drop(file);
    std::fs::remove_file(path)
}

/// Opens without following a link. On Windows no sharing at all: a viewer
/// that holds the file, even one that lets others write, makes this fail
/// rather than see its copy overwritten.
fn open_to_shred(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

#[cfg(unix)]
fn link_count(_file: &std::fs::File, meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.nlink()
}

#[cfg(windows)]
fn link_count(file: &std::fs::File, _meta: &std::fs::Metadata) -> u64 {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is live for the call and `info` is a valid out-pointer.
    match unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) } {
        Ok(()) => u64::from(info.nNumberOfLinks),
        // Unknown: treat it as shared, so nothing outside is overwritten.
        Err(_) => u64::MAX,
    }
}

#[cfg(not(any(unix, windows)))]
fn link_count(_file: &std::fs::File, _meta: &std::fs::Metadata) -> u64 {
    1
}

/// Removes a link, or anything that is neither a file nor a directory, by
/// name. A directory link on Windows goes with `remove_dir`.
fn remove_link(path: &Path) -> std::io::Result<()> {
    std::fs::remove_file(path).or_else(|e| std::fs::remove_dir(path).map_err(|_| e))
}

/// Whether anything is left at `path`, a dangling link included.
fn still_there(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Shreds every file under `dir` and removes `dir`. Returns whether
/// something could not go, which means another application holds it. A
/// link is removed, never followed.
fn shred_tree(dir: &Path) -> bool {
    match std::fs::symlink_metadata(dir) {
        Err(_) => return false,
        Ok(meta) if !meta.file_type().is_dir() => {
            return shred_file(dir).is_err() && still_there(dir);
        }
        Ok(_) => {}
    }
    let mut left = false;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            let gone = if is_dir {
                !shred_tree(&path)
            } else if KEPT_ACROSS_LOCKS
                .iter()
                .any(|kept| entry.file_name() == *kept)
            {
                // Ciphered or sealed: nothing to overwrite.
                std::fs::remove_file(&path).is_ok() || !still_there(&path)
            } else {
                shred_file(&path).is_ok() || !still_there(&path)
            };
            left |= !gone;
        }
    }
    if std::fs::remove_dir(dir).is_err() && still_there(dir) {
        left = true;
    }
    left
}

/// Shreds `path`, a file or a directory. Returns whether something is left.
pub fn shred_path(path: &Path) -> bool {
    shred_tree(path)
}

/// The applications that have `path` open, by name, other than this one.
/// Asked through the Restart Manager, which looks without opening the file:
/// probing it with an exclusive open instead could make a viewer that opens
/// it at that instant fail. Windows only; elsewhere, and when the question
/// cannot be answered, `None`.
pub fn holders(path: &Path) -> Option<Vec<String>> {
    #[cfg(windows)]
    {
        restart_manager::holders(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}

/// Whether another application has `path` open, as far as [`holders`] can
/// tell.
pub fn is_held(path: &Path) -> bool {
    holders(path).is_some_and(|apps| !apps.is_empty())
}

#[cfg(windows)]
mod restart_manager {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows::Win32::System::RestartManager::{
        CCH_RM_SESSION_KEY, RM_PROCESS_INFO, RmEndSession, RmGetList, RmRegisterResources,
        RmStartSession,
    };
    use windows::core::{PCWSTR, PWSTR};

    pub(super) fn holders(path: &Path) -> Option<Vec<String>> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
        let mut session = 0u32;
        // SAFETY: every pointer handed over points into a live local buffer of
        // the size the call is told, and the session is ended on every path.
        unsafe {
            if RmStartSession(&mut session, None, PWSTR(key.as_mut_ptr())) != ERROR_SUCCESS {
                return None;
            }
            let found = (|| {
                let files = [PCWSTR(wide.as_ptr())];
                if RmRegisterResources(session, Some(&files), None, None) != ERROR_SUCCESS {
                    return None;
                }
                let mut infos: Vec<RM_PROCESS_INFO> = Vec::new();
                for _ in 0..3 {
                    let (mut needed, mut count, mut reasons) = (0u32, infos.len() as u32, 0u32);
                    let ptr = if infos.is_empty() {
                        None
                    } else {
                        Some(infos.as_mut_ptr())
                    };
                    let rc = RmGetList(session, &mut needed, &mut count, ptr, &mut reasons);
                    if rc == ERROR_SUCCESS {
                        infos.truncate(count as usize);
                        let me = std::process::id();
                        return Some(
                            infos
                                .iter()
                                .filter(|info| info.Process.dwProcessId != me)
                                .map(|info| {
                                    let name = &info.strAppName;
                                    let end =
                                        name.iter().position(|&c| c == 0).unwrap_or(name.len());
                                    String::from_utf16_lossy(&name[..end])
                                })
                                .collect(),
                        );
                    }
                    if rc != ERROR_MORE_DATA {
                        return None;
                    }
                    infos = vec![std::mem::zeroed(); needed as usize];
                }
                None
            })();
            let _ = RmEndSession(session);
            found
        }
    }
}

/// Turns on EFS for the folder decrypted files are opened from, so what
/// is written there later is encrypted on disk under this Windows account,
/// including the lock and temp files a viewer creates beside the document.
/// The viewers read it as usual. Best effort: Windows Home cannot encrypt,
/// and a FAT volume or a policy may refuse; then nothing changes. Returns
/// whether the folder is encrypted.
pub fn encrypt_scratch_dir(dir: &Path) -> bool {
    #[cfg(windows)]
    {
        efs::encrypt_dir(dir)
    }
    #[cfg(not(windows))]
    {
        let _ = dir;
        false
    }
}

#[cfg(windows)]
mod efs {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows::Win32::Storage::FileSystem::{
        EncryptFileW, FILE_ATTRIBUTE_ENCRYPTED, GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
    };
    use windows::core::PCWSTR;

    pub(super) fn encrypt_dir(dir: &Path) -> bool {
        let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
        let path = PCWSTR(wide.as_ptr());
        // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives both
        // calls; neither keeps the pointer.
        unsafe {
            let attrs = GetFileAttributesW(path);
            if attrs != INVALID_FILE_ATTRIBUTES && attrs & FILE_ATTRIBUTE_ENCRYPTED.0 != 0 {
                return true;
            }
            EncryptFileW(path).is_ok()
        }
    }
}

/// Machine-local bookkeeping that outlives a lock.
///
/// Separate from the scratch directory precisely so that wiping plaintext
/// does not also throw away the record of which blobs are already in the
/// bucket. That record is expensive to rebuild and harmless to keep.
pub fn cache_dir_for(silo_root: &Path) -> PathBuf {
    let key = silo_root.to_string_lossy().to_lowercase();
    base_for(silo_root)
        .join("cache")
        .join(Uuid::new_v5(&WORK_NAMESPACE, key.as_bytes()).to_string())
}

/// Removes this machine's bookkeeping for a silo: which blobs it holds and
/// which have reached the bucket.
///
/// Kept out of `wipe_work_dir` on purpose. Locking a silo throws away its
/// plaintext and keeps this, because the record is expensive to rebuild and
/// harmless to keep. It is only wrong when the silo it describes has ceased
/// to exist, which is the one case this is for.
pub fn wipe_cache_dir(silo_root: &Path) {
    let _ = std::fs::remove_dir_all(cache_dir_for(silo_root));
}

/// Everything this machine holds for a silo outside the silo folder itself.
///
/// Both directories are keyed by the silo's path, not by its id, so a new
/// silo made in a folder a previous one used lands on the previous one's
/// state. Provisioning and deletion both call this so that the only thing a
/// path can hand to its next tenant is an empty directory.
pub fn wipe_machine_state(silo_root: &Path) {
    wipe_work_dir(silo_root);
    wipe_cache_dir(silo_root);
}

/// The files a lock leaves in a silo's scratch directory: the working copy
/// SQLCipher ciphers, its WAL and shared memory, and its page key sealed
/// under the DEK. Nothing else there survives a lock or a sweep.
pub const KEPT_ACROSS_LOCKS: [&str; 5] = [
    "vault.sqlcipher",
    "vault.sqlcipher-wal",
    "vault.sqlcipher-shm",
    "vault.key",
    "vault.key.next",
];

/// Removes a silo's scratch directory and everything in it, the ciphered
/// working copy included. For a silo that is gone or provisioned over.
pub fn wipe_work_dir(silo_root: &Path) {
    let dir = work_dir_for(silo_root);
    if !dir.exists() {
        return;
    }
    shred_tree(&dir);
}

/// Shreds everything readable in a silo's scratch directory: opened files,
/// a plaintext `vault.db` an earlier release left, anything not in
/// [`KEPT_ACROSS_LOCKS`]. Returns whether something could not be removed,
/// which means another application still holds it open.
pub fn wipe_plaintext(silo_root: &Path) -> bool {
    wipe_plaintext_in(&work_dir_for(silo_root))
}

fn wipe_plaintext_in(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut left = false;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if KEPT_ACROSS_LOCKS.iter().any(|kept| name == *kept) {
            continue;
        }
        left |= shred_path(&entry.path());
    }
    left
}

/// Clears the scratch of every silo not in `open`, including what a crash,
/// a kill or a power cut left behind. Plaintext goes; a ciphered working
/// copy stays for the next unlock, and a directory without a sealed page key
/// holds nothing that copy could open with, so it goes whole. Called with
/// nothing open when the app starts, and with the silos still open after
/// each lock. Returns how many directories still hold plaintext, which
/// means another application holds a file in them.
pub fn wipe_work_dirs_except(open: &[&Path]) -> usize {
    wipe_open_dirs_in(&work_base().join("open"), open)
}

fn wipe_open_dirs_in(base: &Path, open: &[&Path]) -> usize {
    let keep: Vec<std::ffi::OsString> = open
        .iter()
        .filter_map(|root| work_dir_for(root).file_name().map(|n| n.to_os_string()))
        .collect();
    let Ok(entries) = std::fs::read_dir(base) else {
        return 0;
    };
    let mut left = 0;
    for entry in entries.flatten() {
        if keep.contains(&entry.file_name()) {
            continue;
        }
        let path = entry.path();
        let has_key = ["vault.key", "vault.key.next"]
            .iter()
            .any(|key| path.join(key).is_file());
        if has_key {
            if wipe_plaintext_in(&path) {
                left += 1;
            }
            continue;
        }
        if shred_tree(&path) {
            left += 1;
        }
    }
    left
}

fn clear_readonly(path: &Path) {
    // Owner only. `set_readonly(false)` sets the write bit for group and
    // world too, which would widen a 0400 file on its way to being deleted.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() | 0o200;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
        }
    }

    #[cfg(not(unix))]
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        let _ = std::fs::set_permissions(path, perms);
    }
}

/// Whether a path looks like it is inside a consumer sync client's folder.
/// Advisory only: it is their disk. Name matching is crude and misses
/// relocated folders, and a false negative costs nothing since the
/// plaintext never goes into the silo folder either way.
pub fn detect_sync_provider(path: &Path) -> Option<&'static str> {
    let text = path.to_string_lossy().to_lowercase();
    for (needle, name) in [
        ("onedrive", "OneDrive"),
        ("dropbox", "Dropbox"),
        ("google drive", "Google Drive"),
        ("googledrive", "Google Drive"),
        ("g:\\my drive", "Google Drive"),
        ("icloud", "iCloud Drive"),
        // Where a Mac keeps iCloud Drive: ~/Library/Mobile Documents.
        ("mobile documents", "iCloud Drive"),
        ("nextcloud", "Nextcloud"),
        ("mega\\", "MEGA"),
        ("pcloud", "pCloud"),
        ("yandexdisk", "Yandex Disk"),
        ("box sync", "Box"),
    ] {
        if text.contains(needle) {
            return Some(name);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Takes on a Mac and an iPhone, and is nothing to do elsewhere; either
    /// way a silo opens.
    #[test]
    fn the_scratch_folder_is_kept_out_of_backups() {
        let dir = tempfile::tempdir().unwrap();
        assert!(exclude_from_backup(dir.path()));
    }

    #[test]
    fn icloud_drive_is_seen_by_its_folder_on_a_mac() {
        let path = Path::new("/Users/sam/Library/Mobile Documents/com~apple~CloudDocs/Silos");
        assert_eq!(detect_sync_provider(path), Some("iCloud Drive"));
    }

    #[test]
    fn two_silos_get_separate_scratch_directories() {
        let a = work_dir_for(Path::new("/silos/personal"));
        let b = work_dir_for(Path::new("/silos/work"));
        assert_ne!(a, b);
    }

    #[test]
    fn the_same_silo_always_gets_the_same_directory() {
        // It has to be answerable without opening anything, and stable
        // across launches, or a lock would fail to find what to wipe.
        assert_eq!(
            work_dir_for(Path::new("/silos/personal")),
            work_dir_for(Path::new("/silos/personal"))
        );
    }

    #[test]
    fn windows_path_casing_does_not_split_a_silo_in_two() {
        // `C:\Users` and `c:\users` are the same directory, and two scratch
        // spaces for one silo would mean a lock wiping only half of it.
        assert_eq!(
            work_dir_for(Path::new(r"C:\Users\sam\Silos\Personal")),
            work_dir_for(Path::new(r"c:\users\sam\silos\personal"))
        );
    }

    #[test]
    fn scratch_never_lands_inside_the_silo_itself() {
        // The whole point: nothing decrypted may be written where the user
        // pointed the silo.
        let root = Path::new(r"C:\Users\sam\OneDrive\Silos\Personal");
        assert!(!work_dir_for(root).starts_with(root));
    }

    #[test]
    fn common_sync_folders_are_recognised() {
        assert_eq!(
            detect_sync_provider(Path::new(r"C:\Users\sam\OneDrive\Documents\Silo")),
            Some("OneDrive")
        );
        assert_eq!(
            detect_sync_provider(Path::new("/home/sam/Dropbox/silo")),
            Some("Dropbox")
        );
        assert_eq!(
            detect_sync_provider(Path::new(r"C:\Users\sam\Google Drive\silo")),
            Some("Google Drive")
        );
    }

    #[test]
    fn an_ordinary_folder_is_not_flagged() {
        assert!(detect_sync_provider(Path::new(r"D:\Silos\Personal")).is_none());
        assert!(detect_sync_provider(Path::new("/home/sam/silos/personal")).is_none());
    }

    #[test]
    fn wiping_a_directory_that_is_not_there_is_not_an_error() {
        wipe_work_dir(Path::new("/silos/never-existed"));
    }

    #[test]
    fn a_sealed_file_cannot_be_written_over() {
        // The reason read-only is wanted at all: an editor must not save into
        // a copy that is about to be wiped.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("opened.txt");
        std::fs::write(&path, b"plaintext").unwrap();

        seal_readonly(&path);

        assert!(
            std::fs::metadata(&path).unwrap().permissions().readonly(),
            "an opened file must be read-only"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_sealed_file_is_not_readable_by_other_users() {
        // `set_readonly(true)` only clears the write bits, so a file created
        // under the usual umask stayed at 0444 and every account on a shared
        // machine could read what the silo owner had open.
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("opened.txt");
        std::fs::write(&path, b"plaintext").unwrap();

        seal_readonly(&path);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o400, "got {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn the_scratch_directory_is_not_readable_by_other_users() {
        // It holds files the user opened, in plaintext.
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("work").join("nested");

        create_private_dir(&dir).unwrap();

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "got {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn making_a_file_deletable_again_does_not_widen_it() {
        // Wiping clears read-only first, because Windows will not delete a
        // read-only file. Doing that with `set_readonly(false)` sets the write
        // bit for group and world on the way past.
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("opened.txt");
        std::fs::write(&path, b"plaintext").unwrap();
        seal_readonly(&path);

        clear_readonly(&path);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
    }

    #[test]
    fn a_sweep_keeps_ciphered_copies_and_removes_plaintext() {
        let tmp = tempfile::tempdir().unwrap();
        let sandbox = tmp.path().join("open");
        let dir_of = |name: &str| {
            let root = tmp.path().join(name);
            sandbox.join(work_dir_for(&root).file_name().unwrap())
        };
        let (open, locked, crashed) = (dir_of("open"), dir_of("locked"), dir_of("crashed"));
        for dir in [&open, &locked, &crashed] {
            std::fs::create_dir_all(dir.join("open")).unwrap();
            let file = dir.join("open").join("opened.txt");
            std::fs::write(&file, b"plaintext").unwrap();
            seal_readonly(&file);
            std::fs::write(dir.join("vault.db"), b"plaintext").unwrap();
            std::fs::write(dir.join("vault.sqlcipher"), b"ciphered").unwrap();
        }
        // Only the locked one has a sealed page key.
        std::fs::write(locked.join("vault.key"), b"sealed").unwrap();

        let left = wipe_open_dirs_in(&sandbox, &[&tmp.path().join("open")]);

        assert_eq!(left, 0);
        assert!(open.join("vault.db").exists(), "an open silo is left alone");
        assert!(open.join("open").join("opened.txt").exists());
        assert!(locked.join("vault.sqlcipher").is_file());
        assert!(locked.join("vault.key").is_file());
        assert!(!locked.join("vault.db").exists(), "plaintext survived");
        assert!(!locked.join("open").exists(), "an opened file survived");
        assert!(!crashed.exists(), "a copy with no key opens under nothing");

        assert_eq!(wipe_open_dirs_in(&sandbox, &[]), 0);
        assert!(!open.join("vault.db").exists());
        let mut names: Vec<_> = std::fs::read_dir(&locked)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        assert_eq!(names, ["vault.key", "vault.sqlcipher"]);
    }

    #[test]
    fn an_opened_copy_keeps_only_the_extension() {
        let name = opened_file_name("Contract Maria Popescu.docx");
        assert!(name.ends_with(".docx"), "{name}");
        assert!(!name.to_lowercase().contains("maria"), "{name}");
        assert_eq!(name.len(), 16 + ".docx".len());
        assert_ne!(name, opened_file_name("Contract Maria Popescu.docx"));
    }

    #[test]
    fn an_odd_extension_is_not_carried() {
        assert_eq!(opened_file_name("no extension").len(), 16);
        assert_eq!(opened_file_name("archive.tar.gz").len(), 16 + ".gz".len());
        // A name that hides text in its "extension" keeps none of it.
        assert_eq!(opened_file_name("x.secret note here").len(), 16);
        assert_eq!(opened_file_name("x.ab/../c").len(), 16);
    }

    #[test]
    fn a_shredded_file_is_gone_read_only_or_not() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("opened.txt");
        std::fs::write(&path, vec![b'p'; 3 * (1 << 20) + 17]).unwrap();
        seal_readonly(&path);
        shred_file(&path).unwrap();
        assert!(!path.exists());

        let empty = tmp.path().join("empty.txt");
        std::fs::write(&empty, b"").unwrap();
        shred_file(&empty).unwrap();
        assert!(!empty.exists());
    }

    #[test]
    fn shredding_a_tree_removes_everything_in_it() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("open");
        std::fs::create_dir_all(dir.join("nested")).unwrap();
        std::fs::write(dir.join("a.txt"), b"plaintext").unwrap();
        std::fs::write(dir.join("nested").join("b.txt"), b"plaintext").unwrap();
        seal_readonly(&dir.join("a.txt"));
        assert!(!shred_path(&dir), "nothing should be left");
        assert!(!dir.exists());
    }

    #[cfg(windows)]
    #[test]
    fn a_file_another_process_holds_is_seen_as_held() {
        // This process is left out of the answer, so the holder has to be
        // another one: PowerShell keeping the file open for a few seconds.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("opened.txt");
        std::fs::write(&path, b"plaintext").unwrap();
        assert_eq!(holders(&path), Some(vec![]));
        assert!(!is_held(&path));

        // It says when the file is open and holds it until told to let go:
        // a cold PowerShell on a CI runner takes longer than any fixed wait.
        use std::io::{BufRead, Write};
        use std::process::Stdio;
        let script = format!(
            "$f=[IO.File]::Open('{}','Open','Read','Read'); 'open'; [void][Console]::In.ReadLine(); $f.Close()",
            path.display()
        );
        let mut child = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "open");
        let held = is_held(&path);
        writeln!(child.stdin.take().unwrap()).unwrap();
        child.wait().unwrap();
        assert!(held, "the other process's handle was not seen");
        assert!(!is_held(&path));
    }

    #[cfg(windows)]
    #[test]
    fn a_viewer_that_denies_writes_keeps_its_file_until_it_lets_go() {
        // Word opens a document with no write sharing: the shred must fail
        // rather than half-delete it, and succeed once Word closes it.
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 1;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("opened.docx");
        std::fs::write(&path, b"plaintext").unwrap();
        let word = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .unwrap();
        assert!(shred_file(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"plaintext");
        drop(word);
        shred_file(&path).unwrap();
        assert!(!path.exists());
    }

    /// A directory link to `target` at `link`: a junction on Windows, which
    /// needs no privilege, a symbolic link elsewhere.
    fn dir_link(target: &Path, link: &Path) {
        #[cfg(windows)]
        {
            let made = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()
                .unwrap();
            assert!(made.status.success(), "{made:?}");
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    #[test]
    fn a_link_in_the_scratch_folder_is_removed_and_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep.txt"), b"not ours").unwrap();
        let dir = tmp.path().join("open");
        std::fs::create_dir_all(&dir).unwrap();
        dir_link(&outside, &dir.join("linked"));
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.join("keep.txt"), dir.join("file-link")).unwrap();

        assert!(!shred_path(&dir), "nothing should be left");
        assert!(!still_there(&dir));
        assert_eq!(
            std::fs::read(outside.join("keep.txt")).unwrap(),
            b"not ours"
        );

        // The folder itself a link: the link goes, what it points at stays.
        let linked = tmp.path().join("linked-open");
        dir_link(&outside, &linked);
        assert!(!shred_path(&linked));
        assert!(!still_there(&linked));
        assert_eq!(
            std::fs::read(outside.join("keep.txt")).unwrap(),
            b"not ours"
        );
    }

    #[test]
    fn a_dangling_link_does_not_read_as_held() {
        let tmp = tempfile::tempdir().unwrap();
        let gone = tmp.path().join("gone");
        std::fs::create_dir_all(&gone).unwrap();
        let dir = tmp.path().join("open");
        std::fs::create_dir_all(&dir).unwrap();
        dir_link(&gone, &dir.join("dangling"));
        std::fs::remove_dir(&gone).unwrap();

        assert!(!shred_path(&dir), "a dangling link was left");
        assert!(!still_there(&dir));
    }

    #[test]
    fn a_hard_linked_file_loses_its_name_and_keeps_its_content() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("keep.txt");
        std::fs::write(&outside, b"not ours").unwrap();
        let dir = tmp.path().join("open");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::hard_link(&outside, dir.join("linked.txt")).unwrap();

        assert!(!shred_path(&dir));
        assert!(!still_there(&dir));
        assert_eq!(std::fs::read(&outside).unwrap(), b"not ours");
    }

    #[cfg(windows)]
    #[test]
    fn a_viewer_that_lets_others_write_keeps_its_copy_intact() {
        // Sharing write access did not protect a holder: the shred opened the
        // file beside it and the viewer read random bytes.
        use std::os::windows::fs::OpenOptionsExt;
        const SHARE_ALL: u32 = 1 | 2 | 4;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("opened.pdf");
        std::fs::write(&path, b"plaintext").unwrap();
        let viewer = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(SHARE_ALL)
            .open(&path)
            .unwrap();
        assert!(shred_file(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"plaintext");
        drop(viewer);
        shred_file(&path).unwrap();
        assert!(!path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn an_encrypted_scratch_folder_encrypts_what_lands_in_it() {
        // Windows Home answers no and nothing changes; anywhere EFS works,
        // a file written afterwards is encrypted without asking.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("open");
        create_private_dir(&dir).unwrap();
        if !encrypt_scratch_dir(&dir) {
            return;
        }
        assert!(encrypt_scratch_dir(&dir), "a second call is a no-op");
        let path = dir.join("opened.txt");
        std::fs::write(&path, b"plaintext").unwrap();
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x4000;
        assert_ne!(
            std::fs::metadata(&path).unwrap().file_attributes() & FILE_ATTRIBUTE_ENCRYPTED,
            0
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"plaintext");
        assert!(!shred_path(&dir));
    }

    #[test]
    fn wiping_removes_read_only_files() {
        // An opened file is written read-only on purpose, and Windows
        // refuses to delete those, so plaintext would survive the lock.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("silo");
        let work = work_dir_for(&root);
        std::fs::create_dir_all(&work).unwrap();

        let locked = work.join("secret.txt");
        std::fs::write(&locked, b"plaintext").unwrap();
        let mut perms = std::fs::metadata(&locked).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&locked, perms).unwrap();

        wipe_work_dir(&root);
        assert!(
            !work.exists(),
            "the scratch directory must not survive a lock"
        );
    }
}

#[cfg(test)]
mod private_write_tests {
    use super::*;

    /// The failure this guards against reached a machine: moving these
    /// writes to temp-then-rename made them fail outright with "Access is
    /// denied" whenever a real-time antivirus still held the destination
    /// open, which is the ordinary state of a file an app has just written.
    /// Creating a silo stopped working on the spot.
    #[test]
    fn a_reader_holding_the_file_does_not_stop_a_key_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("silos.json");
        write_private(&path, b"first").unwrap();

        let scanner = std::fs::File::open(&path).unwrap();
        write_private(&path, b"second").expect("a held handle must not fail the write");
        drop(scanner);

        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert!(!dir.path().join("silos.json.tmp").exists());
    }

    #[test]
    fn a_write_into_a_missing_directory_creates_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets").join("cred.json");

        write_private(&path, b"x").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"x");
    }
}
