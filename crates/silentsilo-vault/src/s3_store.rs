//! Persistence for the user's S3 connection details.
//!
//! Kept next to `device_store` and using the same keyring-with-DPAPI-fallback
//! discipline, because the secret access key is exactly the kind of thing
//! that must not sit in a plain config file: it grants write access to the
//! user's own bucket.

use std::path::PathBuf;

use keyring::Entry;
use silentsilo_store::StoreConfig;
use uuid::Uuid;

use crate::dpapi;
use crate::error::VaultError;

const KEYRING_USER: &str = "s3-config";
const DPAPI_MAGIC: &[u8] = b"SSDPAPI1";
const S3_CONFIG_FILE: &str = "s3.config.json";

/// Keyed by silo: each one syncs to its own bucket or prefix, and a shared
/// keyring entry would quietly point them all at whichever was configured
/// last. That is the fastest way to have a family silo replaying a work
/// silo's operation log.
fn keyring_entry(silo_id: Uuid) -> Result<Entry, keyring::Error> {
    Entry::new(
        crate::keychain::service(),
        &format!("{KEYRING_USER}:{silo_id}"),
    )
}

/// Machine-local, for the same reason as the credentials file: this holds the
/// secret access key, the WebDAV password or the SSH private key, which is
/// full write and delete access to the user's backup storage. A silo folder
/// is made to be moved and may sit in a synced directory.
fn s3_config_path(silo_id: Uuid) -> PathBuf {
    crate::workdir::secrets_dir_for(silo_id).join(S3_CONFIG_FILE)
}

/// The silo's first target, whatever its kind. `None` means sync simply
/// isn't set up, which is a normal state: the app is fully usable without it.
///
/// Not the single slot on its own: that holds only kinds an older release
/// can read ([`LEGACY_KINDS`]), so once a newer kind comes first it is not
/// the answer.
pub fn load_s3_config(silo_id: Uuid) -> Option<StoreConfig> {
    load_targets(silo_id)
        .into_iter()
        .next()
        .map(|target| target.config)
}

/// The single slot as stored.
fn read_slot(silo_id: Uuid) -> Option<StoreConfig> {
    if let Ok(entry) = keyring_entry(silo_id)
        && let Ok(json) = entry.get_password()
        && let Ok(config) =
            crate::format::decode::<StoreConfig>("the storage settings", json.as_bytes())
    {
        return Some(config);
    }

    read_fallback_config(silo_id)
}

/// The keyring-unavailable path, split out so the per-silo separation can be
/// tested without depending on whatever the test machine's keyring does.
fn read_fallback_config(silo_id: Uuid) -> Option<StoreConfig> {
    let raw = std::fs::read(s3_config_path(silo_id)).ok()?;
    let json_bytes = match raw.strip_prefix(DPAPI_MAGIC) {
        Some(protected) => dpapi::unprotect(protected)?,
        None => raw,
    };
    crate::format::decode("the storage settings", &json_bytes).ok()
}

fn write_fallback_config(silo_id: Uuid, config: &StoreConfig) -> Result<(), VaultError> {
    let json = crate::format::encode(config)?;
    let to_write = match dpapi::protect(&json) {
        Some(protected) => {
            let mut out = DPAPI_MAGIC.to_vec();
            out.extend_from_slice(&protected);
            out
        }
        None => json,
    };
    crate::workdir::write_private(&s3_config_path(silo_id), &to_write)?;
    Ok(())
}

/// Writes the one connection a joined or recovered silo starts with.
pub fn save_s3_config(silo_id: Uuid, config: &StoreConfig) -> Result<(), VaultError> {
    if !is_legacy(config) {
        // Where an older release does not look, as the only target.
        return save_targets(
            silo_id,
            &[BackupTarget {
                config: config.clone(),
                label: String::new(),
                role: TargetRole::Working,
            }],
        );
    }
    write_slot(silo_id, config)
}

fn write_slot(silo_id: Uuid, config: &StoreConfig) -> Result<(), VaultError> {
    let json = String::from_utf8(crate::format::encode(config)?)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    // Same verify-after-write as device credentials: some Windows Credential
    // Manager setups report success without the entry becoming readable.
    if crate::keychain::set_password(
        crate::keychain::service(),
        &format!("{KEYRING_USER}:{silo_id}"),
        &json,
    )
    .is_ok()
        && let Ok(verify) = keyring_entry(silo_id)
        && matches!(verify.get_password(), Ok(stored) if stored == json)
    {
        let _ = std::fs::remove_file(s3_config_path(silo_id));
        return Ok(());
    }

    // The file is now the only copy, so whatever the entry still holds is
    // older and `load_s3_config` reads it first. It goes, after the file is
    // safely written and never before. See `save_targets` for the size this
    // happens at.
    write_fallback_config(silo_id, config)?;
    forget_keyring_entry(|| keyring_entry(silo_id));
    Ok(())
}

/// Disconnects sync and forgets every target. Best-effort: a missing entry
/// isn't an error. All of them hold the same secrets, so all of them go.
pub fn clear_s3_config(silo_id: Uuid) {
    clear_slot_and_list(silo_id);
    let _ = std::fs::remove_file(more_path(silo_id));
}

fn clear_slot_and_list(silo_id: Uuid) {
    forget_keyring_entry(|| keyring_entry(silo_id));
    let _ = std::fs::remove_file(s3_config_path(silo_id));
    forget_keyring_entry(|| targets_keyring(silo_id));
    let _ = std::fs::remove_file(targets_path(silo_id));
}

/// Deletes a keyring entry and reads back to confirm it is gone.
///
/// Windows Credential Manager can report a delete as done while the entry
/// stays readable, the mirror of the write problem `save_s3_config` guards
/// against. Here that would leave storage credentials on a machine told to
/// forget the silo, so the delete is retried rather than assumed.
fn forget_keyring_entry(open: impl Fn() -> Result<Entry, keyring::Error>) {
    for _ in 0..5 {
        match open() {
            Ok(entry) => {
                let _ = entry.delete_credential();
            }
            Err(_) => return,
        }
        match open() {
            Ok(entry) => match entry.get_password() {
                Ok(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
                Err(_) => return,
            },
            Err(_) => return,
        }
    }
}

// ── More than one target ────────────────────────────────────────────

/// What the app is allowed to do to a target. The distinction is deletion,
/// and it is a promise: an archive target never receives a DELETE, so
/// ransomware holding this machine cannot clear it either. The cost is
/// that it grows for ever, which the panel says rather than hides.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetRole {
    /// Full capabilities. Deletes are issued and expected to work.
    #[default]
    Working,
    /// Append-only. The app never issues a delete here, whether or not the
    /// storage would refuse one.
    Archive,
}

impl TargetRole {
    pub fn allows_delete(self) -> bool {
        matches!(self, Self::Working)
    }
}

/// One place a silo backs up to, with the role it plays.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackupTarget {
    pub config: StoreConfig,
    /// Shown to the user, so "the NAS" and "Backblaze" are distinguishable
    /// without reading a bucket name. Empty falls back to what the store
    /// says about itself.
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub role: TargetRole,
}

const TARGETS_FILE: &str = "targets.config.json";

fn targets_path(silo_id: Uuid) -> PathBuf {
    crate::workdir::secrets_dir_for(silo_id).join(TARGETS_FILE)
}

fn targets_keyring(silo_id: Uuid) -> Result<Entry, keyring::Error> {
    Entry::new(
        crate::keychain::service(),
        &format!("{KEYRING_USER}-list:{silo_id}"),
    )
}

// ── Kinds an older release cannot read ──────────────────────────────

/// The kinds desktop 1.2 (core v1.7.2) and earlier know. Only these go in the
/// list and the single slot, which those releases read: one entry of any
/// other kind makes their whole list unreadable, they fall back to the single
/// slot and the next save there writes the list back shorter. Every other
/// kind goes in `targets.more.config.json`, which they never open. Never add
/// a kind here.
const LEGACY_KINDS: [&str; 4] = ["s3", "folder", "web-dav", "sftp"];

const MORE_FILE: &str = "targets.more.config.json";

fn more_path(silo_id: Uuid) -> PathBuf {
    crate::workdir::secrets_dir_for(silo_id).join(MORE_FILE)
}

fn kind_of(config: &serde_json::Value) -> Option<&str> {
    config.get("kind")?.as_str()
}

fn is_legacy(config: &StoreConfig) -> bool {
    serde_json::to_value(config)
        .ok()
        .as_ref()
        .and_then(kind_of)
        .is_some_and(|kind| LEGACY_KINDS.contains(&kind))
}

/// A target in `targets.more.config.json`, with its place in the whole list.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MoreEntry {
    position: usize,
    target: serde_json::Value,
}

/// A target as stored: one this build can open, or one a newer release
/// wrote, kept as it was so that saving here never drops it.
enum Stored {
    Known(BackupTarget),
    Unknown(serde_json::Value),
}

impl Stored {
    fn from_value(value: serde_json::Value) -> Self {
        match serde_json::from_value::<BackupTarget>(value.clone()) {
            Ok(target) => Stored::Known(target),
            Err(_) => Stored::Unknown(value),
        }
    }
}

/// A target this build cannot open because a newer release added its kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableTarget {
    pub kind: String,
    pub label: String,
}

/// Every target, in order, readable or not.
fn load_stored(silo_id: Uuid) -> Vec<Stored> {
    let mut all: Vec<Stored> = match read_list(silo_id) {
        Some(list) => list.into_iter().map(Stored::from_value).collect(),
        // A device that has only ever joined or recovered.
        None => read_slot(silo_id)
            .map(|config| {
                vec![Stored::Known(BackupTarget {
                    config,
                    label: String::new(),
                    role: TargetRole::Working,
                })]
            })
            .unwrap_or_default(),
    };
    let mut more = read_more(silo_id);
    more.sort_by_key(|entry| entry.position);
    for entry in more {
        let at = entry.position.min(all.len());
        all.insert(at, Stored::from_value(entry.target));
    }
    all
}

/// The targets this build cannot read, each with the place it was saved at
/// rather than where it lands in a shorter list today, so a save here puts
/// it back where it was.
fn unknown_with_places(silo_id: Uuid) -> Vec<(usize, serde_json::Value)> {
    let mut out = Vec::new();
    for (place, value) in read_list(silo_id)
        .unwrap_or_default()
        .into_iter()
        .enumerate()
    {
        if let Stored::Unknown(value) = Stored::from_value(value) {
            out.push((place, value));
        }
    }
    for entry in read_more(silo_id) {
        if let Stored::Unknown(value) = Stored::from_value(entry.target) {
            out.push((entry.position, value));
        }
    }
    out.sort_by_key(|(place, _)| *place);
    out
}

/// Every target this silo backs up to, in the order they were added.
///
/// Joining a silo and restoring one from a recovery code both write a single
/// connection and no list, so the single slot is read as a list of one rather
/// than rewritten. Rewriting a working connection to change nothing but its
/// shape is a way to lose it on the machine where the rewrite fails.
pub fn load_targets(silo_id: Uuid) -> Vec<BackupTarget> {
    load_stored(silo_id)
        .into_iter()
        .filter_map(|stored| match stored {
            Stored::Known(target) => Some(target),
            Stored::Unknown(_) => None,
        })
        .collect()
}

/// The targets a newer release added, which this build keeps but cannot
/// open, so the app can say "update to use this copy" instead of nothing.
pub fn load_unreadable_targets(silo_id: Uuid) -> Vec<UnreadableTarget> {
    load_stored(silo_id)
        .into_iter()
        .filter_map(|stored| match stored {
            Stored::Unknown(value) => Some(UnreadableTarget {
                kind: value
                    .get("config")
                    .and_then(kind_of)
                    .unwrap_or("unknown")
                    .to_string(),
                label: value
                    .get("label")
                    .and_then(|label| label.as_str())
                    .unwrap_or_default()
                    .to_string(),
            }),
            Stored::Known(_) => None,
        })
        .collect()
}

/// Replaces the list.
///
/// Targets of a kind an older release knows go in the list and the first of
/// them in the single slot, as before; every other kind goes in
/// `targets.more.config.json` with its position. Targets a newer release
/// wrote, which `targets` cannot contain, go back where they were.
pub fn save_targets(silo_id: Uuid, targets: &[BackupTarget]) -> Result<(), VaultError> {
    let mut all: Vec<Stored> = targets.iter().cloned().map(Stored::Known).collect();
    for (place, value) in unknown_with_places(silo_id) {
        let at = place.min(all.len());
        all.insert(at, Stored::Unknown(value));
    }

    let mut list = Vec::new();
    let mut more = Vec::new();
    for (position, stored) in all.into_iter().enumerate() {
        match stored {
            Stored::Known(target) if is_legacy(&target.config) => list.push(target),
            Stored::Known(target) => more.push(MoreEntry {
                position,
                target: serde_json::to_value(&target)
                    .map_err(|e| VaultError::Crypto(e.to_string()))?,
            }),
            Stored::Unknown(target) => more.push(MoreEntry { position, target }),
        }
    }

    write_list(silo_id, &list)?;
    write_more(silo_id, &more)
}

/// The list and the single slot, which older releases read: only kinds they
/// know.
fn write_list(silo_id: Uuid, targets: &[BackupTarget]) -> Result<(), VaultError> {
    let json = String::from_utf8(crate::format::encode(&targets.to_vec())?)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    let stored_in_keyring = crate::keychain::set_password(
        crate::keychain::service(),
        &format!("{KEYRING_USER}-list:{silo_id}"),
        &json,
    )
    .ok()
    .and_then(|()| targets_keyring(silo_id).ok())
    .is_some_and(|verify| matches!(verify.get_password(), Ok(held) if held == json));

    // The single slot below holds only the first entry, so a real list keeps
    // the file too: a lost keyring entry would otherwise read as one target
    // of several. Best-effort, and removed rather than left stale.
    if stored_in_keyring {
        if targets.len() < 2 || write_fallback_targets(silo_id, json.as_bytes()).is_err() {
            let _ = std::fs::remove_file(targets_path(silo_id));
        }
    } else {
        // Windows Credential Manager refuses a blob over
        // `CRED_MAX_CREDENTIAL_BLOB_SIZE`, 2560 bytes, and the blob is
        // UTF-16, so a list over 1280 characters is refused: one SFTP target
        // with its private key passes that on its own. The file takes it,
        // but `load_targets` reads the entry first, so the shorter list the
        // entry still holds came back instead and the target just added was
        // gone. The entry goes, after the file is written and never before,
        // so the two copies cannot disagree and a list never shrinks.
        write_fallback_targets(silo_id, json.as_bytes())?;
        forget_keyring_entry(|| targets_keyring(silo_id));
    }

    match targets.first() {
        Some(first) => write_slot(silo_id, &first.config),
        None => {
            clear_slot_and_list(silo_id);
            Ok(())
        }
    }
}

/// The keyring-unavailable path, split out for the same reason as the
/// single-target one: so the per-silo separation can be tested without
/// depending on whatever the test machine's keyring does.
fn read_fallback_targets(silo_id: Uuid) -> Option<Vec<serde_json::Value>> {
    let raw = std::fs::read(targets_path(silo_id)).ok()?;
    let json_bytes = match raw.strip_prefix(DPAPI_MAGIC) {
        Some(protected) => dpapi::unprotect(protected)?,
        None => raw,
    };
    crate::format::decode("the backup targets", &json_bytes).ok()
}

/// The list as stored, each entry left as JSON so one entry this build cannot
/// read does not take the others with it.
fn read_list(silo_id: Uuid) -> Option<Vec<serde_json::Value>> {
    if let Ok(entry) = targets_keyring(silo_id)
        && let Ok(json) = entry.get_password()
        && let Ok(list) = crate::format::decode("the backup targets", json.as_bytes())
    {
        return Some(list);
    }
    read_fallback_targets(silo_id)
}

/// A file only, no keyring entry: nothing in it is a secret (the tokens of
/// these kinds are stored apart), and one copy cannot disagree with another.
fn read_more(silo_id: Uuid) -> Vec<MoreEntry> {
    let Ok(raw) = std::fs::read(more_path(silo_id)) else {
        return Vec::new();
    };
    let json_bytes = match raw.strip_prefix(DPAPI_MAGIC) {
        Some(protected) => match dpapi::unprotect(protected) {
            Some(json) => json,
            None => return Vec::new(),
        },
        None => raw,
    };
    crate::format::decode("the backup targets", &json_bytes).unwrap_or_default()
}

fn write_more(silo_id: Uuid, more: &[MoreEntry]) -> Result<(), VaultError> {
    if more.is_empty() {
        let _ = std::fs::remove_file(more_path(silo_id));
        return Ok(());
    }
    let json = crate::format::encode(&more.to_vec())?;
    let to_write = match dpapi::protect(&json) {
        Some(protected) => {
            let mut out = DPAPI_MAGIC.to_vec();
            out.extend_from_slice(&protected);
            out
        }
        None => json,
    };
    crate::workdir::write_private(&more_path(silo_id), &to_write)?;
    Ok(())
}

fn write_fallback_targets(silo_id: Uuid, json: &[u8]) -> Result<(), VaultError> {
    let to_write = match dpapi::protect(json) {
        Some(protected) => {
            let mut out = DPAPI_MAGIC.to_vec();
            out.extend_from_slice(&protected);
            out
        }
        None => json.to_vec(),
    };
    crate::workdir::write_private(&targets_path(silo_id), &to_write)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StoreConfig {
        StoreConfig::S3(silentsilo_core::S3Config {
            endpoint: "https://s3.example.com".into(),
            region: "us-east-1".into(),
            bucket: "my-bucket".into(),
            prefix: "silentsilo".into(),
            access_key_id: "AKIAEXAMPLE".into(),
            secret_access_key: "secret".into(),
            path_style: true,
        })
    }

    /// The S3 details on their own, for the tests that are about how a
    /// prefix becomes a key rather than about how a config is stored.
    fn s3_sample() -> silentsilo_core::S3Config {
        match sample() {
            StoreConfig::S3(c) => c,
            other => panic!("expected an S3 config, got {other:?}"),
        }
    }

    fn bucket_of(config: &StoreConfig) -> &str {
        match config {
            StoreConfig::S3(c) => &c.bucket,
            other => panic!("expected an S3 config, got {other:?}"),
        }
    }

    /// Same reasoning as `device_store`: this file now lives under
    /// `work_base()`, a real directory on the machine running the tests, so
    /// each test takes a random id and cleans up after itself.
    pub(super) struct Scratch(Uuid);

    impl Scratch {
        pub(super) fn new() -> Self {
            Scratch(Uuid::new_v4())
        }
        pub(super) fn id(&self) -> Uuid {
            self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            // The keyring entries too, and on a failed test as well: left
            // behind they pile up in the real Credential Manager, and a full
            // one starts losing writes.
            clear_s3_config(self.0);
            let _ = std::fs::remove_dir_all(crate::workdir::secrets_dir_for(self.0));
        }
    }

    /// Held by the tests that read back what the keyring stored. Credential
    /// Manager under many parallel writers now and then loses one, which is
    /// the machine's behaviour rather than this module's.
    pub(super) fn keyring_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn absent_config_reads_as_none() {
        // A random id nothing has ever written a config for.
        assert!(load_s3_config(Uuid::new_v4()).is_none());
    }

    /// The secret access key is full write and delete access to the user's
    /// backup storage, and the silo folder is made to be carried around and
    /// may sit in a synced directory.
    #[test]
    fn the_config_never_lands_in_the_silo_folder() {
        let scratch = Scratch::new();
        let silo_root = std::path::Path::new(r"C:\Users\alex\OneDrive\Documents\Silo");

        let path = s3_config_path(scratch.id());

        assert!(!path.starts_with(silo_root));
        assert!(path.starts_with(crate::workdir::work_base()));
    }

    #[test]
    fn two_silos_keep_separate_configs_on_disk() {
        // A shared file would point both silos at whichever bucket was
        // configured last, which is how a family silo ends up replaying a
        // work silo's operation log.
        let first = Scratch::new();
        let second = Scratch::new();

        let StoreConfig::S3(mut inner) = sample() else {
            unreachable!()
        };
        inner.bucket = "personal-bucket".into();
        write_fallback_config(first.id(), &StoreConfig::S3(inner.clone())).unwrap();

        inner.bucket = "work-bucket".into();
        write_fallback_config(second.id(), &StoreConfig::S3(inner)).unwrap();

        assert_eq!(
            bucket_of(&read_fallback_config(first.id()).unwrap()),
            "personal-bucket"
        );
        assert_eq!(
            bucket_of(&read_fallback_config(second.id()).unwrap()),
            "work-bucket"
        );
    }

    #[test]
    fn keys_are_built_under_the_prefix() {
        let config = s3_sample();
        assert_eq!(config.key("blobs/abc.sslo"), "silentsilo/blobs/abc.sslo");
        assert_eq!(config.key("/blobs/abc.sslo"), "silentsilo/blobs/abc.sslo");
    }

    #[test]
    fn an_empty_prefix_puts_objects_at_the_bucket_root() {
        let mut config = s3_sample();
        config.prefix = String::new();
        assert_eq!(config.key("blobs/abc.sslo"), "blobs/abc.sslo");
        config.prefix = "/".into();
        assert_eq!(config.key("blobs/abc.sslo"), "blobs/abc.sslo");
    }

    #[test]
    fn surrounding_slashes_in_the_prefix_do_not_double_up() {
        let mut config = s3_sample();
        config.prefix = "/vaults/mine/".into();
        assert_eq!(config.key("blobs/a"), "vaults/mine/blobs/a");
    }
}

#[cfg(test)]
mod target_list_tests {
    use super::tests::Scratch;
    use super::*;

    /// The list file holds JSON per entry; these tests are about entries this
    /// build reads.
    fn known(values: Vec<serde_json::Value>) -> Vec<BackupTarget> {
        values
            .into_iter()
            .map(|value| serde_json::from_value(value).expect("a target this build reads"))
            .collect()
    }

    fn folder(path: &str) -> StoreConfig {
        StoreConfig::Folder {
            path: PathBuf::from(path),
        }
    }

    #[test]
    fn a_silo_that_only_ever_joined_reads_as_a_list_of_one() {
        // Joining and recovering write the single slot and no list, so it is
        // read rather than rewritten: changing nothing but the shape of a
        // working connection is a way to lose it on the machine where the
        // rewrite fails.
        let scratch = Scratch::new();
        write_fallback_config(scratch.id(), &folder("D:/Backups")).unwrap();

        let targets = load_targets(scratch.id());

        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].config.target_id(),
            folder("D:/Backups").target_id()
        );
    }

    #[test]
    fn a_list_of_several_survives_losing_the_keyring_entry() {
        // The failure this guards: the list lives in one keyring entry and
        // the first target in another. Lose the list alone and the fallback
        // chain lands on the single slot, which answers "one target" for a
        // silo that has three. Eviction then counts one copy where the user
        // configured three, deletions stop reaching the other two, and the
        // next edit saves the shortened list over the real one.
        let scratch = Scratch::new();
        let list = vec![
            BackupTarget {
                config: folder("D:/Backups"),
                label: "Disk".into(),
                role: TargetRole::Working,
            },
            BackupTarget {
                config: folder("E:/Offsite"),
                label: "Offsite".into(),
                role: TargetRole::Working,
            },
        ];
        save_targets(scratch.id(), &list).unwrap();

        // Whatever this machine's keyring did, the file has to be there: it
        // is the only copy that still holds both.
        assert!(
            targets_path(scratch.id()).is_file(),
            "a list of two must keep the file the single slot cannot represent"
        );
        let recovered = known(read_fallback_targets(scratch.id()).expect("the file still parses"));
        assert_eq!(recovered.len(), 2);
        assert_eq!(
            recovered[1].config.target_id(),
            folder("E:/Offsite").target_id()
        );
    }

    #[test]
    fn forgetting_a_silo_takes_its_target_secrets_with_it() {
        // Every target carries full write and delete access to storage: an
        // access key, a WebDAV password or an SSH private key. Removing the
        // silo and its files while leaving those behind keeps that access on
        // a machine that was told to forget it.
        let scratch = Scratch::new();
        save_targets(
            scratch.id(),
            &[
                BackupTarget {
                    config: folder("D:/Backups"),
                    label: "Disk".into(),
                    role: TargetRole::Working,
                },
                BackupTarget {
                    config: folder("E:/Offsite"),
                    label: "Offsite".into(),
                    role: TargetRole::Working,
                },
            ],
        )
        .unwrap();

        clear_s3_config(scratch.id());

        assert!(!targets_path(scratch.id()).exists());
        assert!(
            load_targets(scratch.id()).is_empty(),
            "nothing about the storage may survive forgetting the silo"
        );
    }

    /// A list Windows Credential Manager will not take, which is not a
    /// contrived size: `CRED_MAX_CREDENTIAL_BLOB_SIZE` is 2560 bytes and the
    /// blob is UTF-16, so 1280 characters of JSON is the real ceiling, and
    /// one SFTP target carrying its private key passes it on its own.
    ///
    /// The bug: the write was refused, the file was written, and the entry
    /// kept the shorter list it had taken last time. `load_targets` reads
    /// the entry first, so a target the user had just added was gone on the
    /// next read, and the next save wrote the shortened list back over the
    /// real one.
    #[cfg(windows)]
    #[test]
    fn a_list_credential_manager_refuses_never_reads_back_short() {
        let scratch = Scratch::new();
        let disk = BackupTarget {
            config: folder("D:/Backups"),
            label: "Disk".into(),
            role: TargetRole::Working,
        };
        save_targets(scratch.id(), std::slice::from_ref(&disk)).unwrap();
        if targets_keyring(scratch.id())
            .and_then(|entry| entry.get_password())
            .is_err()
        {
            // Nothing to prove on a machine whose keyring took nothing.
            eprintln!("skipped: this machine's keyring did not hold a short list");
            return;
        }

        let long = vec![
            disk.clone(),
            BackupTarget {
                config: StoreConfig::Sftp(silentsilo_store::SftpConfig {
                    host: "nas.example.com".into(),
                    port: 22,
                    username: "silo".into(),
                    auth: silentsilo_store::SftpAuth::Key {
                        // The shape and size of a real OpenSSH key.
                        private_key: format!(
                            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
                            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn"
                                .repeat(24)
                        ),
                        passphrase: None,
                    },
                    path: "/srv/silo".into(),
                    host_fingerprint: Some(format!("SHA256:{}", "a".repeat(43))),
                }),
                label: "The NAS".into(),
                role: TargetRole::Working,
            },
        ];
        // The blob is UTF-16, so the 2560-byte ceiling is 1280 characters.
        let written = String::from_utf8(crate::format::encode(&long).unwrap()).unwrap();
        assert!(
            written.encode_utf16().count() * 2 > 2560,
            "this list has to be one Credential Manager refuses, got {} characters",
            written.chars().count()
        );

        save_targets(scratch.id(), &long).unwrap();

        let back = load_targets(scratch.id());
        assert_eq!(
            back.len(),
            long.len(),
            "a target the user added disappeared on the next read"
        );
        assert_eq!(back[1].label, "The NAS");
        // Whatever this machine's Credential Manager did with it, the two
        // copies must not disagree: the file is read only when the entry is
        // gone, so an entry that stayed behind is a shorter list waiting.
        if let Ok(held) = targets_keyring(scratch.id()).and_then(|e| e.get_password()) {
            let from_entry: Vec<BackupTarget> =
                crate::format::decode("the backup targets", held.as_bytes()).unwrap();
            assert_eq!(from_entry.len(), long.len(), "the keyring entry is stale");
        }

        clear_s3_config(scratch.id());
    }

    #[test]
    fn a_silo_with_no_storage_has_no_targets() {
        let scratch = Scratch::new();

        assert!(load_targets(scratch.id()).is_empty());
    }

    #[test]
    fn the_fallback_file_round_trips_a_list() {
        // The keyring is whatever the test machine has, so this exercises the
        // path that does not depend on it.
        let scratch = Scratch::new();
        let list = vec![
            BackupTarget {
                config: folder("D:/Backups"),
                label: "The NAS".into(),
                role: TargetRole::Working,
            },
            BackupTarget {
                config: folder("E:/Offsite"),
                label: String::new(),
                role: TargetRole::Archive,
            },
        ];
        let json = crate::format::encode(&list).unwrap();

        write_fallback_targets(scratch.id(), &json).unwrap();
        let back = known(read_fallback_targets(scratch.id()).unwrap());

        assert_eq!(back.len(), 2);
        assert_eq!(back[0].label, "The NAS");
        // The role travels with the target. Reading it back as Working
        // would mean the app deleting from a place the user asked it never
        // to delete from, which is the one promise this field makes.
        assert!(back[0].role.allows_delete());
        assert!(!back[1].role.allows_delete());
        assert_eq!(back[1].config.target_id(), folder("E:/Offsite").target_id());
    }

    #[test]
    fn two_silos_keep_separate_lists() {
        let first = Scratch::new();
        let second = Scratch::new();

        write_fallback_targets(
            first.id(),
            &crate::format::encode(&vec![BackupTarget {
                config: folder("D:/One"),
                label: String::new(),
                role: TargetRole::Working,
            }])
            .unwrap(),
        )
        .unwrap();

        assert!(read_fallback_targets(second.id()).is_none());
    }
}

/// What desktop 1.2 (core v1.7.2) makes of the files this build writes. The
/// shapes are copied from that release, so a change it cannot read fails
/// here rather than in somebody's backup list after a downgrade.
#[cfg(test)]
mod older_release_tests {
    use super::tests::{Scratch, keyring_lock};
    use super::*;

    /// The target shapes as desktop 1.2 has them. Decoded, never read.
    #[allow(dead_code)]
    mod as_of_1_2 {
        use std::path::PathBuf;

        #[derive(Debug, serde::Deserialize)]
        #[serde(tag = "kind", rename_all = "kebab-case")]
        pub enum StoreConfig {
            S3(silentsilo_core::S3Config),
            Folder { path: PathBuf },
            WebDav(silentsilo_store::WebDavConfig),
            Sftp(silentsilo_store::SftpConfig),
        }

        #[derive(Debug, serde::Deserialize)]
        pub struct BackupTarget {
            pub config: StoreConfig,
            #[serde(default)]
            pub label: String,
            #[serde(default)]
            pub role: super::super::TargetRole,
        }
    }

    fn decode_list(bytes: &[u8]) -> Option<Vec<as_of_1_2::BackupTarget>> {
        crate::format::decode("the backup targets", bytes).ok()
    }

    fn unwrap_file(raw: Vec<u8>) -> Option<Vec<u8>> {
        match raw.strip_prefix(DPAPI_MAGIC) {
            Some(protected) => dpapi::unprotect(protected),
            None => Some(raw),
        }
    }

    /// Desktop 1.2's single slot: the keyring entry, then the file. Read a
    /// few times: under a full parallel test run Credential Manager now and
    /// then fails a read of an entry it just verified, the same flakiness
    /// `forget_keyring_entry` retries around.
    fn slot_as_1_2(silo_id: Uuid) -> Option<as_of_1_2::StoreConfig> {
        for _ in 0..5 {
            if let Some(config) = slot_as_1_2_once(silo_id) {
                return Some(config);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        None
    }

    fn slot_as_1_2_once(silo_id: Uuid) -> Option<as_of_1_2::StoreConfig> {
        if let Ok(entry) = keyring_entry(silo_id)
            && let Ok(json) = entry.get_password()
            && let Ok(config) = crate::format::decode("the storage settings", json.as_bytes())
        {
            return Some(config);
        }
        let raw = unwrap_file(std::fs::read(s3_config_path(silo_id)).ok()?)?;
        crate::format::decode("the storage settings", &raw).ok()
    }

    /// Desktop 1.2's `load_targets`: the list from the keyring, then the
    /// file, then the single slot as a list of one.
    fn read_as_1_2(silo_id: Uuid) -> Vec<as_of_1_2::BackupTarget> {
        if let Ok(entry) = targets_keyring(silo_id)
            && let Ok(json) = entry.get_password()
            && let Some(list) = decode_list(json.as_bytes())
        {
            return list;
        }
        if let Some(list) = std::fs::read(targets_path(silo_id))
            .ok()
            .and_then(unwrap_file)
            .and_then(|json| decode_list(&json))
        {
            return list;
        }
        slot_as_1_2(silo_id)
            .map(|config| {
                vec![as_of_1_2::BackupTarget {
                    config,
                    label: String::new(),
                    role: TargetRole::Working,
                }]
            })
            .unwrap_or_default()
    }

    fn folder(path: &str, label: &str, role: TargetRole) -> BackupTarget {
        BackupTarget {
            config: StoreConfig::Folder {
                path: PathBuf::from(path),
            },
            label: label.into(),
            role,
        }
    }

    /// A target of a kind this build does not know, the way a newer release
    /// would write it.
    fn newer_kind() -> serde_json::Value {
        serde_json::json!({
            "config": { "kind": "onedrive", "account": "ana@example.com", "folder": "Silo" },
            "label": "OneDrive",
            "role": "working"
        })
    }

    fn path_of(target: &as_of_1_2::BackupTarget) -> &std::path::Path {
        match &target.config {
            as_of_1_2::StoreConfig::Folder { path } => path,
            other => panic!("expected a folder, got {other:?}"),
        }
    }

    #[test]
    fn an_older_release_reads_every_target_it_knows_and_nothing_else() {
        let _serial = keyring_lock();
        let scratch = Scratch::new();
        write_more(
            scratch.id(),
            &[MoreEntry {
                position: 0,
                target: newer_kind(),
            }],
        )
        .unwrap();

        save_targets(
            scratch.id(),
            &[
                folder("D:/Backups", "Disk", TargetRole::Working),
                folder("E:/Offsite", "Offsite", TargetRole::Archive),
            ],
        )
        .unwrap();

        let old = read_as_1_2(scratch.id());
        assert_eq!(old.len(), 2, "1.2 must read the whole list it knows");
        assert_eq!(path_of(&old[0]), std::path::Path::new("D:/Backups"));
        assert_eq!(old[1].label, "Offsite");
        assert!(
            !old[1].role.allows_delete(),
            "a never-delete copy read back as deletable would be emptied"
        );
        assert!(matches!(
            slot_as_1_2(scratch.id()),
            Some(as_of_1_2::StoreConfig::Folder { .. })
        ));

        // This build still has all three, in their order.
        assert_eq!(load_targets(scratch.id()).len(), 2);
        let unreadable = load_unreadable_targets(scratch.id());
        assert_eq!(unreadable.len(), 1);
        assert_eq!(unreadable[0].kind, "onedrive");
        assert_eq!(unreadable[0].label, "OneDrive");
        assert!(matches!(load_stored(scratch.id())[0], Stored::Unknown(_)));

        clear_s3_config(scratch.id());
    }

    #[test]
    fn a_save_by_an_older_release_leaves_the_newer_targets_alone() {
        // 1.2 rewrites the list and the single slot and never opens the
        // other file, so whatever it saves, the newer target survives.
        let _serial = keyring_lock();
        let scratch = Scratch::new();
        write_more(
            scratch.id(),
            &[MoreEntry {
                position: 1,
                target: newer_kind(),
            }],
        )
        .unwrap();
        save_targets(
            scratch.id(),
            &[
                folder("D:/Backups", "Disk", TargetRole::Working),
                folder("E:/Offsite", "Offsite", TargetRole::Working),
            ],
        )
        .unwrap();

        // What 1.2's save does after removing a copy: the list and the slot.
        write_list(
            scratch.id(),
            &[folder("E:/Offsite", "Offsite", TargetRole::Working)],
        )
        .unwrap();

        assert_eq!(load_targets(scratch.id()).len(), 1);
        assert_eq!(load_unreadable_targets(scratch.id()).len(), 1);

        clear_s3_config(scratch.id());
    }

    #[test]
    fn a_target_this_build_cannot_read_never_takes_the_others_with_it() {
        // Before 1.3 one unknown entry made the whole list unreadable, the
        // slot answered "one target" and the next save wrote that back.
        let _serial = keyring_lock();
        let scratch = Scratch::new();
        let written = vec![
            serde_json::to_value(folder("D:/Backups", "Disk", TargetRole::Working)).unwrap(),
            newer_kind(),
            serde_json::to_value(folder("E:/Offsite", "Offsite", TargetRole::Archive)).unwrap(),
        ];
        forget_keyring_entry(|| targets_keyring(scratch.id()));
        write_fallback_targets(scratch.id(), &crate::format::encode(&written).unwrap()).unwrap();

        let known = load_targets(scratch.id());
        assert_eq!(known.len(), 2, "the targets this build reads are all there");
        assert_eq!(known[1].label, "Offsite");

        // The next save puts the list back in a shape 1.2 reads, and keeps
        // the entry it could not read, in its place.
        save_targets(scratch.id(), &known).unwrap();
        assert_eq!(read_as_1_2(scratch.id()).len(), 2);
        assert!(matches!(load_stored(scratch.id())[1], Stored::Unknown(_)));

        clear_s3_config(scratch.id());
    }

    #[test]
    fn a_newer_target_keeps_its_place_when_others_are_removed() {
        let _serial = keyring_lock();
        let scratch = Scratch::new();
        write_more(
            scratch.id(),
            &[MoreEntry {
                position: 1,
                target: newer_kind(),
            }],
        )
        .unwrap();
        save_targets(
            scratch.id(),
            &[
                folder("D:/Backups", "Disk", TargetRole::Working),
                folder("E:/Offsite", "Offsite", TargetRole::Working),
            ],
        )
        .unwrap();
        assert!(matches!(load_stored(scratch.id())[1], Stored::Unknown(_)));

        save_targets(
            scratch.id(),
            &[folder("E:/Offsite", "Offsite", TargetRole::Working)],
        )
        .unwrap();

        let stored = load_stored(scratch.id());
        assert_eq!(stored.len(), 2);
        assert!(matches!(stored[1], Stored::Unknown(_)));

        clear_s3_config(scratch.id());
    }

    #[test]
    fn forgetting_a_silo_takes_the_newer_targets_too() {
        let _serial = keyring_lock();
        let scratch = Scratch::new();
        write_more(
            scratch.id(),
            &[MoreEntry {
                position: 0,
                target: newer_kind(),
            }],
        )
        .unwrap();

        clear_s3_config(scratch.id());

        assert!(!more_path(scratch.id()).exists());
        assert!(load_unreadable_targets(scratch.id()).is_empty());
    }
}
