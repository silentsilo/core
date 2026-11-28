//! The unlock password end to end: a silo with only a password and the
//! recovery code, joined, unlocked, changed and removed between two devices
//! sharing a folder target, and what storage can do to it.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use silentsilo_app::flows::{
    DeviceKey, OpenSilo, check_password, enrol_device_key, has_password, is_wrong_password,
    join_finish, open_with_password, open_with_stored_password, password_join_begin,
    recovery_join_begin, recovery_join_provision, remove_unlock_password, set_unlock_password,
};
use silentsilo_app::{
    Action, AppEvent, AppState, Confirmation, DeviceMeans, Host, PasswordChange, SyncReport,
    Unlocked, run_sync_pass,
};
use silentsilo_core::coded::english;
use silentsilo_store::{FolderStore, ObjectStore, StoreConfig};
use silentsilo_vault::{BackupTarget, SiloEntry, TargetRole, VaultSession};
use silentsilo_vfs::Vfs;
use uuid::Uuid;

const PASSWORD: &str = "lantern-gravel-oxidize-tuba";
const CHANGED: &str = "copper-walrus-imply-garnish";

struct OneTarget(BackupTarget, Mutex<Vec<String>>);

impl Host for OneTarget {
    fn emit(&self, _event: AppEvent) {}
    fn warn(&self, area: &str, detail: &str) {
        self.1.lock().unwrap().push(format!("[{area}] {detail}"));
    }
    fn targets(&self, _silo_id: Uuid) -> Vec<BackupTarget> {
        vec![self.0.clone()]
    }
}

fn host(storage: &Path) -> OneTarget {
    OneTarget(
        BackupTarget {
            config: StoreConfig::Folder {
                path: storage.to_path_buf(),
            },
            label: "folder".into(),
            role: TargetRole::Working,
        },
        Mutex::default(),
    )
}

/// One device with one silo open in its own app state.
struct Device {
    state: AppState,
    host: OneTarget,
    silo: SiloEntry,
}

impl Device {
    fn new(storage: &Path, id: Uuid, root: PathBuf, session: VaultSession) -> Self {
        let device = Self {
            state: AppState::default(),
            host: host(storage),
            silo: SiloEntry {
                id,
                name: "Work".into(),
                path: root,
                last_opened: 0,
                auto_lock_minutes: None,
            },
        };
        device
            .state
            .open_session(&device.host, id, session)
            .unwrap();
        device
    }

    async fn pass(&self) -> SyncReport {
        run_sync_pass(&self.state, &self.host, &self.silo)
            .await
            .unwrap()
    }

    fn root(&self) -> &Path {
        &self.silo.path
    }

    /// The open session's keys, out of the lock.
    fn keys(&self) -> (silentsilo_crypto::MasterDek, silentsilo_crypto::ContentKek) {
        let sessions = self.state.sessions.lock().unwrap();
        let session = sessions.get(&self.silo.id).unwrap();
        (session.dek.clone(), session.kek.clone())
    }

    async fn set_password(&self, store: &FolderStore, password: &str) {
        let (dek, kek) = self.keys();
        set_unlock_password(
            OpenSilo {
                root: self.root(),
                vault_id: self.silo.id,
                dek: &dek,
                kek: &kek,
            },
            &[store],
            password,
            &["Work".to_string()],
            false,
            silentsilo_vault::Authority::Machine,
        )
        .await
        .unwrap();
    }

    fn close(&self) {
        self.state.close_session(&self.host, self.silo.id).unwrap();
    }

    fn warnings(&self) -> Vec<String> {
        self.host.1.lock().unwrap().clone()
    }
}

/// Device A: a silo with a folder, a recovery code and a password, no key.
struct Origin {
    _dirs: Vec<tempfile::TempDir>,
    storage: PathBuf,
    code: String,
    vault_id: Uuid,
    a: Device,
}

impl Drop for Origin {
    fn drop(&mut self) {
        silentsilo_vault::clear_credentials(self.vault_id);
    }
}

async fn origin() -> Origin {
    let storage = tempfile::tempdir().unwrap();
    let silo_dir = tempfile::tempdir().unwrap();
    let root = silo_dir.path().join("silo");
    let vault_id = Uuid::new_v4();
    // What a client saves before it provisions.
    silentsilo_vault::save_credentials(&silentsilo_vault::LocalVaultAuth {
        vault_id,
        device_secret: "secret-a".into(),
    })
    .unwrap();
    let session = VaultSession::provision(root.clone(), vault_id, "secret-a").unwrap();
    let vfs = Vfs::new(&session);
    vfs.ensure_initialized().unwrap();
    vfs.create_folder(vfs.root_folder_id().unwrap(), "From A")
        .unwrap();
    let (code, envelope) =
        silentsilo_vault::create_recovery_envelope(&session.dek, &session.kek).unwrap();
    silentsilo_vault::save_recovery_envelope(&root, &envelope).unwrap();

    let a = Device::new(storage.path(), vault_id, root, session);
    let store = FolderStore::new(storage.path().to_path_buf());
    a.set_password(&store, PASSWORD).await;
    let report = a.pass().await;
    assert!(report.ops_pushed > 0, "{report:?}");
    assert!(
        store.head("unlock-password.env").await.unwrap().is_some(),
        "the pass published the password"
    );

    Origin {
        storage: storage.path().to_path_buf(),
        code,
        vault_id,
        a,
        _dirs: vec![storage, silo_dir],
    }
}

/// Device B joins with the password and replays the log.
async fn join_with_password(origin: &Origin, root: PathBuf, password: &str) -> VaultSession {
    let store = FolderStore::new(origin.storage.clone());
    let joined = password_join_begin(&store, password).await.unwrap();
    assert_eq!(joined.vault_id, origin.vault_id);
    let session = recovery_join_provision(&store, &joined, root, "secret-b")
        .await
        .unwrap();
    let plan = silentsilo_sync::fetch_join_plan_reporting(&store, joined.dek(), &mut |_, _| {})
        .await
        .unwrap();
    join_finish(session, plan).unwrap().0
}

fn folder_names(session: &VaultSession) -> Vec<String> {
    let vfs = Vfs::new(session);
    vfs.list_folder(vfs.root_folder_id().unwrap())
        .unwrap()
        .into_iter()
        .filter_map(|e| match e {
            silentsilo_core::VaultEntry::Folder(f) => Some(f.name),
            _ => None,
        })
        .collect()
}

fn key(wrap_key: [u8; 32], id: &str) -> DeviceKey {
    DeviceKey {
        kind: silentsilo_vault::KIND_FIDO2.into(),
        derivation: silentsilo_vault::DERIVATION_HMAC_V1.into(),
        credential_id: id.into(),
        public_key: String::new(),
        wrap_key,
        label: "Key".into(),
    }
}

#[tokio::test]
async fn a_password_only_silo_opens_with_the_password_and_the_secret_opens_nothing() {
    let origin = origin().await;
    let root = origin.a.root().to_path_buf();
    origin.a.close();

    // Setting the password moved the local envelope under it, so the device
    // secret opens nothing whether or not the keyring dropped it. A keyring
    // read can fail under parallel tests; when it works, no secret is left.
    assert!(
        !matches!(silentsilo_vault::load_credentials(origin.vault_id),
            Ok(c) if !c.device_secret.is_empty())
    );
    assert!(VaultSession::open_with_device_secret(root.clone(), "secret-a").is_err());

    assert_eq!(
        english(
            &open_with_password(root.clone(), "wrong-horse-battery-staple", origin.vault_id)
                .err()
                .unwrap()
        ),
        "That password does not open this silo."
    );
    assert!(open_with_password(root.clone(), PASSWORD, Uuid::new_v4()).is_err());
    let (session, meta) = open_with_password(root, PASSWORD, origin.vault_id).unwrap();
    assert_eq!(meta.vault_id, origin.vault_id);
    assert!(folder_names(&session).contains(&"From A".to_string()));
}

#[tokio::test]
async fn the_password_typed_on_another_layout_still_opens() {
    // "é" composed and decomposed: what a Mac and a Windows keyboard send.
    let origin = origin().await;
    let store = FolderStore::new(origin.storage.clone());
    let composed = "caf\u{e9}-lantern-gravel-oxidize";
    let decomposed = "cafe\u{301}-lantern-gravel-oxidize";
    origin.a.set_password(&store, composed).await;
    let root = origin.a.root().to_path_buf();
    origin.a.close();
    assert!(open_with_password(root, decomposed, origin.vault_id).is_ok());
}

#[tokio::test]
async fn joining_with_the_password_brings_the_tree_and_opens_with_it_after() {
    let origin = origin().await;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("joined");
    let b_id = origin.vault_id;
    let session = join_with_password(&origin, root.clone(), PASSWORD).await;
    assert!(folder_names(&session).contains(&"From A".to_string()));
    assert!(has_password(&root));
    assert!(silentsilo_vault::has_recovery_code(&root));
    drop(session);

    // No key here either, so the device secret B was given opens nothing.
    assert!(VaultSession::open_with_device_secret(root.clone(), "secret-b").is_err());
    let (_, meta) = open_with_password(root, PASSWORD, b_id).unwrap();
    assert_eq!(meta.vault_id, b_id);
}

#[tokio::test]
async fn a_wrong_password_joins_nothing_and_a_silo_without_one_says_so() {
    let origin = origin().await;
    let store = FolderStore::new(origin.storage.clone());
    assert_eq!(
        english(
            &password_join_begin(&store, "wrong-horse-battery-staple")
                .await
                .err()
                .unwrap()
        ),
        "That password does not open this silo."
    );

    store.delete("unlock-password.env").await.unwrap();
    assert_eq!(
        english(&password_join_begin(&store, PASSWORD).await.err().unwrap()),
        "No unlock password was set up for this silo."
    );
}

#[tokio::test]
async fn a_password_set_by_a_newer_version_says_update() {
    let origin = origin().await;
    let path = origin.storage.join("unlock-password.env");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    envelope["version"] = 2.into();
    std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    let err = password_join_begin(&FolderStore::new(origin.storage.clone()), PASSWORD)
        .await
        .err()
        .unwrap();
    assert!(english(&err).contains("newer version"), "{err}");
}

#[tokio::test]
async fn joining_with_the_code_brings_the_password_too() {
    let origin = origin().await;
    let store = FolderStore::new(origin.storage.clone());
    let joined = recovery_join_begin(&store, &origin.code).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("joined");
    let session = recovery_join_provision(&store, &joined, root.clone(), "secret-b")
        .await
        .unwrap();
    drop(session);
    assert!(has_password(&root));
    assert!(VaultSession::open_with_device_secret(root.clone(), "secret-b").is_err());
    assert!(open_with_password(root, PASSWORD, origin.vault_id).is_ok());
}

#[tokio::test]
async fn a_changed_password_reaches_the_other_device_and_the_old_one_stops() {
    let origin = origin().await;
    let store = FolderStore::new(origin.storage.clone());
    let dir = tempfile::tempdir().unwrap();
    let b_root = dir.path().join("joined");
    let session = join_with_password(&origin, b_root.clone(), PASSWORD).await;
    let b = Device::new(&origin.storage, origin.vault_id, b_root.clone(), session);
    assert_eq!(b.pass().await.password, PasswordChange::None);

    origin.a.set_password(&store, CHANGED).await;
    origin.a.pass().await;

    assert_eq!(b.pass().await.password, PasswordChange::Adopted);
    b.close();
    assert!(open_with_password(b_root.clone(), PASSWORD, origin.vault_id).is_err());
    assert!(open_with_password(b_root, CHANGED, origin.vault_id).is_ok());
}

#[tokio::test]
async fn the_last_way_in_cannot_be_removed_and_a_removal_reaches_the_other_device() {
    let origin = origin().await;
    let store = FolderStore::new(origin.storage.clone());
    let dir = tempfile::tempdir().unwrap();
    let b_root = dir.path().join("joined");
    let session = join_with_password(&origin, b_root.clone(), PASSWORD).await;
    let b = Device::new(&origin.storage, origin.vault_id, b_root.clone(), session);
    // B gets a key of its own, so the password is not its only way in.
    {
        let sessions = b.state.sessions.lock().unwrap();
        enrol_device_key(
            sessions.get(&origin.vault_id).unwrap(),
            &key([8; 32], "bb22"),
        )
        .unwrap();
    }

    let (_, kek) = origin.a.keys();
    let targets: Vec<(&dyn ObjectStore, bool)> = vec![(&store, true)];
    assert_eq!(
        english(
            &remove_unlock_password(origin.a.root(), &kek, &targets, true)
                .await
                .err()
                .unwrap()
        ),
        "The password is this silo's only way in besides the recovery code. Add a key first."
    );
    assert!(has_password(origin.a.root()));

    {
        let sessions = origin.a.state.sessions.lock().unwrap();
        enrol_device_key(
            sessions.get(&origin.vault_id).unwrap(),
            &key([7; 32], "aa11"),
        )
        .unwrap();
    }
    // The app says this device cannot use the key (a phone key whose
    // fingerprint changed): refused all the same.
    assert!(
        remove_unlock_password(origin.a.root(), &kek, &targets, false)
            .await
            .is_err()
    );
    assert!(has_password(origin.a.root()));
    remove_unlock_password(origin.a.root(), &kek, &targets, true)
        .await
        .unwrap();
    assert!(!has_password(origin.a.root()));
    assert!(store.head("unlock-password.env").await.unwrap().is_none());
    origin.a.pass().await;

    assert_eq!(b.pass().await.password, PasswordChange::RemovedElsewhere);
    assert!(!has_password(&b_root));
    // The pass after that has nothing more to say.
    assert_eq!(b.pass().await.password, PasswordChange::None);
    assert!(store.head("unlock-password.env").await.unwrap().is_none());
}

#[tokio::test]
async fn a_removal_leaves_the_password_on_a_device_no_key_opens() {
    // B joined with the password and has no key of its own. A removal made
    // on A (or a marker a former member wrote) must not leave B with only
    // the recovery code.
    let origin = origin().await;
    let store = FolderStore::new(origin.storage.clone());
    let dir = tempfile::tempdir().unwrap();
    let b_root = dir.path().join("joined");
    let session = join_with_password(&origin, b_root.clone(), PASSWORD).await;
    let b = Device::new(&origin.storage, origin.vault_id, b_root.clone(), session);
    {
        let sessions = origin.a.state.sessions.lock().unwrap();
        enrol_device_key(
            sessions.get(&origin.vault_id).unwrap(),
            &key([7; 32], "aa11"),
        )
        .unwrap();
    }
    origin.a.pass().await;
    let (_, kek) = origin.a.keys();
    remove_unlock_password(origin.a.root(), &kek, &[(&store, true)], true)
        .await
        .unwrap();

    assert_eq!(b.pass().await.password, PasswordChange::KeptAfterRemoval);
    assert!(has_password(&b_root));
    assert!(
        store.head("unlock-password.env").await.unwrap().is_none(),
        "not published again"
    );
    // A's key came down too, unconfirmed: it is not B's way in.
    let keys = silentsilo_vault::load_fido_keys(&b_root).unwrap();
    assert!(keys.active().all(|k| k.unconfirmed));
    b.close();
    assert!(open_with_password(b_root, PASSWORD, origin.vault_id).is_ok());
}

#[tokio::test]
async fn a_key_added_elsewhere_reaches_a_device_the_password_opens() {
    // B has no keys file at all. Before, it never heard of keys added on
    // other devices, and was stranded when the password went.
    let origin = origin().await;
    let dir = tempfile::tempdir().unwrap();
    let b_root = dir.path().join("joined");
    let session = join_with_password(&origin, b_root.clone(), PASSWORD).await;
    let b = Device::new(&origin.storage, origin.vault_id, b_root.clone(), session);
    assert!(!silentsilo_vault::is_fido_enrolled(&b_root));
    b.pass().await;
    assert!(
        !silentsilo_vault::is_fido_enrolled(&b_root),
        "no empty keys file written"
    );

    {
        let sessions = origin.a.state.sessions.lock().unwrap();
        enrol_device_key(
            sessions.get(&origin.vault_id).unwrap(),
            &key([7; 32], "aa11"),
        )
        .unwrap();
    }
    origin.a.pass().await;
    b.pass().await;
    let keys = silentsilo_vault::load_fido_keys(&b_root).unwrap();
    assert_eq!(
        keys.active()
            .map(|k| k.credential_id.as_str())
            .collect::<Vec<_>>(),
        ["aa11"]
    );
    // It opens B's copy with the key, which proves it here.
    b.close();
    let opened = silentsilo_app::flows::open_with_device_key(
        b_root.clone(),
        "aa11",
        &[7; 32],
        origin.vault_id,
    );
    assert!(opened.is_ok(), "{:?}", opened.err());
    assert!(silentsilo_app::flows::key_opens_here(&b_root));
}

#[tokio::test]
async fn a_guard_that_did_not_happen_is_done_by_the_next_pass() {
    // A set that stopped after the envelope was saved: the local DEK
    // envelope is still the device secret's.
    let origin = origin().await;
    let root = origin.a.root().to_path_buf();
    let envelope = silentsilo_vault::password::load_password_envelope(&root).unwrap();
    assert!(!silentsilo_app::flows::password_guard_missing(
        &root, &envelope
    ));
    std::fs::write(
        silentsilo_vault::dek_store::dek_path(&root),
        b"what was there before",
    )
    .unwrap();
    assert!(silentsilo_app::flows::password_guard_missing(
        &root, &envelope
    ));

    origin.a.pass().await;
    assert!(!silentsilo_app::flows::password_guard_missing(
        &root, &envelope
    ));
    origin.a.close();
    assert!(open_with_password(root, PASSWORD, origin.vault_id).is_ok());
}

#[tokio::test]
async fn an_envelope_put_back_after_a_removal_does_not_join_or_come_back() {
    let origin = origin().await;
    let store = FolderStore::new(origin.storage.clone());
    let old = store.get("unlock-password.env").await.unwrap();
    {
        let sessions = origin.a.state.sessions.lock().unwrap();
        enrol_device_key(
            sessions.get(&origin.vault_id).unwrap(),
            &key([7; 32], "aa11"),
        )
        .unwrap();
    }
    let (_, kek) = origin.a.keys();
    remove_unlock_password(origin.a.root(), &kek, &[(&store, true)], true)
        .await
        .unwrap();

    // Storage with history, or anyone who kept a copy, puts it back.
    store.put("unlock-password.env", old.clone()).await.unwrap();
    assert_eq!(
        english(&password_join_begin(&store, PASSWORD).await.err().unwrap()),
        "The unlock password was removed from this silo. Use the recovery code or a key."
    );
    origin.a.pass().await;
    assert!(!has_password(origin.a.root()), "not adopted back");
    assert!(
        store.head("unlock-password.env").await.unwrap().is_none(),
        "deleted again by the pass"
    );
}

/// A password envelope from another silo, planted with a newer date: it
/// opens nothing here, joins nothing, and the real one goes back over it.
#[tokio::test]
async fn a_planted_envelope_is_refused_and_written_over() {
    let origin = origin().await;
    let store = FolderStore::new(origin.storage.clone());

    let other = tempfile::tempdir().unwrap();
    let other_session =
        VaultSession::provision(other.path().join("silo"), Uuid::new_v4(), "secret-x").unwrap();
    let mut planted = silentsilo_vault::password::seal_under_password(
        &other_session.dek,
        &other_session.kek,
        PASSWORD,
        &[],
        false,
    )
    .unwrap();
    planted.date_after(i64::MAX / 2, &other_session.kek, &other_session.dek);
    store
        .put("unlock-password.env", serde_json::to_vec(&planted).unwrap())
        .await
        .unwrap();

    // It opens the other silo's key, which opens nothing here.
    assert!(password_join_begin(&store, PASSWORD).await.is_err());

    let report = origin.a.pass().await;
    assert_eq!(report.password, PasswordChange::None);
    assert!(
        origin
            .a
            .warnings()
            .iter()
            .any(|w| w.starts_with("[password]")),
        "{:?}",
        origin.a.warnings()
    );
    let back = store.get("unlock-password.env").await.unwrap();
    let back = silentsilo_vault::password::parse_password_envelope(&back).unwrap();
    assert_ne!(back.id, planted.id, "the real envelope went back");
    assert!(password_join_begin(&store, PASSWORD).await.is_ok());
}

/// The same silo's envelope with its tag rewritten: the password still
/// opens the key it wraps, but nothing proves a member made it.
#[tokio::test]
async fn an_envelope_whose_tag_fails_does_not_join() {
    let origin = origin().await;
    let path = origin.storage.join("unlock-password.env");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    envelope["auth_dek"] = "00".repeat(32).into();
    std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert_eq!(
        english(
            &password_join_begin(&FolderStore::new(origin.storage.clone()), PASSWORD)
                .await
                .err()
                .unwrap()
        ),
        "This silo's unlock password was not set on its current key. Use the recovery code or a key."
    );
}

#[tokio::test]
async fn a_recovery_envelope_whose_tag_fails_is_not_kept_at_join() {
    let origin = origin().await;
    let path = origin.storage.join("recovery.env");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    envelope["auth_dek"] = "00".repeat(32).into();
    std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

    let store = FolderStore::new(origin.storage.clone());
    let joined = recovery_join_begin(&store, &origin.code).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("joined");
    drop(
        recovery_join_provision(&store, &joined, root.clone(), "secret-b")
            .await
            .unwrap(),
    );
    assert!(!silentsilo_vault::has_recovery_code(&root));
}

#[tokio::test]
async fn the_password_typed_again_is_checked_against_the_open_silo() {
    let origin = origin().await;
    let (dek, kek) = origin.a.keys();
    assert!(check_password(origin.a.root(), PASSWORD, &kek, &dek).is_ok());
    assert!(check_password(origin.a.root(), CHANGED, &kek, &dek).is_err());
}

#[tokio::test]
async fn the_floor_is_enforced_and_the_middle_tier_needs_its_tick() {
    use silentsilo_vault::password::{PasswordStrength, assess_password};
    let origin = origin().await;
    let (dek, kek) = origin.a.keys();
    let silo = || OpenSilo {
        root: origin.a.root(),
        vault_id: origin.vault_id,
        dek: &dek,
        kek: &kek,
    };
    let store = FolderStore::new(origin.storage.clone());
    let context = ["Work".to_string()];

    let err = set_unlock_password(
        silo(),
        &[&store],
        "123456",
        &context,
        true,
        silentsilo_vault::Authority::Machine,
    )
    .await
    .err()
    .unwrap();
    assert!(err.contains("err.password_too_weak"), "{err}");
    let err = set_unlock_password(
        silo(),
        &[&store],
        "Work2026!",
        &context,
        true,
        silentsilo_vault::Authority::Machine,
    )
    .await
    .err()
    .unwrap();
    assert!(err.contains("err.password_too_weak"), "{err}");

    let middle = "k7#Qm2!vXp9z";
    assert_eq!(
        assess_password(middle, &[]).strength,
        PasswordStrength::Weak
    );
    let err = set_unlock_password(
        silo(),
        &[&store],
        middle,
        &context,
        false,
        silentsilo_vault::Authority::Machine,
    )
    .await
    .err()
    .unwrap();
    assert!(err.contains("err.password_weak_unconfirmed"), "{err}");
    set_unlock_password(
        silo(),
        &[&store],
        middle,
        &context,
        true,
        silentsilo_vault::Authority::Machine,
    )
    .await
    .unwrap();
    // Refused ones changed nothing; the accepted one replaced the first.
    origin.a.close();
    assert!(open_with_password(origin.a.root().to_path_buf(), middle, origin.vault_id).is_ok());
}

#[tokio::test]
async fn a_new_password_is_dated_after_a_removal_with_a_clock_ahead() {
    let origin = origin().await;
    let store = FolderStore::new(origin.storage.clone());
    let (dek, kek) = origin.a.keys();
    // A device whose clock runs hours ahead removed the password. A day or
    // more ahead is ignored as a marker altogether.
    let ahead = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 12 * 3600;
    silentsilo_sync::mark_password_removed(&store, &kek, ahead)
        .await
        .unwrap();
    let envelope = set_unlock_password(
        OpenSilo {
            root: origin.a.root(),
            vault_id: origin.vault_id,
            dek: &dek,
            kek: &kek,
        },
        &[&store],
        CHANGED,
        &[],
        false,
        silentsilo_vault::Authority::Machine,
    )
    .await
    .unwrap();
    assert!(envelope.created_at > ahead, "dated after the marker");
    origin.a.pass().await;
    assert!(has_password(origin.a.root()), "not born dead");
}

#[test]
fn the_state_says_how_a_silo_was_opened_and_what_a_change_needs() {
    let state = AppState::default();
    let id = Uuid::new_v4();
    let no_key = DeviceMeans {
        usable_key: false,
        password: true,
    };
    let grace = std::time::Duration::from_secs(120);
    assert_eq!(state.unlocked(id), Unlocked::Fresh);

    state.set_unlocked(id, Unlocked::Password);
    assert_eq!(state.unlocked(id), Unlocked::Password);
    // The unlock itself counts on a phone, not on a desktop.
    assert_eq!(
        state.confirmation_needed(id, Action::Export, no_key, grace),
        Confirmation::None
    );
    assert_eq!(
        state.confirmation_needed(id, Action::Export, no_key, std::time::Duration::ZERO),
        Confirmation::PasswordTyped
    );

    // The password file gone mid-session asks for the password all the
    // same: a missing file must not turn the check off.
    let file_gone = DeviceMeans {
        usable_key: false,
        password: false,
    };
    assert_eq!(
        state.confirmation_needed(id, Action::KeyChange, file_gone, std::time::Duration::ZERO),
        Confirmation::PasswordTyped
    );

    state.set_unlocked(id, Unlocked::RecoveryCode);
    assert_eq!(
        state.confirmation_needed(id, Action::KeyChange, no_key, std::time::Duration::ZERO),
        Confirmation::None
    );

    // A host with its own session handling clears it itself.
    state.forget_unlocked(id);
    assert_eq!(state.unlocked(id), Unlocked::Fresh);
}

#[tokio::test]
async fn an_organisation_silo_takes_a_password_only_with_its_key() {
    let origin = origin().await;
    let store = FolderStore::new(origin.storage.clone());
    let (dek, kek) = origin.a.keys();
    {
        let sessions = origin.a.state.sessions.lock().unwrap();
        enrol_device_key(
            sessions.get(&origin.vault_id).unwrap(),
            &key([7; 32], "aa11"),
        )
        .unwrap();
    }
    let mut keys = silentsilo_vault::load_fido_keys(origin.a.root()).unwrap();
    keys.keys[0].policy = silentsilo_vault::POLICY_ORG.into();
    silentsilo_vault::save_fido_keys(origin.a.root(), &keys, silentsilo_vault::Authority::Machine)
        .unwrap();
    let silo = || OpenSilo {
        root: origin.a.root(),
        vault_id: origin.vault_id,
        dek: &dek,
        kek: &kek,
    };

    let err = set_unlock_password(
        silo(),
        &[&store],
        CHANGED,
        &[],
        false,
        silentsilo_vault::Authority::Machine,
    )
    .await
    .err()
    .unwrap();
    assert!(err.contains("err.password_needs_org_key"), "{err}");

    let proof = silentsilo_vault::OrgProof::verify(&keys, &[0xaa, 0x11], &[7; 32], &dek).unwrap();
    set_unlock_password(
        silo(),
        &[&store],
        CHANGED,
        &[],
        false,
        silentsilo_vault::Authority::Organisation(&proof),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn a_locked_device_opens_with_a_password_changed_elsewhere_from_storage() {
    let origin = origin().await;
    let store = FolderStore::new(origin.storage.clone());
    let dir = tempfile::tempdir().unwrap();
    let b_root = dir.path().join("joined");
    drop(join_with_password(&origin, b_root.clone(), PASSWORD).await);

    origin.a.set_password(&store, CHANGED).await;
    origin.a.pass().await;

    // B is locked and has not heard: its own copy takes only the old one.
    let err = open_with_password(b_root.clone(), CHANGED, origin.vault_id)
        .err()
        .unwrap();
    assert!(is_wrong_password(&err), "{err}");
    let silentsilo_sync::unlock_password::StoredPassword::Envelope(stored) =
        silentsilo_sync::unlock_password::fetch_password_envelope(&store)
            .await
            .unwrap()
    else {
        panic!("no envelope in storage");
    };
    assert!(
        open_with_stored_password(b_root.clone(), &stored, PASSWORD, origin.vault_id, None)
            .is_err()
    );
    drop(
        open_with_stored_password(b_root.clone(), &stored, CHANGED, origin.vault_id, None).unwrap(),
    );
    // Kept: the new one opens from this device's own copy now.
    assert!(open_with_password(b_root.clone(), CHANGED, origin.vault_id).is_ok());
    assert!(open_with_password(b_root, PASSWORD, origin.vault_id).is_err());
}

async fn stored_envelope(store: &FolderStore) -> silentsilo_vault::password::PasswordEnvelope {
    match silentsilo_sync::unlock_password::fetch_password_envelope(store)
        .await
        .unwrap()
    {
        silentsilo_sync::unlock_password::StoredPassword::Envelope(envelope) => envelope,
        _ => panic!("no envelope in storage"),
    }
}

/// Storage still holds the old password when this device changes it: the
/// old one, typed out of habit, does not open the silo or undo the change.
#[tokio::test]
async fn an_older_password_in_storage_does_not_undo_a_change_made_here() {
    let origin = origin().await;
    let store = FolderStore::new(origin.storage.clone());
    let old = stored_envelope(&store).await;
    origin.a.set_password(&store, CHANGED).await;
    origin.a.close();

    let root = origin.a.root().to_path_buf();
    let err = open_with_stored_password(root.clone(), &old, PASSWORD, origin.vault_id, None)
        .err()
        .unwrap();
    assert!(is_wrong_password(&err), "{err}");
    assert!(open_with_password(root.clone(), PASSWORD, origin.vault_id).is_err());
    drop(open_with_password(root, CHANGED, origin.vault_id).unwrap());
}

/// A removal whose delete failed leaves the envelope in storage: the
/// marker beside it keeps it from opening a locked device.
#[tokio::test]
async fn an_envelope_a_removal_covers_does_not_open_a_locked_device() {
    let origin = origin().await;
    let store = FolderStore::new(origin.storage.clone());
    let dir = tempfile::tempdir().unwrap();
    let b_root = dir.path().join("joined");
    drop(join_with_password(&origin, b_root.clone(), PASSWORD).await);
    let old = stored_envelope(&store).await;
    let old_bytes = store.get("unlock-password.env").await.unwrap();
    {
        let sessions = origin.a.state.sessions.lock().unwrap();
        enrol_device_key(
            sessions.get(&origin.vault_id).unwrap(),
            &key([7; 32], "aa11"),
        )
        .unwrap();
    }
    let (_, kek) = origin.a.keys();
    remove_unlock_password(origin.a.root(), &kek, &[(&store, true)], true)
        .await
        .unwrap();
    store.put("unlock-password.env", old_bytes).await.unwrap();
    // B has lost its own copy, so storage's is all it can try.
    std::fs::remove_file(b_root.join("keys/unlock-password.json")).unwrap();

    let marker = silentsilo_sync::unlock_password::removal_marker_bytes(&store)
        .await
        .unwrap();
    assert!(marker.is_some(), "the removal left its marker");
    let err = open_with_stored_password(
        b_root.clone(),
        &old,
        PASSWORD,
        origin.vault_id,
        marker.as_deref(),
    )
    .err()
    .unwrap();
    assert_eq!(
        english(&err),
        "The unlock password was removed from this silo. Use the recovery code or a key."
    );
    assert!(
        !b_root.join("keys/unlock-password.json").exists(),
        "nothing kept"
    );
}
