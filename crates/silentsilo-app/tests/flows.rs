//! Joining with the recovery code, unlocking with it, and a device key,
//! end to end between two devices sharing a folder target.

use std::sync::Mutex;

use silentsilo_app::flows::{
    DeviceKey, enrol_device_key, join_finish, open_with_device_key, open_with_recovery,
    recovery_envelope_for, recovery_join_begin, recovery_join_provision,
};
use silentsilo_app::{AppEvent, AppState, Host, run_sync_pass};
use silentsilo_store::{FolderStore, StoreConfig};
use silentsilo_vault::{BackupTarget, SiloEntry, TargetRole, VaultSession};
use silentsilo_vfs::Vfs;
use uuid::Uuid;

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

fn key(wrap_key: [u8; 32], id: &str) -> DeviceKey {
    // A FIDO2-shaped key so every build, this one included, can use it; the
    // flow is the same for a phone's kind.
    DeviceKey {
        kind: silentsilo_vault::KIND_FIDO2.into(),
        derivation: silentsilo_vault::DERIVATION_HMAC_V1.into(),
        credential_id: id.into(),
        public_key: String::new(),
        wrap_key,
        label: "Phone".into(),
    }
}

/// Device A: a silo with a folder, a recovery code and one key, synced.
struct Origin {
    _dirs: Vec<tempfile::TempDir>,
    storage: std::path::PathBuf,
    code: String,
    vault_id: Uuid,
}

async fn origin() -> Origin {
    let storage = tempfile::tempdir().unwrap();
    let silo_dir = tempfile::tempdir().unwrap();
    let root = silo_dir.path().join("silo");
    let vault_id = Uuid::new_v4();
    let session = VaultSession::provision(root.clone(), vault_id, "secret-a").unwrap();
    let vfs = Vfs::new(&session);
    vfs.ensure_initialized().unwrap();
    vfs.create_folder(vfs.root_folder_id().unwrap(), "From A")
        .unwrap();

    let (code, envelope) = silentsilo_vault::create_recovery_envelope(&session.dek).unwrap();
    silentsilo_vault::save_recovery_envelope(&root, &envelope).unwrap();
    enrol_device_key(&session, &key([7; 32], "aa11")).unwrap();

    let host = OneTarget(
        BackupTarget {
            config: StoreConfig::Folder {
                path: storage.path().to_path_buf(),
            },
            label: String::new(),
            role: TargetRole::Working,
        },
        Mutex::default(),
    );
    let state = AppState::default();
    let silo = SiloEntry {
        id: vault_id,
        name: "A".into(),
        path: root,
        last_opened: 0,
        auto_lock_minutes: None,
    };
    state.open_session(&host, silo.id, session).unwrap();
    let report = run_sync_pass(&state, &host, &silo).await.unwrap();
    assert!(report.ops_pushed > 0, "{report:?}");

    Origin {
        storage: storage.path().to_path_buf(),
        vault_id,
        code,
        _dirs: vec![storage, silo_dir],
    }
}

/// Device B joins with the code and replays the log.
async fn join(origin: &Origin, root: std::path::PathBuf) -> VaultSession {
    let store = FolderStore::new(origin.storage.clone());
    let joined = recovery_join_begin(&store, &origin.code).await.unwrap();
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

#[tokio::test]
async fn a_wrong_code_leaves_nothing_behind() {
    let origin = origin().await;
    let store = FolderStore::new(origin.storage.clone());
    let err = recovery_join_begin(&store, "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH")
        .await
        .err()
        .unwrap();
    assert_eq!(err, "That recovery code doesn't match this silo.");

    let empty = tempfile::tempdir().unwrap();
    let err = recovery_join_begin(&FolderStore::new(empty.path().to_path_buf()), &origin.code)
        .await
        .err()
        .unwrap();
    assert_eq!(err, "That bucket doesn't hold a silo.");
}

#[tokio::test]
async fn joining_with_the_code_brings_the_tree_and_the_keys_and_closes_the_secret_door() {
    let origin = origin().await;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("joined");
    let session = join(&origin, root.clone()).await;

    assert_eq!(session.vault_id, origin.vault_id);
    assert!(folder_names(&session).contains(&"From A".to_string()));
    let keys = silentsilo_vault::load_fido_keys(&root).unwrap();
    assert_eq!(keys.active().count(), 1, "A's key came down");
    assert!(silentsilo_vault::has_recovery_code(&root));
    drop(session);

    // The local DEK envelope is under A's key now, not this device's secret.
    assert!(VaultSession::open_with_device_secret(root.clone(), "secret-b").is_err());
    let (reopened, _) = open_with_device_key(root, "aa11", &[7; 32], origin.vault_id).unwrap();
    assert!(folder_names(&reopened).contains(&"From A".to_string()));
}

#[tokio::test]
async fn the_code_opens_the_joined_silo_and_a_wrong_one_does_not() {
    let origin = origin().await;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("joined");
    drop(join(&origin, root.clone()).await);

    let envelope = recovery_envelope_for(&root, None).await.unwrap();
    let err = open_with_recovery(
        root.clone(),
        &envelope,
        "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH",
        origin.vault_id,
    )
    .err()
    .unwrap();
    assert_eq!(err, "That recovery code doesn't match this silo.");

    let (session, meta) =
        open_with_recovery(root.clone(), &envelope, &origin.code, origin.vault_id).unwrap();
    assert_eq!(meta.vault_id, origin.vault_id);
    drop(session);

    assert!(
        open_with_recovery(root, &envelope, &origin.code, Uuid::new_v4()).is_err(),
        "the silo must be the one this device expects"
    );
}

#[tokio::test]
async fn a_phone_key_enrolled_after_joining_opens_the_silo_on_its_own() {
    let origin = origin().await;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("joined");
    let session = join(&origin, root.clone()).await;

    let added = enrol_device_key(&session, &key([9; 32], "bb22")).unwrap();
    assert_eq!(added.key_slot, 1, "after A's key");
    assert_eq!(
        enrol_device_key(&session, &key([9; 32], "bb22"))
            .err()
            .unwrap(),
        "This credential is already enrolled"
    );
    drop(session);

    let (_, meta) = open_with_device_key(root.clone(), "bb22", &[9; 32], origin.vault_id).unwrap();
    assert_eq!(meta.vault_id, origin.vault_id);
    assert!(open_with_device_key(root.clone(), "bb22", &[8; 32], origin.vault_id).is_err());
    assert!(open_with_device_key(root, "cc33", &[9; 32], origin.vault_id).is_err());
}
