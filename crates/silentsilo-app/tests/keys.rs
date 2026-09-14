//! Enrolled keys travelling between devices through the sync pass.

use silentsilo_app::flows::{DeviceKey, enrol_device_key};
use silentsilo_app::{AppEvent, AppState, Host, run_sync_pass};
use silentsilo_store::{FolderStore, ObjectStore, StoreConfig};
use silentsilo_vault::{
    BackupTarget, SiloEntry, StoredFidoKeys, TargetRole, VaultSession, load_fido_keys,
};
use silentsilo_vfs::Vfs;
use uuid::Uuid;

struct OneTarget(BackupTarget);

impl Host for OneTarget {
    fn emit(&self, _event: AppEvent) {}
    fn warn(&self, area: &str, detail: &str) {
        panic!("[{area}] {detail}");
    }
    fn targets(&self, _silo_id: Uuid) -> Vec<BackupTarget> {
        vec![self.0.clone()]
    }
}

struct Device {
    _dir: tempfile::TempDir,
    state: AppState,
    silo: SiloEntry,
}

impl Device {
    fn new(
        vault_id: Uuid,
        keys: Option<(silentsilo_crypto::MasterDek, silentsilo_crypto::ContentKek)>,
        host: &OneTarget,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("silo");
        let session = match keys {
            Some((dek, kek)) => {
                VaultSession::provision_with_dek(root.clone(), vault_id, "s", dek, kek).unwrap()
            }
            None => VaultSession::provision(root.clone(), vault_id, "s").unwrap(),
        };
        Vfs::new(&session).ensure_initialized().unwrap();
        let silo = SiloEntry {
            id: vault_id,
            name: "T".into(),
            path: root,
            last_opened: 0,
            auto_lock_minutes: None,
        };
        let state = AppState::default();
        state.open_session(host, vault_id, session).unwrap();
        Self {
            _dir: dir,
            state,
            silo,
        }
    }

    fn enrol(&self, id: &str, wrap: u8) {
        let sessions = self.state.sessions.lock().unwrap();
        enrol_device_key(
            &sessions[&self.silo.id],
            &DeviceKey {
                kind: silentsilo_vault::KIND_FIDO2.into(),
                derivation: silentsilo_vault::DERIVATION_HMAC_V1.into(),
                credential_id: id.into(),
                public_key: String::new(),
                wrap_key: [wrap; 32],
                label: id.into(),
            },
        )
        .unwrap();
    }

    fn keys(&self) -> StoredFidoKeys {
        load_fido_keys(&self.silo.path).unwrap()
    }

    fn active_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .keys()
            .active()
            .map(|k| k.credential_id.clone())
            .collect();
        ids.sort();
        ids
    }

    async fn pass(&self, host: &OneTarget) {
        run_sync_pass(&self.state, host, &self.silo).await.unwrap();
    }

    fn shared_keys(&self) -> (silentsilo_crypto::MasterDek, silentsilo_crypto::ContentKek) {
        let s = self.state.sessions.lock().unwrap();
        (s[&self.silo.id].dek.clone(), s[&self.silo.id].kek.clone())
    }
}

fn target(dir: &tempfile::TempDir) -> OneTarget {
    OneTarget(BackupTarget {
        config: StoreConfig::Folder {
            path: dir.path().to_path_buf(),
        },
        label: String::new(),
        role: TargetRole::Working,
    })
}

#[tokio::test]
async fn a_key_enrolled_later_on_one_device_appears_on_the_other_and_revocation_sticks() {
    let storage = tempfile::tempdir().unwrap();
    let host = target(&storage);

    // The desktop, set up first with its own key.
    let desktop = Device::new(Uuid::new_v4(), None, &host);
    desktop.enrol("aa11", 1);
    desktop.pass(&host).await;

    // The phone joins with both keys, then adds its own.
    let phone = Device::new(desktop.silo.id, Some(desktop.shared_keys()), &host);
    phone.enrol("aa11", 1);
    phone.enrol("bb22", 2);
    phone.pass(&host).await;

    // The desktop never joined after the phone's key existed, and still
    // learns it.
    desktop.pass(&host).await;
    assert_eq!(desktop.active_ids(), vec!["aa11", "bb22"]);

    // Revoked on the desktop: a marker goes up, the envelope goes away, and
    // the tombstone is dropped only once the marker is there.
    let mut keys = desktop.keys();
    keys.keys
        .iter_mut()
        .find(|k| k.credential_id == "bb22")
        .unwrap()
        .revoked = true;
    silentsilo_vault::save_fido_keys(
        &desktop.silo.path,
        &keys,
        silentsilo_vault::Authority::Machine,
    )
    .unwrap();
    desktop.pass(&host).await;

    let store = FolderStore::new(storage.path().to_path_buf());
    assert!(
        store
            .head("keys/revoked/bb22.sealed")
            .await
            .unwrap()
            .is_some()
    );
    assert!(store.head("keys/bb22.env").await.unwrap().is_none());
    assert_eq!(desktop.active_ids(), vec!["aa11"]);

    // The phone still has the key as active, and does not put it back.
    phone.pass(&host).await;
    assert_eq!(phone.active_ids(), vec!["aa11"]);
    assert!(store.head("keys/bb22.env").await.unwrap().is_none());

    // Nor does the desktop learn it again from anywhere.
    desktop.pass(&host).await;
    assert_eq!(desktop.active_ids(), vec!["aa11"]);
}

#[tokio::test]
async fn a_silo_with_no_keys_file_is_not_given_one() {
    // A silo that opens with its device secret would otherwise start asking
    // for a key it does not have.
    let storage = tempfile::tempdir().unwrap();
    let host = target(&storage);

    let with_key = Device::new(Uuid::new_v4(), None, &host);
    with_key.enrol("aa11", 1);
    with_key.pass(&host).await;

    let keyless = Device::new(with_key.silo.id, Some(with_key.shared_keys()), &host);
    keyless.pass(&host).await;
    assert!(!silentsilo_vault::is_fido_enrolled(&keyless.silo.path));
}

#[tokio::test]
async fn a_forged_revocation_marker_does_not_revoke_anything() {
    let storage = tempfile::tempdir().unwrap();
    let host = target(&storage);
    let device = Device::new(Uuid::new_v4(), None, &host);
    device.enrol("aa11", 1);
    device.pass(&host).await;

    // Write access to storage, no key: garbage where a sealed marker goes.
    FolderStore::new(storage.path().to_path_buf())
        .put(
            "keys/revoked/aa11.sealed",
            br#"{"version":1,"credential_id":"aa11","revoked_at":0}"#.to_vec(),
        )
        .await
        .unwrap();
    device.pass(&host).await;
    assert_eq!(device.active_ids(), vec!["aa11"]);
}
