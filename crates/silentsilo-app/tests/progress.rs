//! What a running pass tells the interface while it moves things.

use std::sync::Mutex;

use silentsilo_app::{AppEvent, AppState, Host, SyncProgress, run_sync_pass};
use silentsilo_store::StoreConfig;
use silentsilo_vault::{BackupTarget, SiloEntry, TargetRole, VaultSession};
use silentsilo_vfs::Vfs;
use uuid::Uuid;

struct Recording {
    target: BackupTarget,
    progress: Mutex<Vec<SyncProgress>>,
}

impl Host for Recording {
    fn emit(&self, event: AppEvent) {
        if let AppEvent::SyncProgress(step) = event {
            self.progress.lock().unwrap().push(step);
        }
    }
    fn warn(&self, _area: &str, _detail: &str) {}
    fn targets(&self, _silo_id: Uuid) -> Vec<BackupTarget> {
        vec![self.target.clone()]
    }
}

#[tokio::test]
async fn an_upload_is_announced_with_the_file_it_belongs_to() {
    let storage = tempfile::tempdir().unwrap();
    let host = Recording {
        target: BackupTarget {
            config: StoreConfig::Folder {
                path: storage.path().to_path_buf(),
            },
            label: String::new(),
            role: TargetRole::Working,
        },
        progress: Mutex::new(Vec::new()),
    };
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("silo");
    let id = Uuid::new_v4();
    let session = VaultSession::provision(root.clone(), id, "s").unwrap();
    Vfs::new(&session).ensure_initialized().unwrap();
    let folder = Vfs::new(&session).root_folder_id().unwrap();
    let silo = SiloEntry {
        id,
        name: "T".into(),
        path: root,
        last_opened: 0,
        auto_lock_minutes: None,
    };
    let state = AppState::default();
    state.open_session(&host, id, session).unwrap();

    let file = silentsilo_app::files::import_file(
        &state,
        &silo,
        folder,
        &mut &b"a scanned contract"[..],
        "Contract.pdf",
        None,
    )
    .unwrap();
    run_sync_pass(&state, &host, &silo).await.unwrap();

    let steps = host.progress.lock().unwrap();
    let upload = steps
        .iter()
        .find(|s| s.phase == "uploading")
        .expect("the upload was announced");
    assert_eq!(upload.name.as_deref(), Some("Contract.pdf"));
    assert_eq!(
        upload.file_id.as_deref(),
        Some(file.id.to_string().as_str())
    );
    assert!(steps.iter().any(|s| s.phase == "sending-changes"));
}
