//! A file's content, decrypted for showing inside the app.

use silentsilo_store::ObjectStore;
use silentsilo_vault::SiloEntry;
use silentsilo_vfs::Vfs;
use uuid::Uuid;

use crate::{AppState, Host, open_scratch_dir};

/// What a preview gets: the plaintext, and what it is.
pub struct FileContent {
    pub name: String,
    pub mime_type: Option<String>,
    pub bytes: Vec<u8>,
}

/// Decrypts one file into memory, downloading its content first when this
/// device does not hold it. Refused above `max_bytes`: a preview is held
/// whole in memory, which a video is not.
///
/// The plaintext passes through the silo's open-file scratch directory for
/// the length of the decrypt and is removed before this returns; a crash in
/// between leaves it where every lock and unlock already wipes.
pub async fn read_file(
    state: &AppState,
    host: &dyn Host,
    silo: &SiloEntry,
    file_id: Uuid,
    max_bytes: i64,
) -> Result<FileContent, String> {
    let (file, wrapped, kek) = {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        let session = sessions
            .get(&silo.id)
            .ok_or_else(|| silentsilo_core::CoreError::VaultLocked.to_string())?;
        let vfs = Vfs::new(session);
        let file = vfs.get_file(file_id).map_err(|e| e.to_string())?;
        let wrapped = vfs.blob_key(file_id).map_err(|e| e.to_string())?;
        (file, wrapped, session.kek.clone())
    };
    state.touch(silo.id);
    if file.size_bytes > max_bytes {
        return Err("This file is too large to show here.".into());
    }

    let root = &silo.path;
    let blob_path = silentsilo_vault::VaultPaths::new(root.clone()).blob_path(file.blob_id);
    if !blob_path.is_file() {
        let targets: Vec<Box<dyn ObjectStore>> = host
            .targets(silo.id)
            .into_iter()
            .filter_map(|t| t.config.open().ok())
            .collect();
        if targets.is_empty() {
            return Err(
                "This file isn't on this device, and no backup storage is connected.".into(),
            );
        }
        let stores: Vec<&dyn ObjectStore> = targets.iter().map(|t| &**t).collect();
        silentsilo_sync::fetch_blob_from_any(&stores, root, file.blob_id)
            .await
            .map_err(|e| format!("could not download the file content: {e}"))?;
    }

    let key = silentsilo_crypto::unwrap_content_key(&wrapped, &kek)
        .map_err(|_| "This content's key could not be read, so it cannot be opened.".to_string())?;
    let dir = open_scratch_dir(root);
    silentsilo_vault::create_private_dir(&dir).map_err(|e| e.to_string())?;
    let dest = dir.join(format!("preview-{}", Uuid::new_v4()));
    let decrypted = silentsilo_crypto::decrypt_blob(&blob_path, &dest, &key, file.blob_id)
        .map_err(|e| e.to_string())
        .and_then(|_| std::fs::read(&dest).map_err(|e| e.to_string()));
    let _ = std::fs::remove_file(&dest);

    Ok(FileContent {
        name: file.name,
        mime_type: file.mime_type,
        bytes: decrypted?,
    })
}
