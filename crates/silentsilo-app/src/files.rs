//! A file's content, decrypted for showing inside the app.

use silentsilo_core::FileEntry;
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
    let size = {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        let session = sessions
            .get(&silo.id)
            .ok_or_else(|| silentsilo_core::CoreError::VaultLocked.to_string())?;
        Vfs::new(session)
            .get_file(file_id)
            .map_err(|e| e.to_string())?
            .size_bytes
    };
    if size > max_bytes {
        return Err("This file is too large to show here.".into());
    }

    let dir = open_scratch_dir(&silo.path);
    silentsilo_vault::create_private_dir(&dir).map_err(|e| e.to_string())?;
    let dest = dir.join(format!("preview-{}", Uuid::new_v4()));
    let decrypted = decrypt_to_file(state, host, silo, file_id, &dest)
        .await
        .and_then(|file| {
            std::fs::read(&dest)
                .map(|bytes| (file, bytes))
                .map_err(|e| e.to_string())
        });
    let _ = std::fs::remove_file(&dest);
    let (file, bytes) = decrypted?;

    Ok(FileContent {
        name: file.name,
        mime_type: file.mime_type,
        bytes,
    })
}

/// Decrypts one file to `dest`, downloading its content first when this
/// device does not hold it. The caller chose `dest` and removes it; a place
/// every lock wipes, such as [`open_scratch_dir`], is the right one.
pub async fn decrypt_to_file(
    state: &AppState,
    host: &dyn Host,
    silo: &SiloEntry,
    file_id: Uuid,
    dest: &std::path::Path,
) -> Result<FileEntry, String> {
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

    let root = &silo.path;
    let blob_path = silentsilo_vault::VaultPaths::new(root.clone()).blob_path(file.blob_id);
    if !blob_path.is_file() {
        let configured = host.targets(silo.id);
        let every_target: Vec<Uuid> = configured.iter().map(|t| t.config.target_id()).collect();
        let targets: Vec<(Uuid, Box<dyn ObjectStore>)> = configured
            .into_iter()
            .filter_map(|t| {
                let id = t.config.target_id();
                t.config.open().ok().map(|store| (id, store))
            })
            .collect();
        if targets.is_empty() {
            return Err(
                "This file isn't on this device, and no backup storage is connected.".into(),
            );
        }
        let stores: Vec<(Uuid, &dyn ObjectStore)> =
            targets.iter().map(|(id, t)| (*id, &**t)).collect();
        silentsilo_sync::fetch_blob_from_targets(&stores, root, file.blob_id)
            .await
            .map_err(|e| format!("could not download the file content: {e}"))?;
        let _ = silentsilo_vault::settle_blob_delivery(root, &every_target);
    }

    let key = silentsilo_crypto::unwrap_content_key(&wrapped, &kek)
        .map_err(|_| "This content's key could not be read, so it cannot be opened.".to_string())?;
    if let Err(e) = silentsilo_crypto::decrypt_blob(&blob_path, dest, &key, file.blob_id) {
        let _ = std::fs::remove_file(dest);
        return Err(e.to_string());
    }
    Ok(file)
}

/// Adds a file from this device to `folder_id`: sealed into the blob store
/// with no lock held, since encrypting a large file under the sessions lock
/// freezes the interface, then one short lock for its record. The next sync
/// pass uploads it. Moved from the desktop's `encrypt_import` and
/// `commit_import`.
///
/// `source` is read rather than opened, and `name` and `mime_type` are given:
/// on a phone the source is a descriptor another app handed over, with no
/// name of its own and no path this app may open. A name already in the
/// folder has its content replaced, as a drop onto an existing file does on
/// the desktop.
pub fn import_file(
    state: &AppState,
    silo: &SiloEntry,
    folder_id: Uuid,
    source: &mut dyn std::io::Read,
    name: &str,
    mime_type: Option<&str>,
) -> Result<FileEntry, String> {
    let kek = {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        sessions
            .get(&silo.id)
            .ok_or_else(|| silentsilo_core::CoreError::VaultLocked.to_string())?
            .kek
            .clone()
    };
    state.touch(silo.id);

    let root = &silo.path;
    let file_id = Uuid::now_v7();
    let blob_id = Uuid::new_v4();
    let blob_path = silentsilo_vault::VaultPaths::new(root.clone()).blob_path(blob_id);
    if let Some(parent) = blob_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    // A key for this blob alone, wrapped under the content KEK and stored in
    // the record rather than in the file. That is what lets a later key
    // rotation leave every byte of content where it is.
    let content_key = silentsilo_crypto::generate_content_key();
    let blob_key =
        silentsilo_crypto::wrap_content_key(&content_key, &kek).map_err(|e| e.to_string())?;
    let sealed = silentsilo_crypto::encrypt_stream(
        &mut { source },
        &blob_path,
        &content_key,
        file_id,
        blob_id,
    )
    .map_err(|e| e.to_string())?;
    let _ = silentsilo_vault::record_blob_present(root, blob_id, sealed.size_bytes as i64, false);
    let mime = mime_type
        .filter(|m| !m.is_empty())
        .map(str::to_string)
        .or_else(|| silentsilo_vfs::guess_mime(std::path::Path::new(name)));

    let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
    let session = sessions
        .get(&silo.id)
        .ok_or_else(|| silentsilo_core::CoreError::VaultLocked.to_string())?;
    Vfs::new(session)
        .add_file(
            folder_id,
            name,
            blob_id,
            // Counted during encryption, so the row matches the sealed bytes
            // even when the source changed while it was being read.
            sealed.plain_bytes as i64,
            &hex::encode(sealed.header.content_hash),
            mime.as_deref(),
            &blob_key,
        )
        .map_err(|e| e.to_string())
}
