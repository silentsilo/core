//! Moving what a locked phone sent into the silo, during a sync pass.
//!
//! The steps and why each is safe to repeat are in
//! `silentsilo_sync::inbox`. What this adds is when an item may leave the
//! inbox: only once a pass has found it already recorded and has reached
//! every copy. The record is pushed by the pass after the one that wrote it,
//! so an item never disappears from storage while the only trace of it is
//! this device's database.

use silentsilo_crypto::ContentKek;
use silentsilo_store::ObjectStore;
use silentsilo_sync::inbox::{finish_item, scan_inbox, stage_item};
use silentsilo_vault::SiloEntry;
use silentsilo_vfs::Vfs;
use uuid::Uuid;

use crate::{AppState, Host};

/// One target as the import sees it.
pub(crate) struct InboxTarget<'a> {
    pub store: &'a dyn ObjectStore,
    pub label: &'a str,
    /// Whether an item already recorded may leave this target's inbox: the
    /// pass reached every configured copy, and the target allows deletes.
    /// An append-only target keeps its items, and they are skipped as known.
    pub may_finish: bool,
}

#[derive(Default)]
pub(crate) struct InboxOutcome {
    pub imported: usize,
    pub refused: Vec<String>,
}

/// `keep_local` fetches imported content down, so the next push copies it
/// to the targets that do not have it.
pub(crate) async fn import_inbox(
    state: &AppState,
    host: &dyn Host,
    silo: &SiloEntry,
    targets: &[InboxTarget<'_>],
    kek: &ContentKek,
    vault_id: Uuid,
    keep_local: bool,
) -> InboxOutcome {
    let mut outcome = InboxOutcome::default();
    for target in targets {
        let scan = match scan_inbox(target.store, vault_id, kek).await {
            Ok(scan) => scan,
            Err(e) => {
                host.warn("inbox", &format!("{}: {e}", target.label));
                continue;
            }
        };
        for refused in scan.refused {
            outcome.refused.push(format!(
                "{}: {} ({})",
                target.label, refused.object, refused.reason
            ));
        }

        for item in scan.ready {
            let known = match with_vfs(state, silo, |vfs| vfs.file_id_known(item.item_id)) {
                Ok(known) => known,
                // Locked while the pass ran.
                Err(_) => return outcome,
            };
            if known {
                if target.may_finish
                    && let Err(e) = finish_item(target.store, item.item_id).await
                {
                    host.warn("inbox", &format!("{}: {e}", target.label));
                }
                continue;
            }

            if let Err(e) = stage_item(target.store, &item).await {
                host.warn("inbox", &format!("{}: {e}", target.label));
                continue;
            }
            let blob_key = match item.blob_key(kek) {
                Ok(key) => key,
                Err(e) => {
                    host.warn("inbox", &e.to_string());
                    continue;
                }
            };
            let recorded = with_vfs(state, silo, |vfs| {
                let folder = vfs.ensure_folder_path(&item.folder)?;
                vfs.record_imported_file(
                    item.item_id,
                    folder.id,
                    &item.name,
                    item.blob_id,
                    item.size_bytes,
                    &item.content_hash,
                    item.mime_type.as_deref(),
                    &blob_key,
                )
            });
            match recorded {
                Ok(Some(_)) => outcome.imported += 1,
                Ok(None) => {}
                Err(e) => {
                    host.warn("inbox", &format!("{}: {e}", item.name));
                    continue;
                }
            }
            if keep_local
                && let Err(e) =
                    silentsilo_sync::fetch_blob(target.store, &silo.path, item.blob_id).await
            {
                host.warn("inbox", &format!("{} did not come down: {e}", item.name));
            }
        }
    }
    outcome
}

fn with_vfs<T>(
    state: &AppState,
    silo: &SiloEntry,
    f: impl FnOnce(&Vfs<'_>) -> silentsilo_core::CoreResult<T>,
) -> Result<T, String> {
    let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
    let session = sessions
        .get(&silo.id)
        .ok_or_else(|| "The silo was locked".to_string())?;
    f(&Vfs::new(session)).map_err(|e| e.to_string())
}
