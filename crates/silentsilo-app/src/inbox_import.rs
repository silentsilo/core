//! Moving what a locked phone sent into the silo, during a sync pass.
//!
//! The steps and why each is safe to repeat are in
//! `silentsilo_sync::inbox`. What this adds is when an item may leave the
//! inbox: only once a pass has found it already recorded and has reached
//! every copy. The record is pushed by the pass after the one that wrote it,
//! so an item never disappears from storage while the only trace of it is
//! this device's database.
//!
//! Public for a client whose sync pass is still its own: it supplies its
//! session map through [`OpenSilo`] and calls [`import_inbox`] at the same
//! point in its pass.

use std::path::Path;

use silentsilo_crypto::ContentKek;
use silentsilo_store::ObjectStore;
use silentsilo_sync::inbox::{finish_item, scan_inbox, stage_item};
use silentsilo_vfs::Vfs;
use uuid::Uuid;

use crate::AppState;

/// The silo being imported into, as the client holds it open. Called for
/// short database work only, never across an await. A background pass must
/// not count this as use: it would keep the silo from locking when idle.
pub trait OpenSilo: Sync {
    /// Runs `f` against the open silo, or fails when it was locked.
    fn with_vfs(
        &self,
        f: &mut dyn FnMut(&Vfs<'_>) -> silentsilo_core::CoreResult<()>,
    ) -> Result<(), String>;
}

/// One target as the import sees it.
pub struct InboxTarget<'a> {
    pub store: &'a dyn ObjectStore,
    pub label: &'a str,
    /// Whether an item already recorded may leave this target's inbox: the
    /// pass reached every configured copy, and the target allows deletes.
    /// An append-only target keeps its items, and they are skipped as known.
    pub may_finish: bool,
}

#[derive(Debug, Default)]
pub struct InboxOutcome {
    pub imported: usize,
    pub refused: Vec<String>,
}

/// `silo_root` is where content is fetched to when `keep_local` is set,
/// which makes the next push copy it to the targets that do not have it.
/// `warn` gets what went wrong with single items; they stay for next time.
#[allow(clippy::too_many_arguments)]
pub async fn import_inbox(
    silo: &dyn OpenSilo,
    warn: &(dyn Fn(&str) + Sync),
    silo_root: &Path,
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
                warn(&format!("{}: {e}", target.label));
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
            let mut known = false;
            if silo
                .with_vfs(&mut |vfs| {
                    known = vfs.file_id_known(item.item_id)?;
                    Ok(())
                })
                .is_err()
            {
                // Locked while the pass ran.
                return outcome;
            }
            if known {
                if target.may_finish
                    && let Err(e) = finish_item(target.store, item.item_id).await
                {
                    warn(&format!("{}: {e}", target.label));
                }
                continue;
            }

            if let Err(e) = stage_item(target.store, &item).await {
                warn(&format!("{}: {e}", target.label));
                continue;
            }
            let blob_key = match item.blob_key(kek) {
                Ok(key) => key,
                Err(e) => {
                    warn(&e.to_string());
                    continue;
                }
            };
            let mut added = false;
            let recorded = silo.with_vfs(&mut |vfs| {
                let folder = vfs.ensure_folder_path(&item.folder)?;
                added = vfs
                    .record_imported_file(
                        item.item_id,
                        folder.id,
                        &item.name,
                        item.blob_id,
                        item.size_bytes,
                        &item.content_hash,
                        item.mime_type.as_deref(),
                        &blob_key,
                    )?
                    .is_some();
                Ok(())
            });
            if let Err(e) = recorded {
                warn(&format!("{}: {e}", item.name));
                continue;
            }
            if added {
                outcome.imported += 1;
            }
            if keep_local
                && let Err(e) =
                    silentsilo_sync::fetch_blob(target.store, silo_root, item.blob_id).await
            {
                warn(&format!("{} did not come down: {e}", item.name));
            }
        }
    }
    outcome
}

/// A silo open in this crate's [`AppState`].
pub(crate) struct Session<'a> {
    pub state: &'a AppState,
    pub id: Uuid,
}

impl OpenSilo for Session<'_> {
    fn with_vfs(
        &self,
        f: &mut dyn FnMut(&Vfs<'_>) -> silentsilo_core::CoreResult<()>,
    ) -> Result<(), String> {
        let sessions = self.state.sessions.lock().map_err(|e| e.to_string())?;
        let session = sessions
            .get(&self.id)
            .ok_or_else(|| "The silo was locked".to_string())?;
        f(&Vfs::new(session)).map_err(|e| e.to_string())
    }
}
