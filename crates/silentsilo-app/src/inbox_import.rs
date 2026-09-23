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
use silentsilo_sync::inbox::{finish_item, is_staged, scan_inbox, source_present, stage_item};
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
    /// The target's id, to note content fetched from it as held there.
    pub id: Uuid,
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
/// `progress` hears how many of a target's ready items came before each.
#[allow(clippy::too_many_arguments)]
pub async fn import_inbox(
    silo: &dyn OpenSilo,
    warn: &(dyn Fn(&str) + Sync),
    silo_root: &Path,
    targets: &[InboxTarget<'_>],
    kek: &ContentKek,
    vault_id: Uuid,
    keep_local: bool,
    progress: &(dyn Fn(usize, usize) + Sync),
) -> InboxOutcome {
    let mut outcome = InboxOutcome::default();
    // Content ids the silo already uses. An item naming one would be copied
    // over that content, so it is refused instead.
    let mut referenced = std::collections::HashSet::new();
    if silo
        .with_vfs(&mut |vfs| {
            referenced = vfs.referenced_blobs_with_attachments()?;
            Ok(())
        })
        .is_err()
    {
        return outcome;
    }
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

        let total = scan.ready.len();
        // In listing order on every device. Same-named files take their
        // "(2)" suffixes in the order they are recorded, so devices that
        // import at once must record in the same order to agree on names.
        for (done, item) in scan.ready.into_iter().enumerate() {
            progress(done, total);
            let mut recorded = None;
            if silo
                .with_vfs(&mut |vfs| {
                    recorded = vfs.recorded_blob(item.item_id)?;
                    Ok(())
                })
                .is_err()
            {
                // Locked while the pass ran.
                return outcome;
            }
            if let Some(recorded) = recorded {
                // Copied back only over the content this item's own record
                // names. A record with other content has no use for it.
                if target.may_finish
                    && (recorded != item.blob_id
                        || ensure_staged(target.store, &item, warn, target.label).await)
                    && let Err(e) = finish_item(target.store, item.item_id).await
                {
                    warn(&format!("{}: {e}", target.label));
                }
                continue;
            }
            if referenced.contains(&item.blob_id) {
                outcome.refused.push(format!(
                    "{}: {} (its content id belongs to another file)",
                    target.label, item.name
                ));
                continue;
            }

            // Another device importing the same item may have copied it
            // already. The same signed blob id, so the same bytes: a second
            // copy through a phone is only time and data.
            let staged = match is_staged(target.store, &item).await {
                Ok(true) => Ok(()),
                Ok(false) => stage_item(target.store, &item).await,
                Err(e) => Err(e),
            };
            if let Err(e) = staged {
                // An envelope whose content is in neither place brings
                // nothing back, and staying would repeat this every pass.
                // Gone, it lets the phone that sent it notice and send the
                // item again.
                if target.may_finish
                    && let Ok(false) = source_present(target.store, item.item_id).await
                {
                    warn(&format!(
                        "{}: {} lost its content before import; removed so it can be sent again",
                        target.label, item.name
                    ));
                    let _ = finish_item(target.store, item.item_id).await;
                } else {
                    warn(&format!("{}: {e}", target.label));
                }
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
                let folder = vfs.ensure_folder_path(&item.folder, item.item_id)?;
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
            referenced.insert(item.blob_id);
            if added {
                outcome.imported += 1;
            }
            if keep_local {
                match silentsilo_sync::fetch_blob(target.store, silo_root, item.blob_id).await {
                    Ok(_) => {
                        let _ = silentsilo_vault::record_blob_delivered(
                            silo_root,
                            item.blob_id,
                            target.id,
                        );
                    }
                    Err(e) => warn(&format!("{} did not come down: {e}", item.name)),
                }
            }
        }
    }
    outcome
}

/// Checked before an item leaves the inbox. The content copied out of it
/// waits in `blobs/` for its record, and a device that recorded it and then
/// stayed locked for days can find it swept by another device. The inbox
/// still has it, so it is copied again. False keeps the item for next time.
async fn ensure_staged(
    store: &dyn ObjectStore,
    item: &silentsilo_sync::inbox::ReadyItem,
    warn: &(dyn Fn(&str) + Sync),
    label: &str,
) -> bool {
    match is_staged(store, item).await {
        Ok(true) => return true,
        Ok(false) => {}
        Err(e) => {
            warn(&format!("{label}: {e}"));
            return false;
        }
    }
    match stage_item(store, item).await {
        Ok(()) => true,
        Err(e) => {
            // With neither copy there is nothing an envelope can bring back,
            // and keeping it would repeat this on every pass.
            if let Ok(false) = source_present(store, item.item_id).await {
                warn(&format!("{label}: {} is gone from storage", item.name));
                return true;
            }
            warn(&format!("{label}: {e}"));
            false
        }
    }
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
            .ok_or_else(|| "The silo was locked.".to_string())?;
        f(&Vfs::new(session)).map_err(|e| e.to_string())
    }
}
