use silentsilo_vault::BackupTarget;
use uuid::Uuid;

use crate::sync_pass::SyncReport;

/// Something the interface is told about. Each client maps these to its own
/// event names and payloads; the desktop keeps the names it always had.
#[derive(Debug, Clone)]
pub enum AppEvent {
    /// What a sync pass came to (`sync-report` on the desktop).
    SyncReport(SyncReport),
    /// Remote changes landed, so any listing on screen is stale
    /// (`vault-changed`).
    VaultChanged,
}

/// What only the client running this code can do.
pub trait Host: Send + Sync {
    fn emit(&self, event: AppEvent);

    /// Something went wrong in a place that carries on regardless. `area` is
    /// the operation, not the file, so a line is searchable without putting
    /// the user's own words in it.
    fn warn(&self, area: &str, detail: &str);

    /// Every place a silo backs up to, as this client stored them. The
    /// desktop reads the OS keyring; a phone keeps its own store.
    fn targets(&self, silo_id: Uuid) -> Vec<BackupTarget>;
}
