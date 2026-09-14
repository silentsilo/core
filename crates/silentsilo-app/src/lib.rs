//! The application logic every SilentSilo client shares.
//!
//! What lives here was the desktop's command layer: which silos are open,
//! how one is closed, and the order a sync pass runs in. A client supplies a
//! [`Host`] for what only it can do (tell its interface something happened,
//! write a diagnostic, read its saved storage settings) and keeps its own
//! window, tray and platform glue.
//!
//! Nothing here may depend on a user interface. The flows and their
//! invariants are described in the desktop repository's `docs/ARCHITECTURE.md`
//! and in this repository's `docs/ARCHITECTURE.md`.

pub mod files;
pub mod flows;
mod host;
mod state;
mod store_config;
mod sync_pass;

pub use host::{AppEvent, Host};
pub use state::{
    AppState, MAX_OPEN_SILOS, SessionGuard, SessionSnapshot, open_scratch_dir, wipe_open_scratch,
};
pub use store_config::{SftpAuthInput, StoreConfigInput, StoreConfigView};
pub use sync_pass::{SyncReport, TargetStatus, run_sync_pass, sync_now};
