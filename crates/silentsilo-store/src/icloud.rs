//! iCloud Drive: the SilentSilo app's container in the user's iCloud Drive,
//! a folder the system keeps in sync, so it is a [`FolderStore`] at a place
//! each platform finds on its own.
//!
//! Where the container is, verified on 11 October 2026 (`planuri/icloud.md`):
//! - iPhone: wherever iOS says (`FileManager.url(forUbiquityContainerIdentifier:)`),
//!   then `Documents`; the app passes a locator in, since only Swift can ask;
//! - Mac: `~/Library/Mobile Documents/iCloud~com~silentsilo~mobile/Documents`;
//! - Windows (iCloud for Windows): `%USERPROFILE%\iCloudDrive\iCloud~com~silentsilo~mobile`,
//!   which is the same `Documents`, shown without the name.
//!
//! A file another device wrote may be only in iCloud at first; reading it
//! brings it down on all three, so nothing here asks for downloads.
//!
//! The container itself is never created here. It exists once iCloud Drive
//! is on and the iPhone app has used it; a folder made by hand where it
//! should be would not sync, and would quietly become a copy nobody else
//! sees. Without it the target is unreachable, like an unplugged drive.

use std::path::PathBuf;

use crate::{FolderStore, StoreError};

/// The container as iCloud names it on disk.
pub const CONTAINER_FOLDER: &str = "iCloud~com~silentsilo~mobile";

/// The silo's folder inside SilentSilo's folder in iCloud Drive.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ICloudConfig {
    /// One plain name, shown to the user in iCloud Drive.
    pub folder: String,
}

/// Finds the container's `Documents` on a platform where only the app can
/// ask (the iPhone). `None` when iCloud Drive is off or signed out.
pub type ICloudLocator = fn() -> Option<PathBuf>;

static LOCATOR: std::sync::OnceLock<ICloudLocator> = std::sync::OnceLock::new();

/// Called once by an app that has a locator; later calls change nothing.
pub fn set_icloud_locator(locator: ICloudLocator) {
    let _ = LOCATOR.set(locator);
}

/// Whether this device can have iCloud Drive at all: with a locator, or on
/// a Mac or a Windows PC. Android and Linux have no iCloud Drive.
pub fn icloud_supported() -> bool {
    LOCATOR.get().is_some() || cfg!(any(target_os = "macos", windows))
}

/// The container's `Documents` on this device, when iCloud Drive has it.
pub fn icloud_documents() -> Option<PathBuf> {
    if let Some(locate) = LOCATOR.get() {
        return locate().filter(|path| path.is_dir());
    }
    platform_documents().filter(|path| path.is_dir())
}

#[cfg(target_os = "macos")]
fn platform_documents() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(
        PathBuf::from(home)
            .join("Library/Mobile Documents")
            .join(CONTAINER_FOLDER)
            .join("Documents"),
    )
}

#[cfg(windows)]
fn platform_documents() -> Option<PathBuf> {
    let profile = std::env::var_os("USERPROFILE")?;
    Some(
        PathBuf::from(profile)
            .join("iCloudDrive")
            .join(CONTAINER_FOLDER),
    )
}

#[cfg(not(any(target_os = "macos", windows)))]
fn platform_documents() -> Option<PathBuf> {
    None
}

/// What the settings screen shows before iCloud Drive is chosen.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ICloudStatus {
    /// This device can have iCloud Drive at all.
    pub supported: bool,
    /// SilentSilo's folder is there now.
    pub found: bool,
    /// The silo folders already in it, to join one.
    pub folders: Vec<String>,
}

/// Whether iCloud Drive is usable here, and what it holds already.
pub fn icloud_status() -> ICloudStatus {
    let supported = icloud_supported();
    let documents = if supported { icloud_documents() } else { None };
    let mut folders: Vec<String> = documents
        .as_ref()
        .and_then(|dir| std::fs::read_dir(dir).ok())
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|name| !name.starts_with('.'))
                .collect()
        })
        .unwrap_or_default();
    folders.sort_by_key(|name| name.to_lowercase());
    ICloudStatus {
        supported,
        found: documents.is_some(),
        folders,
    }
}

/// The store for one silo's folder, or why there is none on this device.
pub(crate) fn open(config: &ICloudConfig) -> Result<FolderStore, StoreError> {
    if !icloud_supported() {
        return Err(StoreError::Unreachable(
            silentsilo_core::coded!(
                "err.icloud_not_here",
                "iCloud Drive is not available on this device. Open this silo on an iPhone, a Mac or a Windows PC with iCloud, or add another backup copy for this one."
            )
            .into(),
        ));
    }
    let documents = icloud_documents().ok_or_else(|| {
        StoreError::Unreachable(
            silentsilo_core::coded!(
                "err.icloud_off",
                "SilentSilo's folder is not in iCloud Drive on this device. Turn iCloud Drive on and sign in with the same Apple account. On a computer, the folder appears once the iPhone app has used iCloud Drive."
            )
            .into(),
        )
    })?;
    Ok(FolderStore::new(documents.join(&config.folder)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_config_is_stored_as_a_folder_name_only() {
        let config = ICloudConfig {
            folder: "Silo".into(),
        };
        assert_eq!(
            serde_json::to_value(&config).unwrap(),
            serde_json::json!({ "folder": "Silo" })
        );
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    #[test]
    fn a_device_without_icloud_says_so_rather_than_opening_a_folder() {
        if LOCATOR.get().is_none() {
            let config = ICloudConfig {
                folder: "Silo".into(),
            };
            let Err(StoreError::Unreachable(message)) = open(&config) else {
                panic!("no iCloud Drive here, so no store");
            };
            assert!(message.contains("err.icloud_not_here"));
        }
    }

    #[cfg(any(target_os = "macos", windows))]
    #[test]
    fn the_container_is_found_under_the_user_profile() {
        let documents = platform_documents().expect("a home folder");
        assert!(documents.to_string_lossy().contains(CONTAINER_FOLDER));
    }
}
