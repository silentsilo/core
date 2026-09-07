#[cfg(all(feature = "hardware", not(windows)))]
mod ctap;

#[cfg(all(feature = "hardware", windows))]
mod win;

#[cfg(all(feature = "enclave", target_os = "macos"))]
mod enclave_mac;

#[cfg(all(feature = "hardware", feature = "enclave", target_os = "macos"))]
mod mac;

#[cfg(all(feature = "hardware", not(windows), not(target_os = "macos")))]
pub(crate) use ctap::*;

// A Mac without the enclave feature is a Linux-shaped build: removable keys
// only, over CTAP.
#[cfg(all(feature = "hardware", not(feature = "enclave"), target_os = "macos"))]
pub(crate) use ctap::*;

#[cfg(all(feature = "hardware", feature = "enclave", target_os = "macos"))]
pub(crate) use mac::*;

#[cfg(all(feature = "hardware", windows))]
pub(crate) use win::*;

#[cfg(not(feature = "hardware"))]
mod stub;

#[cfg(not(feature = "hardware"))]
pub(crate) use stub::*;
