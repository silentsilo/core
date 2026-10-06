//! Removable security keys over USB HID, spoken in CTAP2 by this crate's own
//! [`crate::ctap2`]: the code Android uses over NFC and USB, so a silo made on
//! one opens on the other.
//!
//! A key with a PIN is always asked for it, as Windows does. `hmac-secret`
//! keeps one secret for assertions with the PIN and another for those
//! without, so a key asked differently on two platforms opens neither's
//! silo on the other. The PIN is asked through [`crate::set_pin_prompt`],
//! which the client answers in its own window; the ceremony itself is in
//! [`crate::ctap2::ceremony`], tested on every platform.

use rand::RngCore;

use crate::ctap2::CtapError;
use crate::ctap2::ceremony::{enrol_on, unlock_on};
use crate::ctap2::hid::{Hid, REPORT_LEN, Reports};
use crate::types::{Authenticator, Enrollment, EnrollmentChallenge, UnlockMaterial};
use crate::{FidoError, RP_ID};

/// The FIDO usage page and its CTAPHID usage. A key is found by these, so one
/// whose vendor nobody listed still counts.
const FIDO_USAGE_PAGE: u16 = 0xF1D0;
const FIDO_USAGE: u16 = 0x01;

/// One key's HID interface. hidapi writes the report id first; CTAPHID uses
/// none, so it is 0.
struct UsbLink(hidapi::HidDevice);

impl Reports for UsbLink {
    fn write(&mut self, report: &[u8; REPORT_LEN]) -> Result<(), CtapError> {
        let mut out = [0u8; REPORT_LEN + 1];
        out[1..].copy_from_slice(report);
        self.0
            .write(&out)
            .map(|_| ())
            .map_err(|e| CtapError::Transport(e.to_string()))
    }

    fn read(&mut self, timeout_ms: u32) -> Result<Option<[u8; REPORT_LEN]>, CtapError> {
        let mut report = [0u8; REPORT_LEN];
        let timeout = i32::try_from(timeout_ms).unwrap_or(i32::MAX);
        match self.0.read_timeout(&mut report, timeout) {
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(report)),
            Err(e) => Err(CtapError::Transport(e.to_string())),
        }
    }
}

fn fido_devices(api: &hidapi::HidApi) -> Vec<&hidapi::DeviceInfo> {
    api.device_list()
        .filter(|d| d.usage_page() == FIDO_USAGE_PAGE && d.usage() == FIDO_USAGE)
        .collect()
}

pub(crate) fn fido_key_present() -> bool {
    hidapi::HidApi::new().is_ok_and(|api| !fido_devices(&api).is_empty())
}

pub(crate) fn fido_interface_accessible() -> bool {
    open_key().is_ok()
}

/// The first key that opens. One plugged in that will not open is, on Linux,
/// almost always a missing udev rule, and is said as such rather than as no
/// key at all.
fn open_key() -> Result<Hid<UsbLink>, FidoError> {
    let api = hidapi::HidApi::new().map_err(|e| FidoError::UnlockFailed(e.to_string()))?;
    let devices = fido_devices(&api);
    if devices.is_empty() {
        return Err(FidoError::NoDevice);
    }
    for device in devices {
        if let Ok(open) = device.open_device(&api) {
            return Ok(Hid::new(UsbLink(open)));
        }
    }
    Err(FidoError::NoAccess)
}

pub fn probe_device() -> Result<(), FidoError> {
    open_key().map(|_| ())
}

/// Always false here: USB HID reaches removable keys only.
pub(crate) fn platform_authenticator_available() -> bool {
    false
}

/// Nothing to wait for: no dialog of the platform's own stands between two
/// ceremonies.
pub(crate) fn wait_for_ceremony_teardown(_timeout_ms: u64) {}

pub fn begin_enrollment(
    vault_id: &str,
    key_slot: u8,
    authenticator: Authenticator,
) -> Result<EnrollmentChallenge, FidoError> {
    if authenticator == Authenticator::ThisDevice {
        return Err(FidoError::NotAvailable);
    }
    probe_device()?;
    let mut challenge = [0u8; 32];
    rand::rng().fill_bytes(&mut challenge);
    Ok(EnrollmentChallenge {
        challenge: challenge.to_vec(),
        rp_id: RP_ID.into(),
        user_id: vault_id.to_string(),
        key_slot,
        authenticator,
    })
}

pub fn complete_enrollment(challenge: &EnrollmentChallenge) -> Result<Enrollment, FidoError> {
    let mut key = open_key()?;
    enrol_on(&mut key, challenge)
}

pub fn derive_unlock_material(
    credential_ids: &[Vec<u8>],
    vault_id: &str,
    // USB has one kind of authenticator, so there is nothing to pin.
    _on: Option<Authenticator>,
) -> Result<UnlockMaterial, FidoError> {
    if credential_ids.is_empty() {
        return Err(FidoError::UnlockFailed("No enrolled security keys".into()));
    }
    let mut key = open_key()?;
    unlock_on(&mut key, credential_ids, vault_id)
}
