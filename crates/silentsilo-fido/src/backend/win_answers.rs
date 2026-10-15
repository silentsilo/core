//! What Windows' answers mean, read apart from the calls that get them so
//! every platform's tests cover them. `win.rs` asks; this decides.

use crate::PlatformStatus;

/// `TPM_DEVICE_INFO::tpmVersion` of a TPM 2.0; 1 is a TPM 1.2, which Hello
/// cannot derive a PRF secret from either.
pub(super) const TPM_VERSION_20: u8 = 2;
/// The first WebAuthn API whose Hello gives a PRF secret, and the first that
/// takes credential hints.
pub(super) const API_VERSION_8: u32 = 8;

/// The built-in authenticator's state from the three facts `win.rs` reads.
/// The TPM first: without one, neither an update nor setting up Hello would
/// help.
pub(super) fn platform_status(
    tpm_version: Option<u8>,
    api_version: u32,
    hello_enrolled: bool,
) -> PlatformStatus {
    if tpm_version != Some(TPM_VERSION_20) {
        PlatformStatus::NoTpm
    } else if api_version < API_VERSION_8 {
        PlatformStatus::UpdateWindows
    } else if !hello_enrolled {
        PlatformStatus::NotSetUp
    } else {
        PlatformStatus::Ready
    }
}

/// Whether an assertion's authenticator data says the person was verified.
/// Flags follow the 32-byte rpIdHash; bit 2 is UV.
pub(super) fn user_verified(auth_data: &[u8]) -> bool {
    auth_data.get(32).is_some_and(|flags| flags & 0x04 != 0)
}

/// What a failed WebAuthn call was. WebAuthn reports most of these as
/// "NotAllowedError"; the HRESULT says which one it was.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Failure {
    /// No credential of this silo on what was offered.
    NotFoundHere,
    NoDevice,
    Cancelled,
    /// The prompt was left to run out.
    Timeout,
    Other,
}

/// Reads a failure from its HRESULT and `WebAuthNGetErrorName`.
pub(super) fn failure(code: u32, name: &str, enroll: bool) -> Failure {
    let lower = name.to_lowercase();
    match code {
        // NTE_NOT_FOUND: such as a Hello key gone with a reset TPM, or one
        // held by the computer at the other end of a remote desktop.
        0x8009_0011 if !enroll => return Failure::NotFoundHere,
        // NTE_DEVICE_NOT_FOUND
        0x8009_0035 => return Failure::NoDevice,
        _ => {}
    }
    // NTE_USER_CANCELLED (0x80090036) is left out: it is not known whether
    // the second ceremony of an enrolment, started while the first dialog
    // closes, fails with it, and that failure is retried.
    if lower.contains("cancel") || code == 0x800704C7 {
        return Failure::Cancelled;
    }
    // ERROR_TIMEOUT as an HRESULT. Said as such, so the app neither retries
    // it nor blames the storage.
    if code == 0x800705B4 || lower.contains("timeout") || lower.contains("timed out") {
        return Failure::Timeout;
    }
    Failure::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tpm_is_reported_before_the_windows_build_and_hello() {
        assert_eq!(platform_status(None, 9, true), PlatformStatus::NoTpm);
        assert_eq!(platform_status(None, 3, false), PlatformStatus::NoTpm);
        // A TPM 1.2 gives Hello nothing to derive from either.
        assert_eq!(platform_status(Some(1), 9, true), PlatformStatus::NoTpm);
        assert_eq!(platform_status(Some(0), 9, true), PlatformStatus::NoTpm);
    }

    #[test]
    fn an_old_windows_is_told_to_update_before_setting_up_hello() {
        assert_eq!(
            platform_status(Some(2), 7, false),
            PlatformStatus::UpdateWindows
        );
        assert_eq!(
            platform_status(Some(2), 7, true),
            PlatformStatus::UpdateWindows
        );
        assert_eq!(platform_status(Some(2), 8, false), PlatformStatus::NotSetUp);
    }

    #[test]
    fn hello_is_ready_only_with_all_three() {
        assert_eq!(platform_status(Some(2), 8, true), PlatformStatus::Ready);
        assert_eq!(platform_status(Some(2), 9, true), PlatformStatus::Ready);
    }

    #[test]
    fn the_uv_flag_is_read_from_the_byte_after_the_rp_id_hash() {
        let mut data = vec![0u8; 37];
        assert!(!user_verified(&data));
        // UP alone: touched, not verified.
        data[32] = 0x01;
        assert!(!user_verified(&data));
        data[32] = 0x05;
        assert!(user_verified(&data));
        // Every other flag set, UV not.
        data[32] = !0x04;
        assert!(!user_verified(&data));
        // The hash itself does not count.
        let mut hash_only = vec![0xFF; 32];
        hash_only.extend_from_slice(&[0x01, 0, 0, 0, 1]);
        assert!(!user_verified(&hash_only));
    }

    #[test]
    fn authenticator_data_too_short_for_flags_is_not_verified() {
        assert!(!user_verified(&[]));
        assert!(!user_verified(&[0x04; 32]));
        let mut just_flags = vec![0u8; 32];
        just_flags.push(0x04);
        assert!(user_verified(&just_flags));
    }

    #[test]
    fn a_closed_dialog_is_a_cancel() {
        assert_eq!(
            failure(0x800704C7, "NotAllowedError", true),
            Failure::Cancelled
        );
        assert_eq!(
            failure(0x800704C7, "NotAllowedError", false),
            Failure::Cancelled
        );
        assert_eq!(failure(0x80004005, "Cancelled", false), Failure::Cancelled);
    }

    #[test]
    fn nte_user_cancelled_stays_retryable() {
        for enroll in [true, false] {
            assert_eq!(
                failure(0x8009_0036, "NotAllowedError", enroll),
                Failure::Other
            );
        }
    }

    #[test]
    fn no_credential_here_is_said_only_at_unlock() {
        assert_eq!(
            failure(0x8009_0011, "NotAllowedError", false),
            Failure::NotFoundHere
        );
        assert_eq!(
            failure(0x8009_0011, "NotAllowedError", true),
            Failure::Other
        );
    }

    #[test]
    fn no_device_is_its_own_answer() {
        for enroll in [true, false] {
            assert_eq!(
                failure(0x8009_0035, "NotAllowedError", enroll),
                Failure::NoDevice
            );
        }
    }

    #[test]
    fn a_prompt_left_to_run_out_is_a_timeout() {
        assert_eq!(
            failure(0x800705B4, "NotAllowedError", false),
            Failure::Timeout
        );
        assert_eq!(failure(0x80004005, "TimeoutError", true), Failure::Timeout);
    }

    #[test]
    fn anything_else_is_passed_on() {
        assert_eq!(
            failure(0x80070057, "InvalidStateError", true),
            Failure::Other
        );
        assert_eq!(failure(0x8009_0027, "UnknownError", false), Failure::Other);
    }
}
