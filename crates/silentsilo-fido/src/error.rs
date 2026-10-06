use thiserror::Error;

#[derive(Debug, Error)]
pub enum FidoError {
    #[error("FIDO2 hardware not available on this platform")]
    NotAvailable,

    #[error("no security key was found: plug it in and try again")]
    NoDevice,

    /// Plugged in, but this account may not open it.
    #[error(
        "a security key is plugged in, but this account cannot reach it. On Linux, install the udev rule for FIDO keys (the libfido2 package has one), then plug the key in again"
    )]
    NoAccess,

    #[error("cancelled: the PIN was not entered")]
    Cancelled,

    #[error("enrollment failed: {0}")]
    EnrollmentFailed(String),

    #[error("unlock failed: {0}")]
    UnlockFailed(String),

    #[error("check-in signature failed: {0}")]
    CheckInFailed(String),
}
