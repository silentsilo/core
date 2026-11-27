//! How each open silo was unlocked, and what a lasting change asks for
//! because of it.
//!
//! Both apps used to keep this themselves, in a set of silos the recovery
//! code had opened. With the unlock password there are three ways in, and
//! the rule for each lives here so the desktop and the phones decide the
//! same way. Each app does only the ceremony: a key touch, a biometric
//! prompt, the password typed again.

use std::path::Path;

/// What opened a silo's session on this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unlocked {
    /// A key recorded in the silo's key file, by credential id.
    Key(String),
    /// The recovery code: the way back in when every key is lost, so it is
    /// asked for nothing more.
    RecoveryCode,
    /// The unlock password.
    Password,
    /// Opened without a credential: a silo just created or joined here.
    Fresh,
}

impl Unlocked {
    /// What the activity log writes as `via` for a session opened this way.
    /// `None` for a key: the app names it from its label.
    pub fn log_name(&self) -> Option<&'static str> {
        match self {
            Unlocked::Key(_) => None,
            Unlocked::RecoveryCode => Some(VIA_RECOVERY_CODE),
            Unlocked::Password => Some(VIA_PASSWORD),
            Unlocked::Fresh => None,
        }
    }
}

/// What the log calls an unlock with the recovery code.
pub const VIA_RECOVERY_CODE: &str = "recovery code";
/// What the log calls an unlock with the unlock password.
pub const VIA_PASSWORD: &str = "unlock password";

/// Something a session does that may need the user to prove they are there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Reading, editing, importing, syncing.
    Everyday,
    /// Showing a protected entry, a fill from the extension, auto-type, an
    /// SSH signature.
    ProtectedEntry,
    /// CSV, KDBX or `.silopwd` export.
    Export,
    /// Adding or removing a key.
    KeyChange,
    /// A new recovery code, or turning it off.
    RecoveryChange,
    /// Setting, changing or removing the unlock password.
    PasswordChange,
    /// A new backup copy, or stopping the activity log.
    BackupOrLog,
    /// Rotating the silo key.
    Rotation,
}

/// What the app asks for before the action goes ahead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    /// Nothing.
    None,
    /// A touch of one of this device's usable keys.
    KeyTouch,
    /// The unlock password, typed again.
    PasswordTyped,
}

/// What this device has that can confirm an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeviceMeans {
    /// A key this device can use: a security key or this device's own.
    pub usable_key: bool,
    /// The silo has an unlock password here.
    pub password: bool,
}

impl DeviceMeans {
    /// Reads what the silo folder records. `usable_key` is the app's answer:
    /// whether one of the silo's keys works on this device (a phone's key
    /// does not work on a computer), which only the app can tell.
    pub fn of(vault_root: &Path, usable_key: bool) -> Self {
        Self {
            usable_key,
            password: silentsilo_vault::password::has_unlock_password(vault_root),
        }
    }
}

/// The confirmation `action` needs in a session opened as `unlocked`.
///
/// A device with a usable key always asks for the key, whatever opened the
/// session: a typed password is knowledge a keylogger can replay. Without a
/// key, the password typed again is the best there is. The recovery code
/// asks for nothing, as before: it is what someone who lost every key has.
/// A silo with neither a key nor a password here (just created, waiting for
/// its first one) asks for nothing, as before.
pub fn confirmation_for(action: Action, unlocked: &Unlocked, means: DeviceMeans) -> Confirmation {
    if action == Action::Everyday || *unlocked == Unlocked::RecoveryCode {
        return Confirmation::None;
    }
    // Opened with the password and no key to ask for: the password again,
    // even if the file holding it went away during the session. A missing
    // file must not turn every check into nothing.
    if *unlocked == Unlocked::Password && !means.usable_key {
        return Confirmation::PasswordTyped;
    }
    if means.usable_key {
        Confirmation::KeyTouch
    } else if means.password {
        Confirmation::PasswordTyped
    } else {
        Confirmation::None
    }
}

/// Whether a confirmation made at `last` still covers a new one at `now`.
/// `grace` is the app's: two minutes on a phone, none on the desktop. Any
/// unlock counts as a confirmation, a password one included.
pub fn within_grace(
    last: Option<std::time::Instant>,
    now: std::time::Instant,
    grace: std::time::Duration,
) -> bool {
    !grace.is_zero() && last.is_some_and(|at| now.saturating_duration_since(at) < grace)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTIONS: [Action; 7] = [
        Action::ProtectedEntry,
        Action::Export,
        Action::KeyChange,
        Action::RecoveryChange,
        Action::PasswordChange,
        Action::BackupOrLog,
        Action::Rotation,
    ];

    fn means(usable_key: bool, password: bool) -> DeviceMeans {
        DeviceMeans {
            usable_key,
            password,
        }
    }

    #[test]
    fn everyday_work_asks_nothing_whatever_opened_the_silo() {
        for unlocked in [
            Unlocked::Key("ab".into()),
            Unlocked::RecoveryCode,
            Unlocked::Password,
            Unlocked::Fresh,
        ] {
            for m in [
                means(true, true),
                means(true, false),
                means(false, true),
                means(false, false),
            ] {
                assert_eq!(
                    confirmation_for(Action::Everyday, &unlocked, m),
                    Confirmation::None
                );
            }
        }
    }

    #[test]
    fn a_device_with_a_key_asks_for_it_even_in_a_password_session() {
        for action in ACTIONS {
            for unlocked in [
                Unlocked::Key("ab".into()),
                Unlocked::Password,
                Unlocked::Fresh,
            ] {
                for password in [true, false] {
                    assert_eq!(
                        confirmation_for(action, &unlocked, means(true, password)),
                        Confirmation::KeyTouch,
                        "{action:?} {unlocked:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_device_without_a_key_asks_for_the_password_again() {
        for action in ACTIONS {
            for unlocked in [
                Unlocked::Key("ab".into()),
                Unlocked::Password,
                Unlocked::Fresh,
            ] {
                assert_eq!(
                    confirmation_for(action, &unlocked, means(false, true)),
                    Confirmation::PasswordTyped,
                    "{action:?} {unlocked:?}"
                );
            }
        }
    }

    #[test]
    fn the_recovery_code_asks_for_nothing_as_before() {
        for action in ACTIONS {
            for m in [
                means(true, true),
                means(true, false),
                means(false, true),
                means(false, false),
            ] {
                assert_eq!(
                    confirmation_for(action, &Unlocked::RecoveryCode, m),
                    Confirmation::None
                );
            }
        }
    }

    #[test]
    fn a_silo_with_nothing_to_confirm_with_asks_for_nothing_as_before() {
        for action in ACTIONS {
            assert_eq!(
                confirmation_for(action, &Unlocked::Fresh, means(false, false)),
                Confirmation::None
            );
        }
    }

    #[test]
    fn the_log_names_the_code_and_the_password_not_a_key() {
        assert_eq!(Unlocked::RecoveryCode.log_name(), Some("recovery code"));
        assert_eq!(Unlocked::Password.log_name(), Some("unlock password"));
        assert_eq!(Unlocked::Key("ab".into()).log_name(), None);
        assert_eq!(Unlocked::Fresh.log_name(), None);
    }

    #[test]
    fn grace_counts_only_inside_its_window_and_never_when_zero() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        let two = Duration::from_secs(120);
        assert!(within_grace(Some(now), now + Duration::from_secs(60), two));
        assert!(!within_grace(
            Some(now),
            now + Duration::from_secs(121),
            two
        ));
        assert!(!within_grace(None, now, two));
        assert!(!within_grace(Some(now), now, Duration::ZERO));
    }
}
