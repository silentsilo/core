//! What Touch ID's answers mean, read apart from the calls that get them so
//! every platform's tests cover them. `enclave_mac.rs` asks; this decides.

use crate::PlatformStatus;

/// Touch ID's state from `canEvaluatePolicy`: `None` when it succeeded,
/// otherwise its `LAError` code. Each code is a different thing for the
/// person to do. `has_sensor` is asked only for the one code it tells apart.
pub(super) fn touch_id_status(
    error_code: Option<isize>,
    has_sensor: impl FnOnce() -> bool,
) -> PlatformStatus {
    let Some(code) = error_code else {
        return PlatformStatus::Ready;
    };
    match code {
        // passcodeNotSet, biometryNotEnrolled
        -5 | -7 => PlatformStatus::NotSetUp,
        // biometryLockout; biometryNotPaired and biometryDisconnected,
        // a Touch ID keyboard not paired or unplugged.
        -8 | -12 | -13 => PlatformStatus::Unavailable,
        // biometryNotAvailable: no sensor, or one out of reach for now.
        // Told apart by whether this Mac has ever had biometry at all.
        -6 if has_sensor() => PlatformStatus::Unavailable,
        _ => PlatformStatus::Absent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_sensor_asked() -> bool {
        panic!("the sensor is asked about only for biometryNotAvailable")
    }

    #[test]
    fn touch_id_that_answers_is_ready() {
        assert_eq!(
            touch_id_status(None, no_sensor_asked),
            PlatformStatus::Ready
        );
    }

    #[test]
    fn no_password_or_no_fingerprint_is_not_set_up() {
        assert_eq!(
            touch_id_status(Some(-5), no_sensor_asked),
            PlatformStatus::NotSetUp
        );
        assert_eq!(
            touch_id_status(Some(-7), no_sensor_asked),
            PlatformStatus::NotSetUp
        );
    }

    #[test]
    fn a_locked_or_unplugged_sensor_is_unavailable_for_now() {
        for code in [-8, -12, -13] {
            assert_eq!(
                touch_id_status(Some(code), no_sensor_asked),
                PlatformStatus::Unavailable,
                "{code}"
            );
        }
    }

    #[test]
    fn biometry_not_available_depends_on_whether_a_sensor_exists() {
        // A MacBook with the lid closed.
        assert_eq!(
            touch_id_status(Some(-6), || true),
            PlatformStatus::Unavailable
        );
        // A Mac mini without a Touch ID keyboard.
        assert_eq!(touch_id_status(Some(-6), || false), PlatformStatus::Absent);
    }

    #[test]
    fn any_other_code_is_absent() {
        for code in [-1, -2, -4, -9, -10, -11, 0, 1] {
            assert_eq!(
                touch_id_status(Some(code), no_sensor_asked),
                PlatformStatus::Absent,
                "{code}"
            );
        }
    }
}
