//! A security key's ceremonies with its PIN, over any link: make a
//! credential and derive the wrap key, or derive it to unlock. A key with a
//! PIN is always asked for it, as Windows does, since `hmac-secret` gives
//! another secret without it. A key without one is not enrolled: the day it
//! gets a PIN, every platform starts verifying and derives the other secret,
//! and the silo would no longer open with it. Used by the desktop's USB
//! backend on Linux and macOS; kept here, apart from the transport, so it is
//! tested everywhere.

#![cfg_attr(
    any(windows, not(feature = "hardware"), feature = "test-authenticator"),
    allow(dead_code)
)]

use zeroize::Zeroizing;

use super::{Ctap, CtapError, SaltShape};
use crate::types::{CredentialInfo, Enrollment, EnrollmentChallenge, UnlockMaterial};
use crate::{FidoError, PinAsk};

/// Makes the credential and, with the same PIN, the wrap key it gives, so the
/// caller needs no second ceremony. Two touches on the key all the same: it
/// counts one presence per operation.
pub(crate) fn enrol_on(
    dev: &mut dyn Ctap,
    challenge: &EnrollmentChallenge,
) -> Result<Enrollment, FidoError> {
    let vault_id = challenge.user_id.as_str();
    let info = super::get_info(dev).map_err(|e| failure(e, FidoError::EnrollmentFailed))?;
    if !info.pin_set {
        return Err(failure(CtapError::PinNotSet, FidoError::EnrollmentFailed));
    }
    let (made, pin) = with_pin(dev, FidoError::EnrollmentFailed, |dev, pin| {
        super::make_credential(dev, vault_id, pin)
    })?;
    let found = super::unlock_candidates(
        dev,
        std::slice::from_ref(&made.credential_id),
        vault_id,
        pin.as_deref().map(String::as_str),
        true,
    )
    .map_err(|e| failure(e, FidoError::EnrollmentFailed))?;
    Ok(Enrollment {
        credential: CredentialInfo {
            credential_id: made.credential_id,
            public_key: made.public_key,
            key_slot: challenge.key_slot,
            rp_id: challenge.rp_id.clone(),
            authenticator: challenge.authenticator,
        },
        unlock: Some(raw_material(found, None)?),
    })
}

pub(crate) fn unlock_on(
    dev: &mut dyn Ctap,
    credential_ids: &[Vec<u8>],
    vault_id: &str,
    opens: Option<crate::Opens>,
) -> Result<UnlockMaterial, FidoError> {
    let (found, _) = with_pin(dev, FidoError::UnlockFailed, |dev, pin| {
        super::unlock_candidates(dev, credential_ids, vault_id, pin, true)
    })?;
    // A silo enrolled before the key had a PIN is wrapped under the
    // unverified secret. Asked for only when the verified one opens nothing,
    // so every other unlock is the single assertion it always was, and
    // without a second touch, which the key does not need for it; a key that
    // refuses (one that always verifies) simply has none to give.
    let verified_opens =
        |opens: crate::Opens| raw_key(&found).is_some_and(|key| opens(&found.credential_id, &key));
    let unverified = if found.verified && opens.is_some_and(|opens| !verified_opens(opens)) {
        super::unlock_candidates(
            dev,
            std::slice::from_ref(&found.credential_id),
            vault_id,
            None,
            false,
        )
        .ok()
        .and_then(|c| raw_key(&c))
    } else {
        None
    };
    raw_material(found, unverified)
}

/// The raw-salt wrap key of an assertion.
fn raw_key(found: &super::UnlockCandidates) -> Option<[u8; 32]> {
    found
        .wrap_keys
        .iter()
        .find(|(shape, _)| *shape == SaltShape::Raw)
        .map(|(_, key)| **key)
}

/// The wrap key every platform derives: the raw salt, verified exactly when
/// the key has a PIN.
fn raw_material(
    found: super::UnlockCandidates,
    unverified_wrap_key: Option<[u8; 32]>,
) -> Result<UnlockMaterial, FidoError> {
    let wrap_key = raw_key(&found)
        .ok_or_else(|| FidoError::UnlockFailed("the key gave no hmac-secret output".into()))?;
    Ok(UnlockMaterial {
        wrap_key,
        credential_id: found.credential_id,
        verified: found.verified,
        unverified_wrap_key,
    })
}

/// Runs `op` with the key's PIN when it has one, asking for it first and
/// again after a wrong one. Returns the PIN that worked, for a second
/// operation in the same ceremony.
fn with_pin<T>(
    dev: &mut dyn Ctap,
    fail: fn(String) -> FidoError,
    mut op: impl FnMut(&mut dyn Ctap, Option<&str>) -> Result<T, CtapError>,
) -> Result<(T, Option<Zeroizing<String>>), FidoError> {
    let info = super::get_info(dev).map_err(|e| failure(e, fail))?;
    let retries = |dev: &mut dyn Ctap| {
        info.protocol()
            .ok()
            .and_then(|p| super::pin_retries(dev, p))
    };
    let mut pin = if info.pin_set {
        let left = retries(dev);
        Some(ask(PinAsk::Enter { retries: left })?)
    } else {
        None
    };
    loop {
        match op(dev, pin.as_deref().map(String::as_str)) {
            Ok(done) => return Ok((done, pin)),
            Err(CtapError::PinRequired) if pin.is_none() => {
                let left = retries(dev);
                pin = Some(ask(PinAsk::Enter { retries: left })?);
            }
            Err(CtapError::PinInvalid { retries: said }) => {
                let left = said.or_else(|| retries(dev));
                pin = Some(ask(PinAsk::Wrong { retries: left })?);
            }
            Err(e) => return Err(failure(e, fail)),
        }
    }
}

fn ask(question: PinAsk) -> Result<Zeroizing<String>, FidoError> {
    crate::ask_pin(question).ok_or(FidoError::Cancelled)
}

/// What a key's refusal means to the person holding it.
fn failure(error: CtapError, fail: fn(String) -> FidoError) -> FidoError {
    let said = match error {
        CtapError::NoCredentials => crate::coded!(
            "err.key_not_of_silo",
            "This security key is not one of this silo's keys."
        )
        .into(),
        CtapError::PinAuthBlocked => crate::coded!(
            "err.pin_blocked_temp",
            "Too many wrong PINs in a row. Unplug the key, plug it back in and try again."
        )
        .into(),
        CtapError::PinBlocked => crate::coded!(
            "err.pin_blocked",
            "This key's PIN is blocked. Only resetting the key clears it, and a reset erases everything on it."
        )
        .into(),
        CtapError::PinNotSet => crate::coded!(
            "err.key_needs_pin",
            "This key needs a PIN before it can open a silo. Set one with its maker's app or in Chrome's security key settings, then add it again."
        )
        .into(),
        CtapError::Timeout => {
            crate::coded!("err.key_no_touch", "No touch was received in time.").into()
        }
        // Whatever is missing, the answer is the same: what kind of key works.
        CtapError::Unsupported(_) => crate::coded!(
            "err.key_unsupported",
            "This key cannot open a silo. It needs FIDO2 with the hmac-secret extension, as on a YubiKey 5, a Nitrokey 3 or a SoloKey."
        )
        .into(),
        other => other.to_string(),
    };
    fail(said)
}

#[cfg(test)]
mod tests {
    use super::super::RP_ID;
    use super::super::hid::Hid;
    use super::super::soft_key::{RefusingHid, SoftKey};
    use super::*;
    use crate::types::Authenticator;
    use std::sync::Mutex;

    const VAULT: &str = "0198b7e2-5a3c-7d10-9c1e-3f2a4b5c6d7e";

    /// The prompt is process-wide; the tests that set it take turns.
    static PROMPT: Mutex<()> = Mutex::new(());

    fn challenge() -> EnrollmentChallenge {
        EnrollmentChallenge {
            challenge: vec![0; 32],
            rp_id: RP_ID.into(),
            user_id: VAULT.into(),
            key_slot: 0,
            authenticator: Authenticator::SecurityKey,
        }
    }

    /// Answers each question with the next of `answers`, and keeps the
    /// questions.
    fn answer_with(answers: &[&str]) -> std::sync::Arc<Mutex<Vec<PinAsk>>> {
        let asked = std::sync::Arc::new(Mutex::new(Vec::new()));
        let queue = Mutex::new(answers.iter().map(|a| a.to_string()).collect::<Vec<_>>());
        let seen = asked.clone();
        crate::set_pin_prompt(Box::new(move |question| {
            seen.lock().unwrap().push(question);
            let mut queue = queue.lock().unwrap();
            (!queue.is_empty()).then(|| Zeroizing::new(queue.remove(0)))
        }));
        asked
    }

    #[test]
    fn a_key_without_a_pin_is_not_enrolled() {
        let _turn = PROMPT.lock().unwrap_or_else(|e| e.into_inner());
        let asked = answer_with(&[]);
        let mut key = SoftKey::new(&[2]);
        let Err(FidoError::EnrollmentFailed(why)) = enrol_on(&mut key, &challenge()) else {
            panic!("a key without a PIN was enrolled");
        };
        assert!(why.contains("err.key_needs_pin"), "{why}");
        assert!(asked.lock().unwrap().is_empty());
    }

    #[test]
    fn a_key_enrolled_without_a_pin_unlocks_without_asking() {
        let _turn = PROMPT.lock().unwrap_or_else(|e| e.into_inner());
        let asked = answer_with(&[]);
        let mut key = SoftKey::new(&[2]);
        // Enrolled by an earlier release, which took keys without a PIN.
        let made = super::super::make_credential(&mut key, VAULT, None).unwrap();
        let opened = unlock_on(
            &mut key,
            std::slice::from_ref(&made.credential_id),
            VAULT,
            None,
        )
        .unwrap();
        assert_eq!(opened.wrap_key, key.expected_wrap_key(&made.credential_id));
        assert!(!opened.verified);
        assert!(opened.unverified_wrap_key.is_none());
        assert!(asked.lock().unwrap().is_empty());
    }

    #[test]
    fn a_pin_set_after_enrolment_still_reaches_the_old_secret() {
        let _turn = PROMPT.lock().unwrap_or_else(|e| e.into_inner());
        let mut key = SoftKey::new(&[2]);
        let made = super::super::make_credential(&mut key, VAULT, None).unwrap();
        let enrolled_under = key.expected_wrap_key(&made.credential_id);

        key.pin = Some("1234".into());
        answer_with(&["1234"]);
        // The silo's envelope opens only under the secret enrolled.
        let opens = move |_: &[u8], secret: &[u8; 32]| *secret == enrolled_under;
        let opened = unlock_on(
            &mut key,
            std::slice::from_ref(&made.credential_id),
            VAULT,
            Some(&opens),
        )
        .unwrap();
        assert!(opened.verified);
        assert_ne!(
            opened.wrap_key, enrolled_under,
            "the PIN reaches the other secret"
        );
        assert_eq!(opened.unverified_wrap_key, Some(enrolled_under));
    }

    #[test]
    fn a_key_whose_verified_secret_opens_is_asked_once() {
        let _turn = PROMPT.lock().unwrap_or_else(|e| e.into_inner());
        let mut key = SoftKey::new(&[2]);
        key.pin = Some("1234".into());
        answer_with(&["1234"]);
        let enrolled = enrol_on(&mut key, &challenge()).unwrap();
        let first = enrolled.unlock.as_ref().unwrap().wrap_key;

        answer_with(&["1234"]);
        key.assertions = 0;
        let opens = move |_: &[u8], secret: &[u8; 32]| *secret == first;
        let opened = unlock_on(
            &mut key,
            std::slice::from_ref(&enrolled.credential.credential_id),
            VAULT,
            Some(&opens),
        )
        .unwrap();
        assert_eq!(opened.wrap_key, first);
        assert!(opened.unverified_wrap_key.is_none());
        assert_eq!(
            key.assertions, 1,
            "no second assertion when the first opens"
        );

        // Without a way to check, the other secret is never asked for.
        answer_with(&["1234"]);
        key.assertions = 0;
        let opened = unlock_on(
            &mut key,
            std::slice::from_ref(&enrolled.credential.credential_id),
            VAULT,
            None,
        )
        .unwrap();
        assert!(opened.unverified_wrap_key.is_none());
        assert_eq!(key.assertions, 1);
    }

    #[test]
    fn a_key_with_a_pin_is_asked_and_a_wrong_one_asked_again() {
        let _turn = PROMPT.lock().unwrap_or_else(|e| e.into_inner());
        let mut key = SoftKey::new(&[2]);
        key.pin = Some("1234".into());
        answer_with(&["1234"]);
        let enrolled = enrol_on(&mut key, &challenge()).unwrap();
        let first = enrolled.unlock.as_ref().unwrap().wrap_key;

        let asked = answer_with(&["0000", "1234"]);
        let again = unlock_on(
            &mut key,
            std::slice::from_ref(&enrolled.credential.credential_id),
            VAULT,
            Some(&|_: &[u8], _: &[u8; 32]| false),
        )
        .unwrap();
        assert_eq!(again.wrap_key, first, "the verified secret both times");
        assert!(again.verified);
        let asked = asked.lock().unwrap();
        assert!(matches!(asked[0], PinAsk::Enter { .. }));
        assert!(matches!(asked[1], PinAsk::Wrong { .. }));
    }

    #[test]
    fn a_key_that_will_not_give_the_other_secret_still_unlocks() {
        let _turn = PROMPT.lock().unwrap_or_else(|e| e.into_inner());
        let mut key = SoftKey::new(&[2]);
        key.pin = Some("1234".into());
        key.always_uv = true;
        answer_with(&["1234"]);
        let enrolled = enrol_on(&mut key, &challenge()).unwrap();
        let first = enrolled.unlock.as_ref().unwrap().wrap_key;

        answer_with(&["1234"]);
        let opened = unlock_on(
            &mut key,
            std::slice::from_ref(&enrolled.credential.credential_id),
            VAULT,
            Some(&|_: &[u8], _: &[u8; 32]| false),
        )
        .unwrap();
        assert_eq!(opened.wrap_key, first);
        assert!(opened.verified);
        assert!(
            opened.unverified_wrap_key.is_none(),
            "the refusal is swallowed"
        );
    }

    #[test]
    fn a_cancelled_pin_is_a_cancel() {
        let _turn = PROMPT.lock().unwrap_or_else(|e| e.into_inner());
        let mut key = SoftKey::new(&[2]);
        key.pin = Some("1234".into());
        answer_with(&[]);
        assert!(matches!(
            enrol_on(&mut key, &challenge()),
            Err(FidoError::Cancelled)
        ));
    }

    #[test]
    fn a_u2f_only_key_is_told_what_kind_of_key_works() {
        let _turn = PROMPT.lock().unwrap_or_else(|e| e.into_inner());
        let asked = answer_with(&[]);
        let mut key = Hid::new(RefusingHid::new(0x01));
        let Err(FidoError::EnrollmentFailed(why)) = enrol_on(&mut key, &challenge()) else {
            panic!("a U2F-only key was enrolled");
        };
        assert!(why.contains("err.key_unsupported"), "{why}");
        let Err(FidoError::UnlockFailed(why)) = unlock_on(&mut key, &[vec![1; 16]], VAULT, None)
        else {
            panic!("a U2F-only key unlocked");
        };
        assert!(why.contains("err.key_unsupported"), "{why}");
        assert!(asked.lock().unwrap().is_empty());
    }

    #[test]
    fn the_wrap_key_is_the_one_android_derives() {
        let _turn = PROMPT.lock().unwrap_or_else(|e| e.into_inner());
        let mut key = SoftKey::new(&[1, 2]);
        key.pin = Some("1234".into());
        answer_with(&["1234"]);
        let enrolled = enrol_on(&mut key, &challenge()).unwrap();
        let id = enrolled.credential.credential_id.clone();
        // What the phone does: the PIN given, the raw salt taken.
        let phone =
            super::super::unlock_candidates(&mut key, &[id], VAULT, Some("1234"), true).unwrap();
        let (_, raw) = phone
            .wrap_keys
            .iter()
            .find(|(s, _)| *s == SaltShape::Raw)
            .unwrap();
        assert_eq!(**raw, enrolled.unlock.as_ref().unwrap().wrap_key);
    }
}
