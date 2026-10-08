//! A security key's ceremonies with its PIN, over any link: make a
//! credential and derive the wrap key, or derive it to unlock. A key with a
//! PIN is always asked for it, as Windows does, since `hmac-secret` gives
//! another secret without it. Used by the desktop's USB backend on Linux
//! and macOS; kept here, apart from the transport, so it is tested
//! everywhere.

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
        unlock: Some(raw_material(found)?),
    })
}

pub(crate) fn unlock_on(
    dev: &mut dyn Ctap,
    credential_ids: &[Vec<u8>],
    vault_id: &str,
) -> Result<UnlockMaterial, FidoError> {
    let (found, _) = with_pin(dev, FidoError::UnlockFailed, |dev, pin| {
        super::unlock_candidates(dev, credential_ids, vault_id, pin, true)
    })?;
    raw_material(found)
}

/// The wrap key every platform derives: the raw salt, verified exactly when
/// the key has a PIN.
fn raw_material(found: super::UnlockCandidates) -> Result<UnlockMaterial, FidoError> {
    let (_, key) = found
        .wrap_keys
        .iter()
        .find(|(shape, _)| *shape == SaltShape::Raw)
        .ok_or_else(|| FidoError::UnlockFailed("the key gave no hmac-secret output".into()))?;
    Ok(UnlockMaterial {
        wrap_key: **key,
        credential_id: found.credential_id,
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
            "Too many wrong PINs in a row. Unplug the key, plug it in again and try again."
        )
        .into(),
        CtapError::PinBlocked => "This key's PIN is blocked. Only resetting the key clears it, \
                                  and a reset erases everything on it."
            .into(),
        CtapError::PinNotSet => crate::coded!(
            "err.key_needs_pin",
            "This key needs a PIN set before it can be used. Set one with its maker's tool."
        )
        .into(),
        CtapError::Timeout => {
            crate::coded!("err.key_no_touch", "No touch was received in time.").into()
        }
        CtapError::Unsupported(why) => format!("This key cannot open a silo: {why}."),
        other => other.to_string(),
    };
    fail(said)
}

#[cfg(test)]
mod tests {
    use super::super::RP_ID;
    use super::super::soft_key::SoftKey;
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
    fn a_key_without_a_pin_enrols_and_unlocks_without_asking() {
        let _turn = PROMPT.lock().unwrap_or_else(|e| e.into_inner());
        let asked = answer_with(&[]);
        let mut key = SoftKey::new(&[2]);
        let enrolled = enrol_on(&mut key, &challenge()).unwrap();
        let first = enrolled.unlock.as_ref().unwrap().wrap_key;
        let again = unlock_on(
            &mut key,
            std::slice::from_ref(&enrolled.credential.credential_id),
            VAULT,
        )
        .unwrap();
        assert_eq!(again.wrap_key, first);
        assert!(asked.lock().unwrap().is_empty());
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
        )
        .unwrap();
        assert_eq!(again.wrap_key, first, "the verified secret both times");
        let asked = asked.lock().unwrap();
        assert!(matches!(asked[0], PinAsk::Enter { .. }));
        assert!(matches!(asked[1], PinAsk::Wrong { .. }));
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
