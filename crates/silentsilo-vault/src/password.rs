//! An unlock password the user chose, synced like a key.
//!
//! Its envelope is published to storage, which the threat model does not
//! trust, so anyone who copies it can guess offline, without limit and
//! without the user knowing. The only defences are what one guess costs
//! (Argon2id at 256 MiB) and how many guesses a password needs, which is why
//! [`seal_under_password`] refuses anything under [`REFUSED_BELOW_LOG10`]
//! and asks for the user's confirmation under [`WARNED_BELOW_LOG10`]. A
//! security key is stronger, and the apps say so.
//!
//! The envelope opens the vault key with the same rights as a key. It lives
//! at the root of storage, outside `keys/`, because every release up to 1.6
//! adopts anything under `keys/` that parses as a key, and none of them
//! lists the root. See `FORMATS.md`, "The unlock password envelope".

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::dek_store::{unwrap_dek_hex, wrap_dek_bytes};
use crate::error::VaultError;
use crate::kdf::KdfParams;
use silentsilo_crypto::{ContentKek, MasterDek};

const PASSWORD_FILE: &str = "keys/unlock-password.json";

/// Separates the tag keys from every other use of the KEK and the vault key,
/// and from the recovery envelope's tags.
const AUTH_CONTEXT: &str = "silentsilo unlock password auth v1";
const AUTH_DEK_CONTEXT: &str = "silentsilo unlock password auth dek v1";

/// Shape of the stored envelope. A reader that sees a higher number says to
/// update instead of guessing; the KDF parameters move without a bump.
pub const PASSWORD_ENVELOPE_VERSION: u32 = 1;

/// The most an envelope from storage may weigh. A real one is under 1 KiB.
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;

/// Under 10^10 estimated guesses a password is refused: copied out of a
/// storage leak, it costs an attacker a few thousand dollars or less, cheap
/// enough to break in bulk.
pub const REFUSED_BELOW_LOG10: f64 = 10.0;

/// Under 10^14 it is accepted only after the user confirms a warning that
/// says what breaking it costs. Above, it is accepted without one.
pub const WARNED_BELOW_LOG10: f64 = 14.0;

/// Longest password accepted, in characters.
const MAX_PASSWORD_CHARS: usize = 1024;

/// zxcvbn's work grows with the input; past this many characters the rest
/// only adds strength, so the estimate reads the start.
const MAX_ESTIMATED_CHARS: usize = 128;

/// What the user typed, against the floor and the warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordStrength {
    /// Under [`REFUSED_BELOW_LOG10`]: never sealed.
    Refused,
    /// Under [`WARNED_BELOW_LOG10`]: sealed only after the warning.
    Weak,
    /// Sealed without a warning.
    Strong,
}

/// The estimate, for the strength meter. `warning` and `suggestions` are
/// zxcvbn's own codes (`StraightRowsOfKeysAreEasyToGuess`), for the apps to
/// translate.
#[derive(Debug, Clone, Serialize)]
pub struct PasswordAssessment {
    pub strength: PasswordStrength,
    pub guesses_log10: f64,
    pub warning: Option<String>,
    pub suggestions: Vec<String>,
}

/// The envelope as stored, locally and at the root of storage.
#[derive(Clone, Serialize, Deserialize)]
pub struct PasswordEnvelope {
    pub version: u32,
    /// Random, so a removal marker names exactly this envelope.
    pub id: String,
    pub kdf: KdfParams,
    pub salt: String,
    pub wrapped_dek: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Tag over every field above, keyed by the content KEK: a device of
    /// this silo wrote it. The KEK never rotates, so this alone tells an
    /// envelope a rotation left behind from one somebody planted.
    pub auth: String,
    /// The same tag keyed by the vault key as well: a device on the current
    /// key wrote it. Only this one makes an envelope worth adopting.
    pub auth_dek: String,
}

/// The version, id, parameters and date. Never the salt or the wrapped key:
/// together they are what a guess is tested against.
impl std::fmt::Debug for PasswordEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordEnvelope")
            .field("version", &self.version)
            .field("id", &self.id)
            .field("kdf", &self.kdf)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

impl PasswordEnvelope {
    /// The bytes the tags cover, length-prefixed so no two envelopes make
    /// the same message by moving a character across a boundary.
    fn auth_message(&self, context: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(context.as_bytes());
        out.push(0);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.kdf.m_cost.to_be_bytes());
        out.extend_from_slice(&self.kdf.t_cost.to_be_bytes());
        out.extend_from_slice(&self.kdf.p_cost.to_be_bytes());
        out.extend_from_slice(&self.created_at.to_be_bytes());
        for field in [
            self.id.as_str(),
            self.kdf.algorithm.as_str(),
            self.salt.as_str(),
            self.wrapped_dek.as_str(),
        ] {
            out.extend_from_slice(&(field.len() as u64).to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out
    }

    fn tag(&self, kek: &ContentKek) -> blake3::Hash {
        let key = zeroize::Zeroizing::new(blake3::derive_key(AUTH_CONTEXT, kek.as_bytes()));
        blake3::keyed_hash(&key, &self.auth_message(AUTH_CONTEXT))
    }

    fn tag_with_dek(&self, kek: &ContentKek, dek: &MasterDek) -> blake3::Hash {
        let mut material = zeroize::Zeroizing::new([0u8; 64]);
        material[..32].copy_from_slice(kek.as_bytes());
        material[32..].copy_from_slice(dek.as_bytes());
        let key = zeroize::Zeroizing::new(blake3::derive_key(AUTH_DEK_CONTEXT, material.as_ref()));
        blake3::keyed_hash(&key, &self.auth_message(AUTH_DEK_CONTEXT))
    }

    /// Stamps both tags.
    pub fn authenticate(&mut self, kek: &ContentKek, dek: &MasterDek) {
        self.auth = self.tag(kek).to_hex().to_string();
        self.auth_dek = self.tag_with_dek(kek, dek).to_hex().to_string();
    }

    /// Dates the envelope at `earliest` or later and stamps it again, so one
    /// made on a device whose clock is behind is still the newer one.
    pub fn date_after(&mut self, earliest: i64, kek: &ContentKek, dek: &MasterDek) {
        if self.created_at < earliest {
            self.created_at = earliest;
            self.authenticate(kek, dek);
        }
    }

    /// A device on this silo wrote it, under any vault key it ever had.
    pub fn is_authentic(&self, kek: &ContentKek) -> bool {
        blake3::Hash::from_hex(&self.auth).is_ok_and(|stored| self.tag(kek) == stored)
    }

    /// A device on the current vault key wrote it.
    pub fn is_authentic_now(&self, kek: &ContentKek, dek: &MasterDek) -> bool {
        blake3::Hash::from_hex(&self.auth_dek)
            .is_ok_and(|stored| self.tag_with_dek(kek, dek) == stored)
    }
}

/// Reads an envelope fetched from storage: bounded in size, and a version
/// this build does not know is refused with "update" rather than guessed at.
pub fn parse_password_envelope(bytes: &[u8]) -> Result<PasswordEnvelope, VaultError> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(VaultError::Corrupted(format!(
            "unlock password envelope of {} bytes is larger than any SilentSilo writes",
            bytes.len()
        )));
    }
    let envelope: PasswordEnvelope =
        serde_json::from_slice(bytes).map_err(|e| VaultError::Corrupted(e.to_string()))?;
    check_version(&envelope)?;
    Ok(envelope)
}

fn check_version(envelope: &PasswordEnvelope) -> Result<(), VaultError> {
    if envelope.version > PASSWORD_ENVELOPE_VERSION {
        return Err(VaultError::Corrupted(format!(
            "unlock password envelope version {} needs a newer SilentSilo",
            envelope.version
        )));
    }
    Ok(())
}

/// The password as the KDF sees it: NFC, so the same password typed on a
/// Mac (which tends to NFD) and on Windows derives the same key. Nothing is
/// trimmed: a space is part of what was typed.
fn normalized(password: &str) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(password.nfc().collect())
}

/// Refuses what is never sealed, whatever its strength: empty, too long,
/// space at either end (almost always a paste or a typo nobody can see),
/// or a control character.
pub fn check_password_shape(password: &str) -> Result<(), VaultError> {
    let chars = password.chars().count();
    if chars == 0
        || chars > MAX_PASSWORD_CHARS
        || password.starts_with(char::is_whitespace)
        || password.ends_with(char::is_whitespace)
        || password.chars().any(char::is_control)
    {
        return Err(VaultError::PasswordMalformed);
    }
    Ok(())
}

/// Estimates how many guesses `password` needs. `user_inputs` are words an
/// attacker would try first for this silo: its name, the device name, key
/// labels. "silentsilo" is always among them.
pub fn assess_password(password: &str, user_inputs: &[&str]) -> PasswordAssessment {
    let password = normalized(password);
    let estimated: String = password.chars().take(MAX_ESTIMATED_CHARS).collect();
    let estimated = zeroize::Zeroizing::new(estimated);
    // Each input whole, without its spaces, and word by word: "Familia
    // Popescu" is typed as "FamiliaPopescu" as often as not.
    let mut owned: Vec<String> = vec!["silentsilo".into()];
    for input in user_inputs {
        let lower = input.to_lowercase();
        owned.push(lower.split_whitespace().collect());
        owned.extend(
            lower
                .split(|c: char| !c.is_alphanumeric())
                .filter(|w| w.chars().count() >= 3)
                .map(str::to_string),
        );
        owned.push(lower);
    }
    owned.retain(|s| !s.is_empty());
    owned.sort();
    owned.dedup();
    let inputs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let entropy = zxcvbn::zxcvbn(&estimated, &inputs);
    let guesses_log10 = entropy.guesses_log10();
    let strength = if guesses_log10 < REFUSED_BELOW_LOG10 {
        PasswordStrength::Refused
    } else if guesses_log10 < WARNED_BELOW_LOG10 {
        PasswordStrength::Weak
    } else {
        PasswordStrength::Strong
    };
    let (warning, suggestions) = match entropy.feedback() {
        Some(feedback) => (
            feedback.warning().map(|w| format!("{w:?}")),
            feedback
                .suggestions()
                .iter()
                .map(|s| format!("{s:?}"))
                .collect(),
        ),
        None => (None, Vec::new()),
    };
    PasswordAssessment {
        strength,
        guesses_log10,
        warning,
        suggestions,
    }
}

/// Wraps the vault key under `password`.
///
/// The floor is enforced here, not only in the apps, so no client can seal a
/// password under it. `confirmed_weak` is the user's answer to the warning a
/// [`PasswordStrength::Weak`] password shows.
pub fn seal_under_password(
    dek: &MasterDek,
    kek: &ContentKek,
    password: &str,
    user_inputs: &[&str],
    confirmed_weak: bool,
) -> Result<PasswordEnvelope, VaultError> {
    check_password_shape(password)?;
    match assess_password(password, user_inputs).strength {
        PasswordStrength::Refused => return Err(VaultError::PasswordTooWeak),
        PasswordStrength::Weak if !confirmed_weak => {
            return Err(VaultError::PasswordWeakNotConfirmed);
        }
        _ => {}
    }
    seal_with(dek, kek, password, KdfParams::unlock_password())
}

fn seal_with(
    dek: &MasterDek,
    kek: &ContentKek,
    password: &str,
    kdf: KdfParams,
) -> Result<PasswordEnvelope, VaultError> {
    let salt: [u8; 16] = rand::random();
    let password = normalized(password);
    let key = zeroize::Zeroizing::new(kdf.derive(password.as_bytes(), &salt)?);
    let wrapped = wrap_dek_bytes(dek, &key)?;
    let mut envelope = PasswordEnvelope {
        version: PASSWORD_ENVELOPE_VERSION,
        id: uuid::Uuid::new_v4().to_string(),
        kdf,
        salt: hex::encode(salt),
        wrapped_dek: hex::encode(wrapped),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        auth: String::new(),
        auth_dek: String::new(),
    };
    envelope.authenticate(kek, dek);
    Ok(envelope)
}

/// Opens the vault key with what the user typed, with the envelope's own
/// parameters. No strength check here: a password sealed under an older
/// floor still opens.
pub fn unwrap_with_password(
    envelope: &PasswordEnvelope,
    password: &str,
) -> Result<MasterDek, VaultError> {
    check_version(envelope)?;
    let salt = hex::decode(&envelope.salt).map_err(|_| VaultError::InvalidCredentials)?;
    let password = normalized(password);
    let key = zeroize::Zeroizing::new(envelope.kdf.derive(password.as_bytes(), &salt)?);
    unwrap_dek_hex(&envelope.wrapped_dek, &key)
}

pub fn password_path(vault_root: &Path) -> PathBuf {
    vault_root.join(PASSWORD_FILE)
}

pub fn has_unlock_password(vault_root: &Path) -> bool {
    password_path(vault_root).is_file()
}

pub fn save_password_envelope(
    vault_root: &Path,
    envelope: &PasswordEnvelope,
) -> Result<(), VaultError> {
    let json =
        serde_json::to_vec_pretty(envelope).map_err(|e| VaultError::Crypto(e.to_string()))?;
    crate::workdir::write_private(&password_path(vault_root), &json)?;
    Ok(())
}

pub fn load_password_envelope(vault_root: &Path) -> Result<PasswordEnvelope, VaultError> {
    let bytes = std::fs::read(password_path(vault_root))?;
    parse_password_envelope(&bytes)
}

pub fn clear_password_envelope(vault_root: &Path) {
    let _ = std::fs::remove_file(password_path(vault_root));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::ARGON2ID;
    use silentsilo_crypto::{generate_content_kek, generate_dek};

    /// Light parameters for the tests that are not about the KDF: 256 MiB in
    /// a debug build takes long enough to matter across a whole suite.
    fn light() -> KdfParams {
        KdfParams {
            algorithm: ARGON2ID.into(),
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    const STRONG: &str = "lantern-gravel-oxidize-tuba-sprinkle";

    fn sealed(dek: &MasterDek, kek: &ContentKek, password: &str) -> PasswordEnvelope {
        seal_with(dek, kek, password, light()).unwrap()
    }

    #[test]
    fn a_password_round_trips_the_dek() {
        let (dek, kek) = (generate_dek(), generate_content_kek());
        let envelope = sealed(&dek, &kek, STRONG);
        let opened = unwrap_with_password(&envelope, STRONG).unwrap();
        assert_eq!(opened.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn a_wrong_password_is_refused_rather_than_returning_junk() {
        let (dek, kek) = (generate_dek(), generate_content_kek());
        let envelope = sealed(&dek, &kek, STRONG);
        for wrong in [
            "lantern-gravel-oxidize-tuba-sprinkl",
            "Lantern-gravel-oxidize-tuba-sprinkle",
            "",
        ] {
            assert!(unwrap_with_password(&envelope, wrong).is_err(), "{wrong:?}");
        }
        // A trailing space is part of what was typed, not trimmed away.
        assert!(unwrap_with_password(&envelope, &format!("{STRONG} ")).is_err());
    }

    #[test]
    fn the_same_password_in_nfc_and_nfd_opens_the_same_envelope() {
        // "Ştiinţă și café", composed on Windows, decomposed on a Mac.
        let composed = "\u{15e}tiin\u{163}\u{103} \u{219}i caf\u{e9} lantern gravel tuba";
        let decomposed: String = composed.nfd().collect();
        assert_ne!(composed, decomposed);
        let (dek, kek) = (generate_dek(), generate_content_kek());
        let envelope = sealed(&dek, &kek, composed);
        let opened = unwrap_with_password(&envelope, &decomposed).unwrap();
        assert_eq!(opened.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn one_password_does_not_open_another_silo() {
        let kek = generate_content_kek();
        let mine = sealed(&generate_dek(), &kek, STRONG);
        let theirs_dek = generate_dek();
        let theirs = sealed(&theirs_dek, &generate_content_kek(), STRONG);
        // Same password, different salt and DEK: nothing crosses over.
        assert_ne!(mine.salt, theirs.salt);
        let opened = unwrap_with_password(&theirs, STRONG).unwrap();
        assert_eq!(opened.as_bytes(), theirs_dek.as_bytes());
        assert!(!theirs.is_authentic(&kek));
    }

    #[test]
    fn trivial_and_leaked_passwords_are_refused() {
        for password in ["123456", "password", "qwerty123", "Password1!", "iloveyou"] {
            assert_eq!(
                assess_password(password, &[]).strength,
                PasswordStrength::Refused,
                "{password}"
            );
            let err = seal_under_password(
                &generate_dek(),
                &generate_content_kek(),
                password,
                &[],
                true,
            )
            .map(|_| ())
            .unwrap_err();
            assert!(
                matches!(err, VaultError::PasswordTooWeak),
                "{password}: {err:?}"
            );
        }
    }

    #[test]
    fn a_password_made_of_the_silos_own_name_is_refused() {
        let inputs = ["Familia Popescu", "Laptop Ana"];
        assert_eq!(
            assess_password("FamiliaPopescu", &inputs).strength,
            PasswordStrength::Refused
        );
        assert_eq!(
            assess_password("silentsilo2026", &[]).strength,
            PasswordStrength::Refused
        );
    }

    #[test]
    fn a_typical_mixed_password_is_weak_and_needs_the_warning() {
        let password = "Tq8#vLm2!xZp";
        assert_eq!(
            assess_password(password, &[]).strength,
            PasswordStrength::Weak
        );
        let err = seal_under_password(
            &generate_dek(),
            &generate_content_kek(),
            password,
            &[],
            false,
        )
        .map(|_| ())
        .unwrap_err();
        assert!(
            matches!(err, VaultError::PasswordWeakNotConfirmed),
            "{err:?}"
        );
    }

    #[test]
    fn generated_phrases_and_long_random_passwords_are_strong() {
        for password in [
            STRONG,
            "k7#Vq2!mZp9@wR4x",
            "correct-orbit-plaza-humid-saddle-quote",
        ] {
            let assessment = assess_password(password, &[]);
            assert_eq!(
                assessment.strength,
                PasswordStrength::Strong,
                "{password}: {assessment:?}"
            );
        }
    }

    #[test]
    fn malformed_passwords_are_refused_whatever_their_strength() {
        let long = "x".repeat(MAX_PASSWORD_CHARS + 1);
        for password in [
            "",
            " lantern-gravel-oxidize-tuba-sprinkle",
            "lantern-gravel-oxidize-tuba-sprinkle ",
            "lantern-gravel\noxidize-tuba-sprinkle",
            "lantern-gravel\u{7}oxidize-tuba-sprinkle",
            long.as_str(),
        ] {
            let err = seal_under_password(
                &generate_dek(),
                &generate_content_kek(),
                password,
                &[],
                true,
            )
            .map(|_| ())
            .unwrap_err();
            assert!(
                matches!(err, VaultError::PasswordMalformed),
                "{password:?}: {err:?}"
            );
        }
        assert!(check_password_shape("inner spaces are fine here").is_ok());
    }

    #[test]
    fn a_very_long_password_is_estimated_quickly_and_still_accepted() {
        let password = format!("{STRONG}-{}", "abcdefgh".repeat(100));
        let start = std::time::Instant::now();
        let assessment = assess_password(&password, &[]);
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(assessment.strength, PasswordStrength::Strong);
    }

    #[test]
    fn every_field_is_covered_by_both_tags() {
        let (dek, kek) = (generate_dek(), generate_content_kek());
        let envelope = sealed(&dek, &kek, STRONG);
        let other = sealed(&dek, &kek, STRONG);
        assert!(envelope.is_authentic(&kek));
        assert!(envelope.is_authentic_now(&kek, &dek));

        let mut changes: Vec<(&str, PasswordEnvelope)> = Vec::new();
        let mut e = envelope.clone();
        e.version += 1;
        changes.push(("version", e));
        let mut e = envelope.clone();
        e.id = other.id.clone();
        changes.push(("id", e));
        let mut e = envelope.clone();
        e.kdf.m_cost += 1;
        changes.push(("kdf", e));
        let mut e = envelope.clone();
        e.kdf.algorithm = "argon2i".into();
        changes.push(("algorithm", e));
        let mut e = envelope.clone();
        e.salt = other.salt.clone();
        changes.push(("salt", e));
        let mut e = envelope.clone();
        e.wrapped_dek = other.wrapped_dek.clone();
        changes.push(("wrapped_dek", e));
        let mut e = envelope.clone();
        e.created_at += 86_400;
        changes.push(("created_at", e));

        for (field, changed) in changes {
            assert!(
                !changed.is_authentic(&kek),
                "{field} is not covered by auth"
            );
            assert!(
                !changed.is_authentic_now(&kek, &dek),
                "{field} is not covered by auth_dek"
            );
        }
    }

    #[test]
    fn after_a_rotation_the_envelope_is_ours_but_no_longer_current() {
        // What a client tells from an envelope an older release left under
        // the old vault key: the KEK tag still holds, the vault key tag not.
        let (dek, kek) = (generate_dek(), generate_content_kek());
        let envelope = sealed(&dek, &kek, STRONG);
        let rotated = generate_dek();
        assert!(envelope.is_authentic(&kek));
        assert!(!envelope.is_authentic_now(&kek, &rotated));
    }

    #[test]
    fn the_recovery_tags_never_verify_a_password_envelope() {
        // Different contexts: a value made for one is never one for the other.
        assert_ne!(AUTH_CONTEXT, "silentsilo recovery envelope auth v1");
        assert_ne!(AUTH_DEK_CONTEXT, "silentsilo recovery envelope auth v2");
    }

    #[test]
    fn junk_tags_are_refused_rather_than_panicking() {
        let (dek, kek) = (generate_dek(), generate_content_kek());
        let mut envelope = sealed(&dek, &kek, STRONG);
        for junk in ["", "zz", "not hex", &"aa".repeat(31)] {
            envelope.auth = junk.into();
            envelope.auth_dek = junk.into();
            assert!(!envelope.is_authentic(&kek));
            assert!(!envelope.is_authentic_now(&kek, &dek));
        }
    }

    #[test]
    fn a_later_date_is_stamped_again_and_never_moves_back() {
        let (dek, kek) = (generate_dek(), generate_content_kek());
        let mut envelope = sealed(&dek, &kek, STRONG);
        let later = envelope.created_at + 86_400;
        envelope.date_after(later, &kek, &dek);
        assert_eq!(envelope.created_at, later);
        assert!(envelope.is_authentic_now(&kek, &dek));
        envelope.date_after(later - 10, &kek, &dek);
        assert_eq!(envelope.created_at, later);
    }

    #[test]
    fn a_future_or_oversized_or_unknown_envelope_is_refused() {
        let (dek, kek) = (generate_dek(), generate_content_kek());
        let envelope = sealed(&dek, &kek, STRONG);

        let mut future = envelope.clone();
        future.version = PASSWORD_ENVELOPE_VERSION + 1;
        let err = unwrap_with_password(&future, STRONG)
            .map(|_| ())
            .unwrap_err();
        assert!(
            matches!(&err, VaultError::Corrupted(m) if m.contains("newer")),
            "{err:?}"
        );
        let bytes = serde_json::to_vec(&future).unwrap();
        assert!(
            matches!(parse_password_envelope(&bytes), Err(VaultError::Corrupted(m)) if m.contains("newer"))
        );

        let mut scrypt = envelope.clone();
        scrypt.kdf.algorithm = "scrypt".into();
        let err = unwrap_with_password(&scrypt, STRONG)
            .map(|_| ())
            .unwrap_err();
        assert!(
            matches!(&err, VaultError::Corrupted(m) if m.contains("newer")),
            "{err:?}"
        );

        let mut hostile = envelope.clone();
        hostile.kdf.m_cost = u32::MAX;
        assert!(unwrap_with_password(&hostile, STRONG).is_err());

        let huge = vec![b' '; MAX_ENVELOPE_BYTES + 1];
        assert!(parse_password_envelope(&huge).is_err());
        for junk in [&b""[..], b"{}", b"null", b"[1,2]", b"{\"version\":1}"] {
            assert!(parse_password_envelope(junk).is_err(), "{junk:?}");
        }
    }

    #[test]
    fn fields_a_later_release_adds_are_ignored() {
        let (dek, kek) = (generate_dek(), generate_content_kek());
        let envelope = sealed(&dek, &kek, STRONG);
        let mut value = serde_json::to_value(&envelope).unwrap();
        value["hint"] = serde_json::json!("something new");
        let parsed = parse_password_envelope(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            unwrap_with_password(&parsed, STRONG).unwrap().as_bytes(),
            dek.as_bytes()
        );
    }

    #[test]
    fn an_envelope_survives_a_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let (dek, kek) = (generate_dek(), generate_content_kek());
        let envelope = sealed(&dek, &kek, STRONG);
        assert!(!has_unlock_password(dir.path()));
        save_password_envelope(dir.path(), &envelope).unwrap();
        assert!(has_unlock_password(dir.path()));
        let loaded = load_password_envelope(dir.path()).unwrap();
        assert!(loaded.is_authentic_now(&kek, &dek));
        assert_eq!(
            unwrap_with_password(&loaded, STRONG).unwrap().as_bytes(),
            dek.as_bytes()
        );
        clear_password_envelope(dir.path());
        assert!(!has_unlock_password(dir.path()));
    }

    #[test]
    fn debug_never_shows_what_a_guess_is_tested_against() {
        let (dek, kek) = (generate_dek(), generate_content_kek());
        let envelope = sealed(&dek, &kek, STRONG);
        let shown = format!("{envelope:?}");
        assert!(!shown.contains(&envelope.salt), "{shown}");
        assert!(!shown.contains(&envelope.wrapped_dek), "{shown}");
    }

    #[test]
    fn the_real_parameters_are_the_heaviest_every_reader_accepts() {
        // 256 MiB is the ceiling `KdfParams::derive` enforces on read in every
        // release since 1.10: a heavier envelope would read as broken there.
        let kdf = KdfParams::unlock_password();
        assert_eq!(
            (kdf.algorithm.as_str(), kdf.m_cost, kdf.t_cost, kdf.p_cost),
            ("argon2id", 262_144, 3, 1)
        );
        assert!(kdf.derive(b"x", &[1u8; 16]).is_ok());
    }

    #[test]
    fn seal_under_password_uses_the_real_parameters() {
        let (dek, kek) = (generate_dek(), generate_content_kek());
        let envelope = seal_under_password(&dek, &kek, STRONG, &[], false).unwrap();
        assert_eq!(envelope.kdf, KdfParams::unlock_password());
        assert_eq!(envelope.version, PASSWORD_ENVELOPE_VERSION);
        assert!(uuid::Uuid::parse_str(&envelope.id).is_ok());
        assert_eq!(
            unwrap_with_password(&envelope, STRONG).unwrap().as_bytes(),
            dek.as_bytes()
        );
    }

    #[test]
    fn the_thresholds_are_the_ones_decided() {
        assert_eq!(REFUSED_BELOW_LOG10, 10.0);
        assert_eq!(WARNED_BELOW_LOG10, 14.0);
        assert_eq!(PASSWORD_ENVELOPE_VERSION, 1);
        assert_eq!(AUTH_CONTEXT, "silentsilo unlock password auth v1");
        assert_eq!(AUTH_DEK_CONTEXT, "silentsilo unlock password auth dek v1");
        assert_eq!(PASSWORD_FILE, "keys/unlock-password.json");
    }
}
