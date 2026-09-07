//! The Secure Enclave itself, through Security.framework. Everything that
//! is not an Apple call, the agreement and the derivation, is in
//! `crate::enclave` and is tested on every platform; this file only makes
//! the chip do its half.
//!
//! The enclave key is a P-256 pair whose private half never leaves the
//! chip. It is created with `kSecAccessControlBiometryCurrentSet`, so any
//! use of it puts up the Touch ID sheet, and adding or removing a
//! fingerprint invalidates it for good, which is what "sealed to this
//! machine" should mean. `kSecAccessControlPrivateKeyUsage` is what an
//! enclave key needs to be allowed to use the private half at all.
//!
//! Keys are filed in the data-protection keychain under a label made from
//! the credential id's tag, and found again by that label at unlock. A
//! search by label returns a reference and does not touch the private
//! half, so looking for a key that belongs to another Mac's enrolment
//! costs nothing and prompts for nothing.

// Only `mac.rs` calls into here, and it needs `hardware` for the CTAP half.
// Building `enclave` alone is how this file is type-checked for macOS from a
// machine that cannot compile the HID stack, and in that build nothing
// calls it.
#![cfg_attr(not(feature = "hardware"), allow(dead_code))]

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::{CFError, CFErrorRef};
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use objc2_local_authentication::{LAContext, LAPolicy};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage,
};
use security_framework_sys::item::{
    kSecAttrKeyClass, kSecAttrKeyClassPublic, kSecAttrKeySizeInBits, kSecAttrKeyType,
    kSecAttrKeyTypeECSECPrimeRandom,
};
use security_framework_sys::key::SecKeyCreateWithData;
use zeroize::Zeroizing;

use crate::FidoError;
use crate::enclave::{self, EnrolMaterial, TAG_LEN};
use crate::types::UnlockMaterial;

/// The keychain label an enrolment's key is filed under, tag in hex. What
/// Keychain Access shows, so it says what it is.
fn label_for(tag: &[u8]) -> String {
    format!("SilentSilo Touch ID {}", hex::encode(tag))
}

/// Whether Touch ID can answer right now: a sensor exists, has fingerprints
/// enrolled and is not locked out. A Mac mini with no Touch ID keyboard
/// answers no, and so does a MacBook with the lid closed on an external
/// display, which is why this is asked at ceremony time and not cached.
pub fn available() -> bool {
    // SAFETY: LAContext has no preconditions; the policy is a documented
    // constant and the result is read once.
    unsafe {
        LAContext::new()
            .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
            .is_ok()
    }
}

/// Generates a key in the enclave and enrols it for `vault_id`. One
/// ceremony: the enclave signs nothing at enrolment, so no Touch ID prompt
/// appears here. The first prompt is the first unlock.
pub fn enrol(vault_id: &str) -> Result<EnrolMaterial, FidoError> {
    let tag = enclave::random_tag();
    let key = generate(&tag)?;
    let public = key
        .public_key()
        .and_then(|public| public.external_representation())
        .ok_or_else(|| {
            FidoError::EnrollmentFailed("the enclave did not return its public key".into())
        });
    let material = public.and_then(|public| enclave::enrol(public.bytes(), vault_id, &tag));
    if material.is_err() {
        // Nothing references this key; leaving it would only clutter the
        // keychain with a label no envelope names.
        let _ = key.delete();
    }
    material
}

fn generate(tag: &[u8; TAG_LEN]) -> Result<SecKey, FidoError> {
    // The protection class is passed rather than defaulted: with `None` the
    // wrapper picks `kSecAttrAccessibleWhenUnlocked`, which is eligible for
    // keychain migration to another Mac. The private half cannot leave the
    // chip either way, so nothing was extractable, but "sealed to this
    // machine" should be what the item says and not only what the hardware
    // enforces.
    let access = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        kSecAccessControlBiometryCurrentSet | kSecAccessControlPrivateKeyUsage,
    )
    .map_err(|e| FidoError::EnrollmentFailed(format!("Touch ID access control: {e}")))?;
    let mut options = GenerateKeyOptions::default();
    options
        .set_key_type(KeyType::ec_sec_prime_random())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave)
        .set_location(Location::DataProtectionKeychain)
        .set_label(label_for(tag))
        .set_access_control(access);
    SecKey::new(&options).map_err(|e| {
        FidoError::EnrollmentFailed(format!("the Secure Enclave refused to make a key: {e}"))
    })
}

/// Whether any of `credential_ids` names a key in this Mac's keychain.
/// Ids that are not enclave ids are skipped, not counted.
pub fn holds_any(credential_ids: &[Vec<u8>]) -> bool {
    credential_ids
        .iter()
        .filter_map(|id| enclave::split_credential_id(id))
        .any(|(tag, _)| find_key(tag).is_some())
}

/// Reproduces the wrap key for the first of `credential_ids` this Mac holds
/// the enclave key for. The Touch ID sheet appears inside the agreement.
///
/// A caveat the caller has to know: success here means the enclave performed
/// an agreement, not that the wrap key opens anything. The chip agrees with
/// any point on the curve, so an envelope whose stored point was altered
/// produces a Touch ID prompt that succeeds and a key that unwraps nothing.
/// Only the caller, holding the sealed DEK, can tell the two apart.
pub fn derive_unlock_material(
    credential_ids: &[Vec<u8>],
    vault_id: &str,
) -> Result<UnlockMaterial, FidoError> {
    let mut last_err = None;
    for credential_id in credential_ids {
        let Some((tag, point)) = enclave::split_credential_id(credential_id) else {
            continue;
        };
        let Some(key) = find_key(tag) else {
            continue; // Another Mac's enrolment on the same silo.
        };
        match agree(&key, point) {
            Ok(shared) => {
                let wrap_key = enclave::wrap_key_from_shared(&shared, vault_id);
                return Ok(UnlockMaterial {
                    wrap_key: *wrap_key,
                    credential_id: credential_id.clone(),
                });
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        FidoError::UnlockFailed("No Touch ID key for this silo on this Mac".into())
    }))
}

/// The private key filed under `tag`, if this Mac has it. A reference only:
/// nothing here touches the private half, so nothing prompts.
fn find_key(tag: &[u8]) -> Option<SecKey> {
    let results = ItemSearchOptions::new()
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(&label_for(tag))
        .ignore_legacy_keychains()
        .load_refs(true)
        .limit(1)
        .search()
        .ok()?;
    results.into_iter().find_map(|result| match result {
        SearchResult::Ref(Reference::Key(key)) => Some(key),
        _ => None,
    })
}

/// ECDH between the enclave key and the ephemeral point from the credential
/// id. The standard algorithm returns the raw x coordinate, thirty-two
/// bytes, and ignores the requested size; the KDF is ours, not Apple's, so
/// the derivation is the same one the pure-Rust tests exercise.
fn agree(key: &SecKey, ephemeral_point: &[u8]) -> Result<Zeroizing<Vec<u8>>, FidoError> {
    let peer = import_public(ephemeral_point)?;
    let shared = key
        .key_exchange(Algorithm::ECDHKeyExchangeStandard, &peer, 32, None)
        .map(Zeroizing::new)
        .map_err(|e| FidoError::UnlockFailed(format!("Touch ID: {e}")))?;
    if shared.len() != 32 {
        return Err(FidoError::UnlockFailed(
            "the Secure Enclave returned a shared secret of the wrong size".into(),
        ));
    }
    Ok(shared)
}

/// An uncompressed SEC1 point as a `SecKey`, which is the only form
/// `SecKeyCopyKeyExchangeResult` accepts a peer in. The wrapper crate has
/// no constructor for this, hence the one raw call in the file.
fn import_public(point: &[u8]) -> Result<SecKey, FidoError> {
    let data = CFData::from_buffer(point);
    // SAFETY: the `kSecAttr*` statics are exported by Security.framework for
    // the life of the process and are only borrowed here.
    let attributes = unsafe {
        CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyClass),
                CFString::wrap_under_get_rule(kSecAttrKeyClassPublic).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeySizeInBits),
                CFNumber::from(256).into_CFType(),
            ),
        ])
    };
    let mut error: CFErrorRef = std::ptr::null_mut();
    // SAFETY: both arguments are live Core Foundation objects for the
    // duration of the call, and `error` is a valid out-pointer.
    let raw = unsafe {
        SecKeyCreateWithData(
            data.as_concrete_TypeRef(),
            attributes.as_concrete_TypeRef(),
            &mut error,
        )
    };
    if raw.is_null() {
        let why = if error.is_null() {
            "not a P-256 point".to_string()
        } else {
            // SAFETY: a non-null error out-param is owned by the caller.
            unsafe { CFError::wrap_under_create_rule(error) }.to_string()
        };
        return Err(FidoError::UnlockFailed(format!(
            "the ephemeral key in the credential id was refused: {why}"
        )));
    }
    // SAFETY: a non-null return from a Create function is owned by us.
    Ok(unsafe { SecKey::wrap_under_create_rule(raw) })
}
