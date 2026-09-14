# Changelog

Notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The version follows
semver, and anything that could stop an existing silo from opening needs a
major version rather than a note.

This repository has its own version line, separate from the desktop
application's. A client pins a tag from here; the tag it pins is what its
release notes should say.

## [Unreleased]

### Added

- The sync pass in `silentsilo-app` imports the inbox: items a locked phone
  sent become ordinary files in the folder the item names, and leave the
  inbox a pass later, once their record has reached every target. Items from
  an unknown sender or a removed key stay and are reported in
  `SyncReport::inbox_refused`.
- `set_local_protector`, for sealing the local secret files where there is
  no DPAPI. Files written before it was set still read.
- `silentsilo_app::files::import_file`, adding a file from this device, moved
  from the desktop's import, and `decrypt_to_file`, for opening a file
  outside a preview.
- `inbox::send_item_from` and `encrypt_stream` in the crate root, for content
  read from a descriptor another app handed over rather than opened by path.

## [1.3.0] - The shared application crate

No existing format version changed, so the 1.0.0 fixtures still describe the
current era. The one new object, the revocation marker, is pinned by a byte
vector and skipped by 1.0.0, which a test runs. Desktop keeps pinning 1.2.0
until it moves onto `silentsilo-app`.

### Added

- `silentsilo-app`, the application logic the clients share, moving in from
  the desktop's command layer: the session map and closing a silo, the sync
  pass, joining and unlocking with the recovery code, device key enrolment
  and unlock, the storage settings types, and reading a file for a preview.
  Characterization tests pin each against folder targets.
- The sync pass keeps enrolled keys in step between devices: keys another
  device enrolled are added locally, and a revocation leaves a sealed marker
  under `keys/revoked/` that every other device honours instead of
  publishing the key again. A test runs 1.0.0's key listing over a store
  holding a marker.
- `silentsilo_vault::set_work_base`, for a phone app to keep working copies
  and fallback secrets in its private storage.

## [1.2.0] - Groundwork for the mobile builds

No existing format version changed, so the 1.0.0 fixtures still describe the
current era. The new objects (the inbox and the Android key kind) are pinned
by byte vectors, and a test runs the 1.0.0 vault and sync code against them.
Nothing here changes what a Windows or Linux client does at runtime.

### Added

- A third key kind, `android-keystore`, with derivation
  `keystore-aes-256-gcm-v1`: a wrap key encrypted under a Keystore AES key
  that allows one use per strong biometric. Usable on Android only; every
  other build carries it and skips it.
- `secure-enclave` keys are usable on iOS as well as macOS.
- The byte vectors hold an Android Keystore envelope, and
  `silentsilo-fixture` depends on the 1.0.0 vault to check that an installed
  client offers only its FIDO2 keys and keeps every other key intact through
  a load and save of `keys/fido.json`.

- The inbox: a device that cannot open the silo seals content to the silo's
  inbox key and signs it, and an unlocked device imports it as an ordinary
  file. New objects under `inbox/`, described in `FORMATS.md` with byte
  vectors. Nothing new reaches `ops/` or `blobs/`, and a test runs 1.0.0's
  sweep and key rotation over a store holding items.
- `ObjectStore::copy`: S3 CopyObject, WebDAV COPY and a local copy for
  folders; SFTP and servers without COPY go through a temporary file.

### Changed

- `public_key` in a `secure-enclave` envelope is the enclave key's point, not
  a copy of the ephemeral point already in the credential id. No released
  client wrote the old form.

### Fixed

A review of what 1.1.0 added found three ways the macOS unlock could refuse
a silo it should have opened.

- Unlock falls through to an enrolled security key when Touch ID cannot
  answer, instead of stopping at the enclave. Biometry has more ways to be
  unavailable than a security key does: the lid is closed on an external
  display, biometry is locked out after five failed attempts, or the user
  added a fingerprint and invalidated the enclave key for good. Each of
  those was a lockout with a working key plugged in.
- Whether biometry can answer is now asked at unlock, not assumed from
  enrolment.
- A `secure-enclave` envelope whose credential id is not readable is no
  longer counted as usable. It reached the hex decode that builds the
  allow-list, which fails as a whole, so one damaged entry took down every
  other key on the silo. Only macOS was exposed, because only there is the
  kind usable at all.
- The enclave key is created with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`
  rather than the wrapper's default of `kSecAttrAccessibleWhenUnlocked`. The
  private half could not leave the chip either way, but the keychain item
  now says what the hardware already enforced.

### Documentation

- `docs/ARCHITECTURE.md` shows the second branch that wraps the DEK, and no
  longer says `derivation` is unused.
- `docs/CRYPTO.md` records that the stored ephemeral point is not
  authenticated, what that does and does not let an attacker do, and the
  `keys/fido.json` fields as both kinds actually write them.

## [1.1.0] - Groundwork for the macOS build

No persisted format changed. The 1.0.0 fixtures still describe the current
era, and a 1.0.0 client reads everything a 1.1.0 client writes.

### Added

- A second key kind, `secure-enclave` with derivation
  `ecdh-p256-hkdf-sha256-v1`, for a P-256 key in a Mac's Secure Enclave
  gated on Touch ID. The wrap key is HKDF-SHA256 over an ECDH agreement
  between that key and an ephemeral key made at enrolment; the ephemeral
  public key rides in the credential id. A client on another platform
  carries the envelope and does not offer it to its authenticator, which is
  what 1.0.0 already did with any kind it did not know. The byte vectors
  hold the new envelope, and `FORMATS.md` describes both kinds.
- `silentsilo-fido` gained an `enclave` feature, on by default: the
  agreement and derivation are pure Rust and tested everywhere, and the
  Security.framework half compiles only on macOS, where the backend now
  answers for a removable key over CTAP and for Touch ID.

### Changed

- The CTAP backend finds security keys by the FIDO usage page rather than
  by the vendor list alone, and no longer rewrites Windows interface paths
  that never occurred on the platforms it is compiled for.
- This repository publishes tags only. The extraction tool is built from
  the pinned tag by the desktop release workflow.

## [1.0.0] - Extracted from the desktop repository

The crates, formats, fixtures and extraction tool that shipped in SilentSilo
1.0.0 on 21 August 2026, moved here unchanged. No format, no behaviour and no
public API differs from what that release contains. The dependency graph was
compared before and after: same packages, same versions.

What moved: `silentsilo-core`, `silentsilo-crypto`, `silentsilo-vault`,
`silentsilo-vfs`, `silentsilo-sync`, `silentsilo-store`, `silentsilo-s3`,
`silentsilo-fido`, `silentsilo-extract`, `silentsilo-fixture`,
`silentsilo-testkit`, along with `FORMATS.md`, the cryptography
specification, the compatibility fixtures for the 1.0.0 format era, and the
CI jobs that exercise them.

What did not move: the Tauri application, its OS integration crate and the
frontend, which stay in
[silentsilo/desktop](https://github.com/silentsilo/desktop).
