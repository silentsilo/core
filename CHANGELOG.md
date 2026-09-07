# Changelog

Notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The version follows
semver, and anything that could stop an existing silo from opening needs a
major version rather than a note.

This repository has its own version line, separate from the desktop
application's. A client pins a tag from here; the tag it pins is what its
release notes should say.

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
