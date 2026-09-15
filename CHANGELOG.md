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

- `Vfs::move_file` and `move_folder`, built from records every version
  applies (the entry recorded again in the destination over the same
  content, then the old record trashed, in one transaction), not a new
  record type that a 1.0.0 compaction would drop.
- `silentsilo_fido::passkey`: passkeys kept in a silo, as a `passkey`
  field inside a password entry (`FORMATS.md`, Passkeys). Makes ES256
  passkeys with "none" attestation and signs sign-ins with a zero counter.
  Answers browsers only: an app caller is refused until something checks
  the site's Digital Asset Links. Default feature `passkey`.
- `flows::key_join_begin` and `key_join_open`: joining a silo from its
  storage with a published key instead of the recovery code. The recovery
  envelope comes along when the silo has one.
- `silentsilo_fido::ctap2`: CTAP2 spoken directly over a link the platform
  provides (NFC APDUs, USB HID reports), for Android, where Credential
  Manager's PRF hashes the salt and cannot reproduce the wrap key. Makes a
  credential with `hmac-secret` (with the key's PIN when it asks) and
  derives the same unverified `hmac-secret-v1` wrap key as the desktop, so a
  key enrolled on either opens the silo on both. Default feature `ctap2`.
- `flows::enrol_device_key` records a `fido2` key as removable
  (`platform: false`).
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
- A sync pass reports where it is while it runs (`AppEvent::SyncProgress`:
  sending changes, uploading, fetching changes, downloading, importing, with
  the file being moved). `push_everything_to_reporting` and friends in
  `silentsilo-sync` are the steps it is built from.
- `fetch_blob_from_targets`: content downloaded from a copy is noted as held
  there, so it no longer shows as waiting to back up until the next push.
- `silentsilo_app::inbox_import`, public, for a client whose sync pass is
  still its own: it hands over its open silo through `OpenSilo`.
- `inbox::send_item_from` and `encrypt_stream` in the crate root, for content
  read from a descriptor another app handed over rather than opened by path.

### Fixed

- Editing storage settings with a secret left blank kept the stored secret
  whatever server the settings now named, so a mistyped or hostile host
  would have received it. The stored secret is kept only for the same
  S3 endpoint and access key, WebDAV server and user, or SFTP host, port and
  user.
- Content no configured target holds is remembered locally when a download
  finds it on every configured copy (`list_absent_blob_ids`), asked about
  again by each pass, and skipped by the full-copy fetch.
- A purge replayed on a device that had meanwhile added something under the
  purged folder left that row pointing at a missing folder, and every later
  replay failed. What sits under a purged folder goes with it.
- Two devices importing the same inbox items before either synced put
  them in two folders ("Phone" and "Phone (2)") and disagreed about which
  held the files. Folders made by the import now take ids derived from
  their parent and name.
- An inbox item finished by another device during a scan failed the whole
  scan with "no such file". It is skipped.
- An item recorded by a device that then stayed locked could leave the inbox
  after another device's sweep removed its copied content. The content is
  checked, and copied again, before the item goes.
- Content another device already copied out of the inbox is not copied
  again.
- An inbox item naming a content id the silo already uses is refused
  rather than copied over that content, and an item already recorded is
  copied back only over the content its own record names.
- `flows::key_join_open` refuses a key whose revocation marker is in
  storage, even when its envelope was published again.
- The extractor wrote password entries only as CSV, which has no column
  for passkeys, cards or identities. They are also written whole, to
  `_passwords/entries.json`.
- A file or folder given a " (2)" suffix could take a name another entry
  in the folder already asked for, and the replay then failed on every pass
  on every device. Suffixed names skip names already asked for.
- Subtree queries folded case, so purging or renaming "x (2)" also reached
  into "X (2)". They compare case for case now.
- The storage settings kept the saved SFTP password when the server
  answered with a different host key. A new key needs the password again.
- A WebDAV folder whose name has a space or a letter such as "ș" listed
  nothing, so sync and key reconciliation saw an empty store. WebDAV also
  gives up on a server that stops answering.
- Emptying a trash of more than about 27,000 items wrote one record over
  the 1 MiB every reader refuses, which held back everything after it on
  every other device. A large purge is split into records that each stand
  on their own, and this build reads records up to 4 MiB.
- The blob sweep and compaction ran on a pass that had held records back,
  met an unreadable one, or could not read a copy. Content others added
  could look unreferenced and be deleted. Neither runs on such a pass.
- A device that wrote many records offline could miss that it had fallen
  below a snapshot horizon, because its own records raised the bound it
  was checked on. The check uses what storage listed at the last complete
  fetch.
- A record copied by storage under another record's name was replayed at
  the copy's place in the order, which could bring back an old password
  or a purged file. It is skipped.
- An old snapshot copied under a higher name made every device ask for a
  rebuild on every pass. A snapshot counts only when its contents agree
  with its name.
- A blob header's chunk size is not authenticated, and a reader allocated
  whatever it named, up to 4 GiB per chunk. Any size but the one every
  writer uses is refused.
- Revocation markers are sealed under the content key, which never
  rotates, so anyone who once held it could write one for every key and
  remove every way into the silo on every device. Markers that would leave
  no key are not followed.
- A phone whose key was removed could keep sending to the inbox by putting
  its plain key envelope back in storage. The sealed revocation marker is
  checked too.
- Staging an inbox item replaced content of another size already stored
  under the same id. It is refused.
- A device that had not heard of a new recovery code pushed its old
  envelope back over it, so the new code stopped working and the old one
  worked again. A newer envelope in storage is kept, and adopted locally.
- The content key envelope was rewritten on every pass, and a device left
  out of a key rotation could write its old one over the new. It is
  written only where there is none.
- Key envelopes from storage are not authenticated. One whose credential
  id is not hex is no longer taken in (the id becomes an object name), and
  a recovery-code join no longer takes in a key a revocation marker names.
- The recovery envelope's key derivation could ask for 1 GiB and 64 passes,
  enough to get a phone's app killed during a join. The ceiling is 256 MiB
  and 10 passes, four times what any build writes.
- A preview checked the size a file's record states, which a phone sending
  to the inbox sets, before reading the decrypted file whole. The decrypted
  length is checked too.
- The extractor wrote a second file over the first when two wanted one
  path (a folder really named `_trash`, or two entries with the same title
  and attachment). The second is kept beside it, and Windows device names
  such as `CON` are written with a leading underscore.
- An SFTP overwrite removed the old object before renaming the new one in,
  so a crash between the two lost it, and a device checking the content key
  in that moment took "nothing here" as an answer. The old object is set
  aside until the new one is in place, and the key check asks the next
  copy instead.
- S3 and SFTP give up on a server that stops answering: connecting and
  each read are bounded, and so is the SSH handshake.
- Store settings printed with `{:?}` showed the S3 secret, the WebDAV
  password and the SFTP password or key. They are left out.
- A USB security key answering every channel request with the wrong nonce
  kept the setup going for good, and a short authenticator answer could
  crash Windows enrolment. Both are bounded.
- The key derived from a recovery code, and a device key's wrap key once
  recorded, are wiped after use; the device secret no longer appears in
  `{:?}` output.
- Devices could disagree for good about what is in the trash. Trashing and
  restoring updated rows as each record arrived, so a folder trashed on one
  device and a file in it restored or created on another ended up in the
  trash on some devices and out of it on others. An entry's place in the
  trash is now worked out from every trash and restore record that concerns
  it, in total order, whichever arrived first.
- A password edit fetched late overwrote a newer one, or brought a deleted
  entry back, on the devices that received it last. The newest edit or
  deletion in total order wins everywhere.
- A rename fetched after a newer one undid it on that device, and renaming a
  file to the name it already showed skipped recording the rename, which
  made names differ between devices later.
- Purging entries left what remained of their name groups with the suffixes
  they had, so devices that applied the purge before or after a later claim
  showed different names. The groups are ranked again.
- A conflict copy made when the earlier of two edits arrived last carried
  the other edit's content key, so its content never opened. It carries its
  own.
- Which content a file held and which conflict copies stood beside it
  depended on arrival order: an edit arriving after the edit that built on
  it made a copy of a version that was never a conflict, on that device
  only. Both are now worked out from every edit of the file, and a copy's
  name follows the file's name and the losing edit's date.
- A record creating something a purge had already named, arriving after
  the purge, brought it back on that device alone. It is ignored.
- `SCHEMA_VERSION` is 2: the derived tables are rebuilt once from the log on
  the first open.
- Emptying the trash deleted what another device had meanwhile put in a
  purged folder, which nobody had seen go to the trash. It is moved to the
  top of the silo instead, and so is anything a record arriving after the
  purge creates in that folder. A purged file's conflict copies go with it.
- A rebuild after falling below a snapshot horizon dropped the changes this
  device had not pushed yet. They are written again on top of the rebuilt
  silo.

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
