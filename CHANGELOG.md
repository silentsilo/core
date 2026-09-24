# Changelog

Notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The version follows
semver, and anything that could stop an existing silo from opening needs a
major version rather than a note.

This repository has its own version line, separate from the desktop
application's. A client pins a tag from here; the tag it pins is what its
release notes should say.

## [Unreleased]

## [1.7.1] - Touched copies stay

### Fixed

- A conflict copy someone trashed, renamed, edited or starred no longer
  vanishes on the devices where the edit that retires it arrived first. The
  record aimed at it was dropped as pointing at nothing, and a device
  rebuilt from the log dropped it too, so an edit to such a copy was lost
  everywhere but on the device that made it. A record aimed at a file not
  here yet now waits (`pending_touches`) and applies when the file appears,
  and a touched copy is never retired. `SCHEMA_VERSION` is 4, so every
  device rebuilds its index once. Found by the soak test.

## [1.7.0] - The same silo on every device

### Fixed

- Emptying the trash no longer removes content that no copy holds yet. A
  file edited and then purged before a push lost that edit everywhere when
  another device's purge had not seen it and kept it: the kept file pointed
  at content in none of the backups. `files::release_purged_blobs` keeps
  such content until the pass has sent it, and the pass removes it once
  every copy has it. Present since kept edits shipped; found by the soak
  test.
- A snapshot carries what purges left behind and the edit history of edited
  files (`Snapshot::purged`), so a device rebuilt or joined from it no
  longer drops a file added offline to a folder purged below the horizon, or
  an edit to a purged file, that every other device keeps at the top. The
  same holds for a purge above the horizon of a file edited below it. Left
  out when empty; 1.0.0 and 1.6.1 read
  such a snapshot and ignore the field (`snapshot_purge_memory.rs`).
  `SNAPSHOT_VERSION` stays 1. Found by the soak test.
- A device no longer misses records written offline long ago that another
  device sent and compacted before it fetched them. They carry Lamport
  values the others passed, so a received mark above the horizon hid them.
  The `silentsilo-app` pass now replays its own log to each new horizon
  once (`vfs::state_at`) and rebuilds when the snapshot holds something it
  does not (`vfs::holds_more`). Present since compaction shipped; found by
  the soak test.
- Two devices importing the same inbox item put it in the same folder when
  the import folder had been trashed or emptied from the trash.
  `Vfs::ensure_folder_path` takes the item id and derives the folder id from
  it where the plain derived id is taken; each device used to keep the item
  in a folder of its own. Replay drops a folder creation only when a purge
  of that id sorts after it, so a device whose base hides the purge can make
  the folder again and every device keeps it. Two imports of one item that
  still name two folders are settled by order: the creation first in the
  order places the file everywhere. Found by the random lifecycle test.
- A rebuild writes again only what this device wrote and no copy holds
  (`vfs::undelivered_own_ops`). It took every record not yet on every copy,
  so beside a copy that does not answer (an unplugged drive, a never-delete
  copy under a replaced key) it wrote old history again as new changes,
  other devices' records included: purged folders came back and older edits
  landed on top of newer ones. Present since compaction shipped; found by
  the random lifecycle test.
- A device that was rebuilt from a snapshot, or had compacted before, no
  longer publishes a snapshot missing everything below its base. `capture_at`
  replayed the local log into an empty tree, and after a rebuild or an
  earlier compaction that log starts at the base, so the second compaction
  published a short snapshot and a device rebuilt from it lost what it left
  out. It now starts from the base, like `rebuild_derived`, and
  `choose_horizon` never picks a horizon at or below it. Present since
  compaction shipped; found by the new mixed-fleet test against v1.6.1.
- A key rotation commits the re-wrapped keys and the new recovery envelope
  with the key itself (`rotation::commit_rotation_with`). They were written
  after the commit, so a crash or a locked file in between left the new key
  in force and nothing that opened it. `finish_interrupted_commit` finishes
  a commit that stopped after the KEK moved; `load_fido_keys` and
  `rotation_pending` call it.
- A folder target whose root is gone (an unplugged drive) is `Unreachable`
  for every call instead of empty, so it no longer counts as reached with a
  horizon of 0, and a pass no longer recreates the root and fills it as a
  new copy. `FolderStore::check` creates the root, for a place being added.
- `lowest_snapshot_horizon` ignores a target below the highest horizon whose
  records do not reach it: a stale, never-compacted copy no longer hides that
  a device fell behind. The `silentsilo-app` pass marks every target failed
  and backs off when none answers, instead of stopping with an error.
- `reseal_under_new_key` reports records and snapshots that open under
  neither key in `ResealOutcome::unreadable` rather than in `failed`, so one
  corrupt object no longer blocks a rotation for good. The KEK envelope
  still fails.
- A silo whose `vault.db.enc` is missing opens from the shadow copy or a
  staged snapshot, and `VaultPaths::exists` and `SiloEntry::is_present`
  count those.
- The `silentsilo-app` pass asks every copy whether this device's key is
  still current and takes the gravest answer, leaving never-delete copies
  out unless the silo has no working copy. The first answer used to decide,
  so a copy that missed a rotation could let a retired device push.
- A never-delete copy left under a replaced key is left out of the pass
  with `RETIRED_COPY` as its status. Waiting on it kept inbox items in the
  inbox and stopped the sweep and compaction for as long as it stayed
  configured. Found by the random lifecycle test.
- `seal_for_lock` refuses, like `backup_locally`, when the silo's key changed
  since the session opened, so a lock right after a rotation cannot seal the
  retired key's snapshot over the new one.
- A recovery code made by a newer version is refused with "update
  SilentSilo" in the `silentsilo-app` flows instead of "does not match", and
  the recovery join runs Argon2id off the async workers.
- On Windows a security key prompt that ran out reports a timeout rather
  than a generic failure.
- `send_item_from` leaves an item alone once its envelope is in the inbox,
  and `stage_item` checks the blob header against the envelope before and
  after the copy. A resend no longer lets an import record content sealed
  under another blob id.

### Added

- `seed_target_checked`, which copies records, snapshots and the KEK envelope
  only when they open under the current key, and key envelopes and the
  manifest only where the destination has none. `SeedOutcome::stale` counts
  what it left behind.
- `ObjectStore::get_prefix`, with a default that reads the object whole;
  the folder and S3 backends read only the bytes asked for.

### Changed

- `JoinPlan::FromSnapshot` holds its snapshot boxed.

## [1.6.1] - No parts left behind

### Fixed

- An S3 multipart upload cut short by a killed process no longer leaves its
  parts billed and invisible for good. Before starting a multipart upload,
  `S3Client` aborts every unfinished upload of that exact key, so the retry
  cleans up after the upload it replaces. A provider without
  ListMultipartUploads still uploads; the cleanup is skipped.

### Added

- `ObjectStore::abort_stale_uploads`, with a default that does nothing, and
  `silentsilo_sync::abort_stale_uploads`. The daily blob sweep in
  `silentsilo-app` now also aborts unfinished uploads older than 24 hours
  under `blobs/`, `snapshots/` and `inbox/`, on targets that allow deletes.
  That covers content deleted before anything uploaded it again. A younger
  upload is left alone, since it may be another device's, still running.
- `S3Client::pending_uploads` and `S3Client::abort_uploads_started_before`.

## [1.6.0] - Storage you do not have to trust, and bytes you can watch

### Added

- Byte-level progress and a responsive stop while copying objects between
  storages. `ObjectStore` gained `put_from_file_reporting` and
  `get_to_file_reporting`, which take a callback receiving the bytes moved
  since the last call and answering whether to carry on; a `Break` stops the
  transfer and returns the new `StoreError::Cancelled`. The default
  implementations move the whole file and report it once at the end, so an
  implementation outside this repository keeps working. All four backends
  report as they go: SFTP and a folder per 512 KiB chunk, S3 and WebDAV per
  chunk downloading, WebDAV from the body as it is read, and S3 per part.
- S3 uploads any file over 16 MiB in parts, a sync pass as well as a seed.
  Alongside the progress it lifts the 5 GiB ceiling a single PUT has, which
  until now was the largest file a silo could hold. A stop or a failure
  aborts the upload, so no parts are left billed and invisible.
- `silentsilo_store::init_android_tls` (Android only): gives the platform
  certificate verifier the JVM and the app context. The app also has to ship
  the verifier's Kotlin component; see the README.

### Changed

- **Breaking for clients**: `seed_target` reports a `SeedProgress` struct
  (objects done and total, bytes done and total) instead of two `usize`
  arguments, at most once every 250 ms, and asks `cancel` on every progress
  report as well as between objects. Filling one copy from another now moves
  a number while a single large blob is transferring, and Stop lands inside
  the object rather than after it. Whatever already landed stays: the next
  run skips it. A client passes `&mut |progress: SeedProgress| …` where it
  passed `&mut |done, total| …`.
- **Breaking for clients**: a sync pass reports bytes while a single large
  blob uploads, not only between blobs. `push_blobs_reporting` takes
  `&mut |step: BlobPush|` instead of `&mut |done, total, blob_id|`, and
  `PushStep::Blob` carries that same `BlobPush` (blobs done and total, the
  blob id, bytes done and the blob's size) instead of three named fields.
  Every blob is still named once before it is looked at; one being sent
  reports again as it goes, at most every 250 ms, and once more with all of
  it up. `silentsilo_app::SyncProgress` gained `bytes_done` and
  `bytes_total`, zero on the phases counted in items, and resolves the file
  a blob belongs to once per blob rather than once per report.
- Three oplog calls a client makes with the silo held no longer scale with
  the history. `replay` applies a batch in one transaction with a savepoint
  per record, instead of a commit per record; a record still stands or falls
  on its own and everything before a refused one is kept. `mark_delivered`
  writes one prepared statement under one savepoint, instead of a commit per
  record, and nests inside a transaction the caller already holds.
  `pending_ops_for` reads the payloads out before decoding them, so the
  statement is no longer open for the whole of the parsing.

### Fixed

- A backup target can no longer disappear from the list after it is added.
  Windows Credential Manager refuses a blob over 2560 bytes, which is 1280
  characters because the blob is UTF-16, and one SFTP target carrying its
  private key passes that on its own. The refused write fell back to the
  file, the keyring entry kept the shorter list it had taken before, and
  `load_targets` reads the entry first: the target just added was gone on
  the next read, eviction counted fewer copies than the user had configured,
  and the next save wrote the short list back. The entry is now deleted once
  the file holds the list, so the two copies cannot disagree. The storage
  settings and the device credentials had the same shape and were fixed with
  it. `s3_store.rs` has a test that writes a list Credential Manager refuses.
- HTTPS to S3 and WebDAV works on Android. S3 found no root certificates on
  a phone, and WebDAV panicked in the handshake because its verifier was
  never set up. Both now use Android's verifier, and a handshake before
  `init_android_tls` fails with an error instead of a panic. Desktop keeps
  the SDK's client and native roots for S3; WebDAV passes the same platform
  verifier to reqwest explicitly.
- Joining a silo no longer trusts the `policy` on fetched key envelopes. A
  recovery-code join clears it everywhere; a key join keeps `org` only on
  the key that opened the silo. Storage could plant an `org` envelope nobody
  can prove, which then refused rotation and recovery-code changes on the
  joined device.

### Security

- The protected folders' list and import ledger are encrypted. Between them
  they named every mirrored file by its full local path, in the clear beside
  the blob cache, and they outlived locking the silo and removing it. The
  list is a sealed payload (`protected.enc`) and the ledger is a SQLCipher
  database (`protected.sqlcipher`) under a random page key, both under the
  content KEK, which never rotates: sealed under the DEK a rotation would
  leave the ledger unreadable, and a ledger that reads as empty means every
  protected file imported a second time. A `protected.json` or `protected.db`
  from an earlier release is read once, taken over and removed. A ledger that
  will not open is an error rather than an empty one, for the same reason.
  `load_protected`, `save_protected`, `load_seen` and `mark_seen` take the
  content KEK, so a client reads them only while the silo is unlocked.
- An old `keys/content.kek` put back in storage is told apart from a key
  rotation, and reported as what it is. Both look the same from the envelope
  alone, so every device went to `needs_rejoin` and the rejoin then failed on
  the same object: one PUT by anyone who could write to the bucket stopped a
  whole fleet with a message telling it to do something that cannot work. A
  device that cannot open the envelope now reads the newest records, which a
  rotation re-seals first, and says the object was replaced
  (`SyncReport::key_material_replaced`) rather than asking for a rejoin. The
  join flows give the two cases different messages instead of a crypto error.
  New: `silentsilo_sync::kek_envelope_state` and `KekState`.
- The recovery envelope carries a tag keyed by the content KEK, and a device
  adopts a stored envelope only when that tag verifies. `created_at` alone
  decided which envelope a device kept, and that number is chosen by whoever
  writes the object: a bucket writer could bring back a code that had been
  turned off, or replace the local envelope on every device with one that
  opens nothing, which nobody would notice until they needed it. The field is
  optional and left out of the JSON when absent, so a client from 1.0.0
  onward reads and opens an envelope written today unchanged; a device tags
  the envelope it already holds on its next pass, so a silo made before this
  needs no new code written down. `create_recovery_envelope` and
  `seal_under_code_for_fixtures` take the content KEK.
- A committed rotation replaces the working copy's `vault.key` at once with
  the one staged under the new DEK, or deletes it when none was staged.
  Until the next unlock it stayed sealed under the retired DEK, which with
  local disk access still opened the ciphered working copy.
- Windows Credential Manager entries (device secret, storage settings, the
  target list) are written with `CRED_PERSIST_LOCAL_MACHINE` instead of
  keyring's roaming `CRED_PERSIST_ENTERPRISE`, so a domain roaming profile
  no longer copies them to other machines. Reads are unchanged; an existing
  entry is rewritten local the next time it is saved.
- Key envelopes, revocation markers, inbox keys and senders, `vault.json`,
  `keys/content.kek` and `recovery.env` are refused unread above 64 KiB
  (`MAX_SMALL_OBJECT_BYTES`), judged from the listing or a HEAD. A hostile
  provider could answer one with enough bytes to exhaust memory.
- OpenSSL no longer reads a configuration file. The vendored build has the
  build machine's path compiled in as OPENSSLDIR, and a config there, or one
  named by `OPENSSL_CONF`, could load a provider library into the app, the
  extractor or the fixture tool. `silentsilo_vault::init_openssl` runs before
  every SQLite connection this workspace opens.
- rustls 0.23.45 (RUSTSEC-2026-0285) and h2 0.4.19 (RUSTSEC-2026-0258) in the
  lockfile, with aws-lc-rs 1.18 which rustls 0.23.45 needs. CI runs
  `cargo audit` on every push.

## [1.5.0] - Nothing readable left behind, and no lost edits

No persisted format version changed, so the 1.0.0 fixtures still describe
the current era. `SCHEMA_VERSION` is 3, which rebuilds each device's derived
tables from its own log on the first open. The working copy of a silo's
index is now ciphered with SQLCipher and kept across locks; `vault.db.enc`
keeps its format. Purges written by this build carry marker ids in
`file_ids`, which earlier clients ignore. Building now needs a Windows Perl
(Strawberry) for the vendored OpenSSL; see the README.

### Added

- `wipe_work_dirs_except` and `AppState::sweep_scratch`: remove the decrypted
  scratch of every silo that is not open, including what a crash, a kill or a
  power cut left for a silo that may never be opened again. Clients call them
  at start and after each lock. They keep a ciphered working copy that has
  its sealed key.
- `wipe_plaintext`, `KEPT_ACROSS_LOCKS`.
- The storage sweep puts back content a file still points at that a copy no
  longer holds, from this device's cache or from another copy
  (`restore_missing_blobs`, `SyncReport::blobs_restored`). It uses the
  listing the sweep already makes, so it costs no extra request. Content no
  row here references is never sent.

### Changed

- An edit made on one device while another emptied the trash is kept as a
  copy at the top of the silo, instead of going with the file. Only edits
  the emptying device had not received count. A purge now also names a
  marker per file saying it lists every edit its device held; for a purge
  from an earlier release, an edit counts as not received when another
  device wrote it at or after the purge's place in the order. The index
  rebuilds once on the first unlock (`SCHEMA_VERSION` 3).
- The sweep deletes content only once it has been unreferenced for 30 days
  by this device's clock, on top of the two sightings
  (`snapshot::gc_first_seen`, a new `blob_gc_seen` table beside the
  candidates). Emptying the trash frees space in storage a month later.

### Changed

- The working copy of an open silo is ciphered with SQLCipher 4 (vendored
  OpenSSL) and named `vault.sqlcipher`. Its random page key sits beside it
  as `vault.key`, sealed under the DEK, so a crash, a kill or a power cut
  leaves nothing readable and the next unlock still adopts the changes.
  Unlock and snapshots move the decrypted index through memory only. The
  connection keeps a 64 MiB page cache, since every page read is decrypted.
  `vault.db.enc` is unchanged: still a whole plain SQLite image in the same
  envelope, so every release reads it.
- A plaintext `vault.db` left by a crash of an earlier release is adopted
  once, snapshotted and replaced by a ciphered copy. An earlier release
  after a downgrade never sees the ciphered copy and opens the snapshot.
- `VaultPaths::db_path` names the ciphered copy; `db_key_path`,
  `db_key_staged_path` and `legacy_db_path` are new.
- `stage_local_backup` also seals the page key under the new DEK
  (`vault.key.next`), so a crash after a rotation commits keeps the changes.
- A lock keeps the ciphered working copy and its sealed key, and the next
  unlock reuses it while it still stands for `vault.db.enc`, checked by a
  BLAKE3 fingerprint the copy records at every snapshot write. A 12 MB index
  unlocks in about 50 ms instead of 800 ms. A snapshot written by anything
  else gets a fresh export. `seal_for_lock` marks the copy and folds its WAL;
  `wipe_plaintext_working_copy` now removes only plaintext (opened files, a
  legacy `vault.db`), and `wipe_work_dir` still removes everything.
  `encrypt_vault_bytes` returns the fingerprint.
- A lock or a flush with nothing written to the working copy since the
  snapshot on disk was taken keeps that snapshot instead of sealing it
  again: after an unlock with no change, a lock takes about 35 ms instead
  of 220 ms on a 12 MB index. "Nothing written" is this connection's count
  of changed rows plus the schema cookie, noted in a TEMP table when the
  snapshot is written, exported or adopted, and both `vault.db.enc` and its
  shadow copy must still match the recorded fingerprint.
- Building now needs Perl for OpenSSL (Strawberry Perl on Windows).

### Fixed

- A file moved on a device that had not yet received an edit or a purge of
  it could lose its content. The move records the file again over the
  content that device held; every other device had stopped referencing that
  content and swept it after two sightings, so the moved file opened
  nowhere. The grace period covers a device that syncs at least once a
  month. Seen as 11 failures in 218 runs of `fleet.rs` with a sweep on every
  pass, none since.
- Beside a 1.0.0 device, content this build keeps and 1.0.0 has no row for
  was swept by 1.0.0 for good: a file added to a folder another device
  purged meanwhile (1.0.0 drops it, this build moves it to the top), or a
  move made from a version 1.0.0 had already replaced or purged. A device on
  this build that holds the bytes now puts them back on its daily sweep.
  1.0.0 deletes them again two sweeps later for as long as it runs, so the
  content can be missing from storage for up to a day at a time, and it is
  lost only where no device on this build holds it.

- A lock straight after a key rotation snapshotted under the session's old
  DEK, over the snapshot the rotation had just written under the new one,
  and the silo then failed to open locally. `backup_locally` now refuses
  when the content KEK on disk no longer opens under the session's DEK.
- The first unlock after an update rebuilt the derived tables one commit per
  record: 32 seconds on a 50,000-record log. The rebuild now runs in one
  savepoint (about 9 seconds), and an interrupted rebuild leaves the previous
  tables to start over from.
- A device on this build no longer writes, from what it holds, records that
  stop a 1.0.0 device for good. A 1.0.0 device stopped replaying at a record
  it could not apply and received nothing after it until it updated. The
  causes, all changes 1.0.0 itself refuses:
  - names. 1.0.0 ranks a name group `a.txt`, `a (2).txt`, `a (3).txt` with
    no gaps, and this build skips a suffix another entry asked for outright.
    Where the two would differ, a record joining the group asks for the name
    shown (the entry keeps that suffix later). Asking outright for a suffix
    some group ranks onto renames the entries holding it first. After a
    purge, the last entry of each group it left gaps in is renamed to the
    name it already asked for, because 1.0.0 does not rank the rest again.
  - emptying the trash while a trashed folder still holds something
    restored. What is live in a trashed folder is moved to the top of the
    silo first, deepest first.
  - a purge now names the conflict copies of the files it removes. This
    build removed them without naming them, and 1.0.0 kept them, in folders
    it then could not delete.

  Two devices changing the same folder at once can still write records that
  1.0.0 refuses together, as two 1.0.0 devices can.
- `Vfs::ensure_folder_path` failed with "not found" when the folder id it
  derives had been purged; it now takes a fresh id, as for a trashed row.

## [1.4.0] - The mobile client, and devices that agree

No persisted format version changed, so the 1.0.0 fixtures still describe
the current era. `SCHEMA_VERSION` is 2, which only rebuilds each device's
derived tables from its own log on the first open. The recovery-off marker
reuses the revocation marker's bytes. Desktop and mobile pin this tag.

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
- A recovery code turned off on one device came back from any device that
  still held its envelope, on that device's next pass. Turning it off now
  leaves a sealed marker under `keys/revoked/recovery.sealed`, and each pass
  drops an envelope made at or before it, locally and in storage
  (`settle_recovery_envelope`, `mark_recovery_disabled`, `revoked_at`).

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
