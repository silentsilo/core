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

- `silentsilo_fido::device_enclave`: the Secure Enclave on iPhone and iPad,
  the same `secure-enclave` kind and derivation a Mac uses, with `remove` to
  delete a device's key. Builds for `aarch64-apple-ios`; not yet called by
  the mobile client.
- Touch ID refused for want of a signature (`errSecMissingEntitlement`) is
  said as such, with a translation key (`err.touchid_unsigned`), instead of
  the raw keychain error.
- Error messages a person reads carry a translation key after their English
  (`silentsilo_core::coded`): about 50 of them, in recovery, joining, the
  activity log, security keys, storage settings and the three clouds. The
  English comes first, so a client that does not translate shows it as
  before once it drops the key.
- Activity log codes 35 to 38: restored from the trash, moved, renamed,
  folder created. A reader that does not know them names them by number.
- `repair_from`: what a content check finds missing or damaged on a working
  copy (bit rot, an upload cut short, a lost file, a garbled record) is put
  back from another copy or the local cache, once that source proves it
  holds the object whole. Nothing is deleted, never-delete copies are only
  reported, and every write is read back.

### Fixed

- iOS: an enclave key was made without its Face ID requirement, so a silo
  on an iPhone opened without asking. security-framework 3.7 adds the
  private-key attributes, where the access control lives, only when built
  for macOS. The attributes are now built in this crate for both, a test
  holds that the access control rides with the private key (run on macOS in
  CI), and an enrolment whose key comes out without it is refused. Found
  before any iPhone release; no released build was affected.
- macOS: the app could crash minutes after start when it looked for a
  security key. hidapi files its device manager on the run loop of the
  thread that first opens it, and that was a tokio blocking thread which
  later retired; the first opening now happens on a thread that lives as
  long as the process. Found on a real Mac.
- S3: reading the first bytes of an empty object returned an error (416)
  instead of nothing.
- The trash no longer lists the old place of a moved file or folder. A
  move recorded the entry again and trashed the old row, so a moved file
  showed in the trash at its old path, and a file moved then deleted showed
  twice; restoring the old one put it back where it had been.
- Audit L1 is closed by reader checks, with no format change: a sealed
  object's AAD does not bind its name, so every reader now compares the
  name with the content and has a test that moves a real object under
  another name. Fixed where one did not: a content check reports a record
  under another record's name as damaged; the rotation check and the
  missed-rotation check no longer count such a record; the KEK envelope
  must hold a 32-byte key before a pass takes it as current or a seed
  copies it; a seed copies no record or snapshot whose name does not match;
  an activity log key must match its name and its wrapped private key must
  match its public key; retention skips a segment that names another place;
  the KEK and a rotation's staged key in the silo folder refuse each other.
- Reading the activity log no longer waits on the copies one after
  another: they are read together, each given 30 seconds, and one that does
  not answer is named as not read. `read_audit_log_local` gives what this
  computer holds without touching storage; both now take the `Reader` by
  reference.
- A working copy that missed a rotation of the silo's key (one only this
  device lists, or a drive unplugged at the time) no longer sends a device
  the rotation kept to rejoin in a loop. It is left out of the pass with a
  status that says to remove and add it again; a device whose own key was
  retired is still sent to rejoin (audit CO-4).
- Checking an inbox item's header on WebDAV and SFTP reads only the header,
  not the whole file (audit CO-3).
- Answers from OneDrive, Dropbox and Google Drive are read up to 8 MiB, and
  token answers up to 256 KiB; a larger one is refused rather than held in
  memory (audit CL-7).
- A sign-in whose port is held on `::1` by another program moves to the
  next port, so that program never receives the redirect (audit CL-3).
- rustls-platform-verifier 0.7.1: on Android, certificates with only a
  revocation list (Google's now) were reported as revoked.

### Changed

- The cloud tests' fake servers keep listening after a failed accept and
  close connections cleanly.

## [1.9.0] - The activity log, custom fields and history

### Added

- The activity log is on by default for a personal silo nobody ever set it
  for: started at the first sync pass once every copy the silo has
  answered (those resting after a failure included) and none holds a
  policy, or when opened for a silo with no copies
  (`AppState::start_audit_by_default`). A choice of off, on any copy, is
  kept, and so is off chosen on this device before the log ever started.
- Reading the activity log opens its records on every core, and keeps what
  it opened while the silo is open, so a second read opens only what is
  new: 100,000 events went from 15 seconds to half a second, then 65 ms.
  `AppState::forget_audit_read` drops it; a client with its own close path
  calls it. A personal log opens with every key in `audit/keys/` the
  content key unwraps, so records two devices sealed to their own keys,
  having started the log at the same time, both read.
- Event code 15, "Signed with an SSH key", for the desktop's SSH agent,
  and the optional `ssh_agent` flag on an SSH-key entry (`FORMATS.md`): an
  older client keeps it when it saves the entry, since desktop and Android
  edit a copy of the whole entry.
- `silentsilo-audit`: the activity log. Each event is sealed alone with
  HPKE (RFC 9180) to the log's key, queued on the device (`audit-queue/`
  beside the silo, safe against a crash at any point: a record cut short is
  cut off before the next is appended), and sent in numbered, chained
  segments under `audit/`, each under 8 MiB and 100,000 records. A segment
  in the queue that does not read is set aside rather than holding back the
  rest, and one a copy holds under the same number with other bytes is
  kept here, not counted as delivered. The
  key is random, its private half wrapped under each organisation key or
  under the content key, so devices on an organisation's silo write the log
  and cannot read it. Event codes are numbers, fixed for good. The format is
  in `FORMATS.md`, pinned by a byte vector, and 1.0.0's and 1.6.1's own
  pruning and sweep leave `audit/` byte for byte.
- A seed copies `audit/`, and never writes over a segment the destination
  holds.
- `AppState::set_audit_log` and `audit_status`: a personal silo's log is
  turned on or off on the device, with or without copies; the queue keeps
  the key and policy, and the pass writes the newest policy to every copy
  that lacks it. Turned on again, it keeps its key. An organisation's log
  cannot be turned off.
- `silentsilo-extract` writes a personal activity log to `_activity/`, as
  CSV and JSON lines, next to the files; `list` counts its events. An
  organisation's log is named and left alone: only its security keys read
  it.
- `silentsilo_audit::reading`: opening and checking a gathered log, and its
  CSV and JSON lines, shared by the app and the extract tool so the two
  cannot read it differently. CSV cells that look like a formula are kept
  as text.
- `audit_admin`: an organisation's log, started with one of its keys
  touched and readable only by its keys; another key added the same way;
  retention changed; segments past it removed from every copy that takes
  deletes, never below 90 days whatever the policy says. A personal log
  follows the key a newer policy names, so devices follow an organisation
  starting its log; an organisation's key stays pinned, and a policy
  naming another key changes nothing of it. The scope pinned is the sealed
  policy's, and a key file it does not confirm is refused. Copies of the
  log's key merge their ways in, with the one on the device as well.
- `audit_read::read_audit_log`: the whole log, from this computer and every
  copy, opened with the log's key, with each device's missing segments and
  events, the records that do not open, and the copies that could not be
  read. Fetched segments are kept in `audit-cache/` beside the silo.
- `silentsilo_app::record_lock`: the lock event and the segment it closes,
  for a client that closes its sessions itself.
- `MAX_ENTRY_BYTES`: `upsert_password` refuses an entry over 512 KB, so its
  record stays under the 1 MiB readers before core 1.4.0 accept. Nothing
  wrote entries that large; history inside the entry could.
- `FORMATS.md` describes the entry's `fields` and `history`, and a fixture
  test proves 1.0.0 keeps both through replay, snapshot and compaction.
- `fixtures/v1.9.0` and its compacted twin: a silo whose storage holds a
  personal activity log, and an entry with custom fields, history and
  `ssh_agent`. The fixture digest now lists the activity log a store holds.

### Fixed

- Opening a silo could fail now and then with "no such function:
  sqlcipher_export", seen on Linux CI. SQLite marks itself initialised
  before SQLCipher's setup has registered that function, so a thread
  opening its first connection at the wrong moment got one without it.
  `init_openssl`, which runs before every connection, now initialises
  SQLite too, inside the same `Once`.
- A security key with a PIN, enrolled on Linux or macOS, did not open the
  silo on Windows or Android, and the other way round. Those builds talked
  to keys through `ctap-hid-fido2` and never asked for the PIN, so they
  read the key's other `hmac-secret`. They now go through this crate's own
  CTAP2 code, the one Android uses, over USB HID (`hidapi`): a key with a
  PIN is asked for it, as Windows does. The client asks through
  `set_pin_prompt`; without one, such a key is refused as cancelled.
  `ctap-hid-fido2` is gone. A key that is plugged in but cannot be opened
  is reported as such (`FidoError::NoAccess`, a missing udev rule on
  Linux) rather than as no key.
- A removed key could come back. A copy that was unplugged when the key was
  removed (an external drive, say) still held its envelope and no marker,
  and once the removal was confirmed elsewhere, plugging it in put the key
  back on this device and published it again. A pass now reads the
  revocation markers on every copy before it takes in any envelope.
- Seeding a new copy from a never-delete one could copy back the envelope of
  a removed key, and nothing would ever delete it there. The checked seed
  now copies envelopes only for keys this device holds as in use; the pass
  that follows publishes the rest.
- A sign-in to OneDrive, Dropbox or Google Drive that was never used stayed
  in memory until the app quit, unless another sign-in pushed it out. It now
  goes when its dialog closes or when the silos lock, and a Dropbox one is
  revoked then; after 30 minutes it is no longer offered. Adopting one takes
  it out of the list first, so a lock at that moment cannot revoke it.
- A refresh token Microsoft rotated right after a copy was added or
  reconnected was not written, and a pass still running during a reconnect
  could write an older token over the new one, or write one back for a copy
  just removed. Only the source a copy currently uses writes its token now.
- Joining read `keys/content.kek` and every revocation marker as if they
  were key envelopes, and logged each one as unreadable.
- The activity log's queue on the device had no lock: an event recorded
  while the pass closed a segment could take a number already used. The
  queue is now held under a file lock while open, and the pass holds it only
  for local work, never across an upload.
- `audit_is_mandatory` answered no for an organisation's silo whose queue
  could no longer be read, which let a client go on unrecorded exactly when
  writing failed. A silo seen with an organisation's log now stays mandatory
  for as long as the process runs.

### Changed

- `seed_target_checked` takes this device's keys, and
  `reconcile_key_envelopes` the markers found on the other copies
  (`revocation_marks`). New: `cancel_cloud_sign_in` and
  `forget_cloud_sign_ins`, for a client to call when a sign-in dialog closes
  and when the silos lock.

## [1.8.3] - russh 0.63

### Security

- `russh` 0.62 to 0.63 for SFTP, for four advisories GitHub lists and
  RustSec does not yet (GHSA-47hw-gvq5-r2gm, GHSA-35g8-35p8-c8fw,
  GHSA-p8qx-h547-fjw9, GHSA-w3jg-pjxf-73p4). Each needs the SFTP server to
  be hostile. A host certificate is still refused: silos pin the server key.

## [1.8.2] - Audit fixes before the cloud releases

### Fixed

- A key change could leave a silo with no working recovery code. Past the
  point of no return, a key file held open by a sync client or an antivirus
  turned the commit into an error, the app never showed the new code, and
  the old one had already stopped working. The commit now reports success
  from there on and writes a held file in place.
- An upload Google Drive or OneDrive had not finished could be taken as
  done, and the blob then counted as delivered and could be evicted from
  this computer. Drive may keep only part of a chunk, and OneDrive can
  answer 202 to the last fragment; the upload now goes on from where the
  provider says, and is done only when it returns the file.
- `targets.more.config.json` that could not be read (protected under another
  Windows account, damaged, or from a newer release) was taken as empty, and
  the next save deleted it with every cloud copy in it. The save now refuses.
- Answers a provider should never give no longer panic or loop: a Dropbox
  path with non-ASCII letters, a token lifetime too large for a clock, a 416
  to a request with no range, a Google Drive folder that is its own
  ancestor.
- The test helper that holds a file open now holds it as a scanner does, so
  the tests for held files test what they say.

## [1.8.1] - Cloud sign-in on a phone

### Fixed

- Signing in to OneDrive, Dropbox or Google Drive from a phone. The browser
  is answered at once; the code is traded only once the app is back on
  screen, and a request the phone kept off the network is tried again for
  up to a minute. Before, Android's certificate check answered "revoked"
  for about half a minute after the app came back, and OneDrive's account
  was read from a place the app folder permission cannot reach.
- Google Drive on an account with several silos: a check for a file no
  longer searches the whole Drive each time and finds the other silos'
  files of the same name. A new small file costs about four requests, not
  ten.
- Keyring deletes are confirmed twice: Credential Manager has been seen to
  hand back an entry it had confirmed deleted.

### Changed

- `ObjectStore::get_small` reads a small object in one request where the
  backend can, refusing it unread when it is too large. Sync uses it for the
  manifest, the key envelopes and `recovery.env`; on the cloud providers it
  saves a request each time.
- The sign-in page says plainly what to do next.
- The cloud request trace (`SILENTSILO_TRACE_CLOUD`) exists in debug builds
  only.

## [1.8.0] - OneDrive, Dropbox and Google Drive

### Added

- OneDrive, Dropbox and Google Drive backends (`silentsilo-cloud`), each in
  the app's own folder at the provider, and all three held to the same
  `ObjectStore` contract suite as the others, against fake servers in CI.
- Signing in to them: PKCE and a loopback redirect, the account and space a
  sign-in reached, refresh tokens kept per target in the keyring (in a
  file when too long for it, DPAPI-sealed on Windows), and one refresh at a
  time per target.
- The account of a cloud target comes from a sign-in the app holds, never
  from the UI. A reconnect must be the same account.
- Backup targets of a kind 1.7 does not know are kept in
  `targets.more.config.json`, so an older release reads the list it knows
  unharmed and its saves leave the new targets alone. A kind this release
  does not know is kept as it is, in its place.

### Fixed

- A token read that Credential Manager fails now and then is retried before
  it asks for a new sign-in, and deletes of keyring entries are checked.

## [1.7.2] - Kept edits settle

### Fixed

- An edit kept as a file of its own after a purge no longer stays on the
  devices that got the purge before the edit it had listed. Once that edit
  arrives, the kept file is taken back, as it never appeared on the others,
  unless someone trashed, renamed, edited or starred it; then it stays on
  every device. `SCHEMA_VERSION` is 5, so every device rebuilds its index
  once. Found by a test written for a missed mutant.

### Added

- Tests for what mutation testing of `silentsilo-vfs` found unchecked:
  snapshots through their bytes, splitting large purges, the derived id of
  an import folder, a rebuild meeting a record it may not skip, conflict
  copy metadata, and the star in every listing.

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
