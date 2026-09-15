# Persisted formats

Everything SilentSilo writes that outlives a run, what version it is at, and
what an older build does when it meets a newer one.

A vault that will not open is unrecoverable by the person who owns it. That
makes every change on this page higher risk than the code around it, so each
one answers the same question before it lands: **what does a client on the
previous release do with the new bytes?** Only two answers are acceptable, and
they have to be true by test, not by argument.

1. It ignores the new thing safely.
2. It refuses explicitly and says to update.

Anything else needs a version discriminator first.

## In the bucket

| What | Where | Version | An older build meeting a newer one |
|---|---|---|---|
| Manifest | `vault.json` | `MANIFEST_VERSION = 1`, `silentsilo-sync` | Refuses to open the silo and says to update |
| Snapshot | `snapshots/….snap` | `SNAPSHOT_VERSION = 1`, `silentsilo-vfs/snapshot.rs`, sealed | Refuses, naming the version |
| Operation record | `ops/…` | `skippable` flag per record, plus `seq` and `prev`, `silentsilo-vfs/oplog.rs` | Skips a record marked ignorable, refuses on anything else. A record without `seq` is refused outright. `ReplaceFileContent.replaces` is optional and absent when unset, so a record without it decodes and is applied the old way, without conflict detection |
| Sealed payload | wraps every op record | `SEAL_VERSION = 1`, `silentsilo-crypto/sealed.rs` | Refuses, naming the version |
| Blob | `blobs/….sslo` | `SSLO_VERSION = 1`, `silentsilo-crypto/blob.rs` | Refuses, naming the version |
| Recovery envelope | `recovery.env` | `RECOVERY_ENVELOPE_VERSION = 1`, plus stored KDF parameters | Refuses on a newer structure; a parameter change needs no bump |
| Key envelopes | `keys/….env` | **No file version.** Plain JSON of one enrolled key, carrying `kind` (what unwraps its `wrapped_dek`) and `derivation` (how that key was derived from the authenticator) | Ignores an envelope whose `kind` or `derivation` it does not know, and refuses by name when none is left it can use |
| Content KEK | `keys/content.kek` | Sealed payload under the vault DEK | Refuses, naming the version |
| Inbox key | `inbox/keys/….sealed` | `INBOX_VERSION = 1` inside a sealed payload under the content KEK, `silentsilo-sync/inbox.rs` | 1.0.0 never lists `inbox/`. A build with the inbox skips a key it cannot read |
| Inbox sender | `inbox/senders/….sealed` | `INBOX_VERSION = 1`, sealed under the content KEK | As above |
| Revocation marker | `keys/revoked/….sealed` | `version: 1` inside a sealed payload under the content KEK, `silentsilo-sync/key_sync.rs` | 1.0.0 lists it with the key envelopes and skips it as unreadable |
| Inbox item | `inbox/items/….sslo` and `….env` | The blob as in `blobs/`; the envelope carries `INBOX_VERSION = 1` | 1.0.0 never lists `inbox/`. A build with the inbox leaves an item of another version where it is and says to update |

## Reading a backup from scratch

The order below is the whole of it, and it is written out because a format
nobody can read without our source is not a format. `silentsilo-extract`
follows exactly these steps; a reader written from this page alone should
arrive at the same files.

Everything is in one bucket or folder. Nothing else is needed but the
recovery code.

1. **`vault.json`** gives `vault_id` and `MANIFEST_VERSION`. Refuse a version
   above the one you understand rather than guessing at the rest.

2. **`recovery.env`** holds the vault DEK wrapped under the recovery code.
   Derive the wrapping key with Argon2id over the normalised code and the
   salt stored beside it, using the parameters in the envelope rather than
   assumed ones, then open the sealed payload. Out comes the 32-byte DEK.
   Normalising means uppercasing, dropping separators, and mapping the
   letter and digit pairs the alphabet excludes.

3. **`keys/content.kek`** is a sealed payload under the DEK. Inside is the
   32-byte content KEK. Every file's key is wrapped under this, not under the
   DEK, which is what lets the vault key be rotated without touching content.

4. **`snapshots/`**, if it is not empty. Take the highest-numbered object,
   which is also the last in a plain listing because the horizon is
   zero-padded. It is a sealed payload under the DEK holding the whole tree
   at that point. Start from it: after a compaction the records below its
   horizon are gone, and replaying only what is left rebuilds the tail of the
   history rather than the silo.

5. **`ops/`**, in listing order, which is already the order to apply them: the
   key begins with the zero-padded Lamport counter. Each object is a sealed
   payload under the DEK holding one JSON operation record. Apply them onto
   the snapshot, or onto an empty tree if there was none. A record whose
   operation you do not recognise is skippable if it says so and fatal if it
   does not.

6. **The tree** is then folders, files, and for each file its `blob_id` and
   its `blob_key`. Unwrap `blob_key` with the content KEK from step 3 to get
   that file's own 32-byte key.

7. **`blobs/<blob_id>.sslo`** is the content. The 82-byte header gives the
   version, the chunk size, the file and blob ids, the BLAKE3 hash of the
   plaintext and the nonce prefix. After it, chunks of `chunk_size`
   ciphertext each followed by a 16-byte tag. Decrypt each with AES-256-GCM
   under the file's key, nonce being the 8-byte prefix followed by the
   big-endian chunk index, with the blob id as additional authenticated data.
   Check the plaintext against the hash in the header: the header is not
   authenticated, so that comparison is what catches content swapped for
   other valid content.

`inbox/` holds content a device sent but no unlocked device has imported
yet. It is not part of the tree, and a reader rebuilding the silo may ignore
it. To recover those items too, follow "The inbox" below.

Two things worth stating because they are easy to get wrong. Records are
never rewritten, so a record's fingerprint covers a body that does not
change, and the `prev` chain per device holds. And a blob can be in storage
before the record naming it, so content nothing refers to is normal rather
than a sign of damage.

## In the silo folder

Everything here travels with the folder, which is the point: a silo is
restored as a unit. Nothing that would let the holder of a copy open it is
in this list; that lives on the machine instead, in the table after this one.

| What | Where | Version | Notes |
|---|---|---|---|
| Wrapped DEK | `master.dek.enc` | Sealed payload envelope | Same format as an op record, one place to change |
| Content KEK | `content.kek.enc` | Sealed payload under the vault DEK | Refuses, naming the version |
| Salt | `vault.salt` | **No version.** 16 raw bytes | Any other length is refused as bad credentials rather than read short |
| Which silo this is | `silo.json` | `MARKER_VERSION = 1`, `silentsilo-vault/registry.rs` | Refuses a newer one; unlock uses it to tell a leftover working copy from this silo's |
| Enrolled keys | `keys/fido.json` | `SILO_FILE_VERSION`, plus a `kind` per key | |
| Recovery envelope | `keys/recovery.json` | Its own, as above | Its version means the shape of one wrapped key, not the file |
| Index | `vault.db.enc` | `SCHEMA_VERSION = 2`, `silentsilo-vfs/schema.rs` | Not a format: see below |
| Index, mid-rotation | `vault.db.enc.next` | Same envelope as `vault.db.enc` | Transient; unlock adopts it, see below |
| Base snapshot | `vault_base` table in `vault.db` | `SNAPSHOT_VERSION = 1`, `silentsilo-vfs/snapshot.rs` | Refuses, naming the version |

## On this machine only

Kept in the OS keychain where it will hold them, and in these files where it
will not. Never in the silo folder: that folder is made to be carried around
and may sit in a synced directory, and a device secret or an access key
travelling with it would hand the vault, or the storage behind it, to whoever
holds a copy.

| What | Where | Version | Notes |
|---|---|---|---|
| Credentials | `credentials.json` | `SILO_FILE_VERSION = 1`, `silentsilo-vault/format.rs` | Refuses rather than reading as "no silo here" |
| Storage settings | `s3.config.json` | `SILO_FILE_VERSION` | The one connection a joined or recovered device starts with |
| Backup targets | `targets.config.json` | `SILO_FILE_VERSION` | Every copy, in order. Kept as a file as well as in the keychain whenever there is more than one, because the single slot above holds only the first |
| Silo list | `silos.json` | `SILO_FILE_VERSION` | Where the silos are. Losing it costs the list, not the data |
| Cache settings | `cache_settings.json` | **No version.** Plain JSON | One number, the local cache ceiling. Unreadable reads as the default, so there is nothing a version could save |
| Protected folders | `protected.json` | `SILO_FILE_VERSION` | Which folders on this computer the silo copies from. Absolute local paths, so they describe what someone keeps and where; kept beside the ledger of what has already been imported, and out of a folder that travels |

### `vault.db.enc.next`

Rotation writes the index under the new key beside the old one, commits the
keys, then renames. Those last two are separate filesystem operations, so a
machine that dies between them wakes with the new key in force and
`vault.db.enc` still under the old one. The shadow backup is under the old
key too, so both of the usual fallbacks fail and the silo does not open.

The staged file is the way out, which is why unlock knows about it: when the
primary snapshot will not decrypt, `open_database` tries `vault.db.enc.next`
before the shadow backup, and promotes it if it opens. It is tried under the
key in force and nothing else, so an abandoned rotation's leftovers under a
different key are not mistaken for the answer.

## The kind of a key

Every enrolled key carries a `kind`, in `keys/fido.json` and in the envelope
published to `keys/….env`. There are three values:

- `fido2`, with derivation `hmac-secret-v1`: a FIDO2 credential whose
  `hmac-secret` output derives the key that unwraps `wrapped_dek`. Windows
  Hello is one of these. An envelope written before the field existed reads
  as `fido2`, which is what it is.
- `secure-enclave`, with derivation `ecdh-p256-hkdf-sha256-v1`, for the
  macOS and iOS builds: a P-256 key in the device's Secure Enclave, gated on
  Touch ID or Face ID. The wrap key is the HKDF-SHA256 of a Diffie-Hellman
  agreement between that key and an ephemeral key made at enrolment, salted
  by the same per-vault string the FIDO2 path uses. The ephemeral public key
  has to reach unlock, so `credential_id` carries it: a 16-byte tag naming
  the key on that device, then the 65-byte uncompressed point, all hex.
  `public_key` is the device key's own uncompressed point. `platform` is
  true, as for Hello, and means the same thing: the key does not survive the
  device.
- `android-keystore`, with derivation `keystore-aes-256-gcm-v1`, for the
  Android build: an AES-256 key in the phone's Keystore (StrongBox where the
  phone has one) that allows one operation per strong biometric. The wrap key
  is 32 random bytes chosen at enrolment and encrypted under it with
  AES-256-GCM, associated data `silentsilo-dek-v1:{vault_id}`. `credential_id`
  is a 16-byte tag naming the Keystore key, the 12-byte nonce, then the
  48-byte ciphertext and tag, all hex; `public_key` is empty. Not the enclave's
  key agreement, because Android binds a single use of a key to a biometric
  only for ciphers, signatures and MACs, and every StrongBox chip does AES.

Core 1.1.0 wrote the ephemeral point into `public_key` of a `secure-enclave`
envelope. No release of any client carried that code, so no such envelope
exists in a user's bucket; nothing reads `public_key` to unlock either way.

Adding kinds changed nothing a 1.0.0 client does. It carries the envelope
verbatim, because `credential_id` and `wrapped_dek` are strings it never
looks inside, and it does not offer the key to its authenticator, because
`kind` is not one it knows. The byte vectors hold every envelope, and one
test runs the 1.0.0 vault code itself against them and against a
`keys/fido.json` it loads and saves back.

The field is not for this build. It is for the one that meets a key it has
never heard of, and that is not a hypothetical: a macOS build would enrol
Touch ID keys through the Secure Enclave, and a Linux one may use a TPM.
Neither derives anything a FIDO2 backend can produce, and every device on a
silo reads every other device's envelopes.

So the rule for anything reading these:

- **Publishing, listing and revoking go over every enrolled key.** A key this
  build cannot use is still a key on the silo. Retiring another platform's
  key because it looks unusable is how a household ends up with one device
  locked out.
- **Every device learns the others' keys and revocations** (core 1.3.0). Each
  sync pass, before it publishes, reads `keys/`: an envelope for a key this
  device has never had is added to its `keys/fido.json`, and a revocation
  marker `keys/revoked/<credential_id>.sealed` (JSON `version`,
  `credential_id`, `revoked_at`, sealed under the content KEK) turns a key
  this device still has into a tombstone, so it is not published again. A
  device that revokes writes the marker before it deletes the envelope, and
  drops its tombstone only once the marker is in storage. Three limits, each
  deliberate: an envelope is not authenticated, so a key added this way
  carries no organisation policy on a silo that has none; a silo with no
  keys file is never given one, because it opens with its device secret; and
  an organisation's key is not tombstoned on another device's say-so, since
  retiring one needs its proof. 1.0.0 skips the markers, so a 1.0.0 client
  neither sees keys enrolled after it joined nor honours a marker.
- **Turning the recovery code off leaves a marker too** (core 1.4.0), the
  same sealed JSON under `keys/revoked/recovery.sealed`, with
  `credential_id` `"recovery"` and `revoked_at` the time it was turned off.
  No key id can be `recovery`, since key ids are hex. Each pass drops a
  local or stored envelope created at or before it, so a device that still
  held the code does not publish it again; a code generated later is dated
  after the marker. Clients before 1.4.0 read it as a marker for a key they
  do not have and ignore it, so they can still put the old envelope back.
- **Unlocking goes over the keys of a kind this build knows.** That is
  `StoredFidoKeys::usable`, and it is what the authenticator allow-list, the
  "do you have a spare key" nudge and the last-key removal guard are all
  counted from. A credential id only has to be hex because a FIDO2 one is:
  built from every key instead, a single id in another platform's shape would
  fail the whole unlock on a machine whose own key is plugged in.
- **When nothing is left that this build can use, refuse by name.** Joining a
  silo whose only keys are of another kind says so, rather than asking for a
  security key that cannot exist.

Adding the field is only possible before the first public release. The
clients that have to skip an unknown kind are the ones already installed, and
they cannot be taught after the fact.

`kind` is also the version, and there is deliberately no second field beside
it. A key envelope is the one thing in the bucket with no file version, and
the fix for that is not to add one now: a version added today is a number
shipped clients do not check, so it would buy nothing that `kind` does not
already buy. If the shape of a `fido2` envelope ever has to change
incompatibly, ship it as a new kind. Every client from the first release
onward skips what it does not recognise and says so when nothing is left,
which is the behaviour a version field would have been for.

## Who administers a key

Beside `kind` and `derivation`, an enrolled key carries `policy`, in
`keys/fido.json` and in the published envelope. Empty is the ordinary case and
means the person holding the machine decides the key's fate. The one other
value is `org`: a key an organisation provisioned, which the machine's user
cannot retire and without which they cannot change the recovery code.

It is not a permission on the vault key. An `org` key unwraps the same DEK as
any other and unlocks exactly like it; the field constrains who may *administer*
the silo, never who may open it. That is why it needs no version of its own and
no discriminator: a build that ignored the field entirely would still open every
silo correctly, and would only be more permissive about administration.

The rules, all enforced in the backend rather than in the UI, because the
commands are reachable from anything that can call it:

- **Set only at the first enrolment.** `fido_enroll_primary` takes it; nothing
  else can turn an ordinary silo into an administered one. A key its holder
  cannot remove has to be part of what the silo was set up as, or the same
  feature becomes a way to take somebody's vault away from them.
- **Retiring one takes another in hand.** `fido_remove_key` runs a fresh
  assertion restricted to the silo's `org` keys and verifies the derived key
  actually unwraps one of their envelopes. The key being retired counts as
  proof of itself, which is what lets an organisation rotate its key and hand a
  silo over by retiring the last one.
- **The recovery code counts as a second door.** Regenerating or disabling it
  on an administered silo asks for the same proof. Guarding the key while
  leaving that open would protect nothing.
- **So does rotating the encryption key**, starting one and finishing an
  interrupted one alike. Rotation is retirement plus a fresh recovery code in
  a single operation, so without the same proof it would be a one-screen way
  around both rules above.
- **Adding another needs an existing one**, and only on a silo already
  administered.
- **Never hidden.** Every device lists the key with an Organisation badge.

The rules above are not enforced by each command remembering to ask. They are
enforced by `save_fido_keys`, which every write to the enrolled keys goes
through: it compares what is being written against what is on disk, and refuses
any write that leaves an administered silo with fewer organisation keys unless
the caller carries an `OrgProof`. That token exists only if its holder derived
the wrap key of an enrolled organisation key, checked by unwrapping the
envelope, so it cannot be fabricated by a caller that merely believes it is
entitled.

The shape is deliberate, and it is worth keeping. Rotation shipped without a
guard because the guard was something each command had to remember, and a
command that never asks is invisible to review: nothing in the rotation code
mentioned organisations at all. Now a new command cannot reach the file without
naming its authority, and naming `Machine` does not get it past the check. The
cost is that the rule lives away from the commands it constrains, which is why
it is written here.

Three writes are deliberately not proofs of anything, because they take nothing
away: a join or a recovery-code restore creating the file from what the bucket
holds, sync dropping tombstones storage has already confirmed, and enrolling or
renaming a key. The check lets them through on its own, by asking what changed
rather than who is calling.

`policy` defaults when absent, like its two neighbours and for the same reason:
an envelope assembled by something that does not write the field, the extraction
tool included, must read as an ordinary key rather than be refused. A silo that
will not load is the worst outcome this format has.

## The inbox

A device that cannot open the silo still adds to it: a phone backing up
photos in the background holds no key that opens anything. It seals each
item to the silo's inbox key and signs it, and an unlocked device imports it
later as an ordinary file. Added in core 1.2.0.

```text
inbox/keys/<key_id>.sealed        the inbox secret
inbox/senders/<sender_id>.sealed  a device allowed to send
inbox/items/<item_id>.sslo        the content, an ordinary blob
inbox/items/<item_id>.env         the signed envelope naming it
```

**Keys and senders** are sealed payloads under the content KEK, not the DEK.
The KEK never rotates, so a rotation by a client that has never heard of the
inbox cannot strand items waiting in it; 1.0.0's rotation re-seals `ops/`,
`snapshots/` and `keys/content.kek` and nothing else. Inside, JSON:

```json
{"version":1,"key_id":"…","secret_key":"<32 bytes hex>","created_at":1789000000}
{"version":1,"sender_id":"…","public_key":"<65 bytes hex>","credential_id":"…","label":"Galaxy S23 Ultra","created_at":1789000000}
```

`key_id` and `sender_id` must match the object's name. Several inbox keys may
exist; every item names the one it is sealed to. A sender's `public_key` is an
ECDSA P-256 key, and `credential_id` names the device key the sender belongs
to: the sender is accepted only while `keys/<credential_id>.env` is in
storage, so removing a device's key from the silo stops its sending too.

**An item** is the content as an ordinary `.sslo` blob, with the item id as
its file id and a fresh content key, and an envelope:

```json
{"version":1,"item_id":"…","blob_id":"…","key_id":"…","sent_at":1789000000,
 "blob_size":103,"ephemeral":"<65 bytes hex>","sealed":"<hex>","signature":"<64 bytes hex>"}
```

The envelope does not name its sender. The storage provider reads it, and
which device sent which photo is not the provider's to know; the importer
finds the sender by trying each registered sender's key.

The header both the seal and the signature cover is, at fixed widths and
big-endian: `silentsilo inbox item v1` and a zero byte, `item_id`, `blob_id`,
`key_id` and `sender_id` as 16 bytes each, `sent_at` as a signed 64-bit
integer, `blob_size` as an unsigned one, then the 65-byte ephemeral point.

- `sealed` is `nonce(12) || ciphertext || tag(16)`: AES-256-GCM with the header
  as associated data, under HKDF-SHA256 of the P-256 agreement between the
  ephemeral key and the inbox key, salt `silentsilo-inbox-v1:{vault_id}`, info
  `silentsilo inbox item key v1`.
- `signature` is raw `r || s` with `s` low, ECDSA P-256 over SHA-256 of the
  header followed by the sealed bytes.

The plaintext of `sealed` is JSON: `content_key` (hex), `name`, `mime_type`,
`size_bytes`, `content_hash` (BLAKE3 of the plaintext, hex), `taken_at`,
`folder` (one folder name per element, below the root) and `source`
(`photos` or `contacts`).

**Import** runs on an unlocked device, in an order that loses nothing when it
stops anywhere:

1. Check the envelope: its version, that its name matches `item_id`, a
   registered sender whose signature it carries, that sender's device key
   still in storage, and that the inbox key opens it. An item failing any of
   these stays where it is and is reported.
2. If the silo already has a file with id `item_id`, go to 5.
3. Check the `.sslo` is `blob_size` bytes and copy it to `blobs/<blob_id>.sslo`.
   A copy, not a move: stopping here leaves an unreferenced blob the sweep
   will collect, and the original still in the inbox.
4. Record an ordinary `AddFile` with `id = item_id`, its content key wrapped
   under the content KEK, and push it.
5. Delete the `.sslo`, then the envelope.

Nothing here is a new operation. What reaches `ops/` and `blobs/` is exactly
what an upload writes, so every client since 1.0.0 reads an imported photo
like any other file. Two devices importing the same item converge, because a
second `AddFile` with an id already present is obsolete in every version.

What 1.0.0 does with a store holding items, its orphan sweep and its key
rotation included, is checked by a test that runs 1.0.0's own code, and the
byte vectors hold one real item.

## Passkeys

A passkey lives in a password entry, as the optional `passkey` field of the
entry JSON that `UpsertPassword` carries whole (`silentsilo-fido/passkey.rs`):

```json
"passkey": {
  "version": 1,
  "rp_id": "example.com",
  "credential_id": "<base64url, no padding>",
  "user_handle": "<base64url>",
  "user_name": "alice",
  "user_display_name": "Alice",
  "algorithm": -7,
  "private_key": "<base64url of the 32-byte P-256 scalar>",
  "created_at": 1789000000000
}
```

The entry around it is a `login` whose `url` is `https://<rp_id>`; its
`password` may be empty. The signature counter is not stored: synced
passkeys answer 0, and a stored counter would make every sign-in a write
that conflicts across devices.

A field rather than an operation of its own, and the reason is 1.0.0's
compaction. A record type 1.0.0 does not know is stored and skipped, but its
snapshot leaves it out and its prune deletes it from the bucket, so a
passkey kept that way would be gone from storage the first time a 1.0.0
desktop compacted. A field it does not know rides inside the entry through
replay, snapshots and edits: both frontends save an entry by spreading the
loaded object, so fields they do not name are written back.

A reader offers only passkeys whose `version` it knows and leaves the others
in their entries. An older client shows the entry as a login.

## The index is not a format

Every table in `vault.db` except `vault_meta` and `oplog` is a cache of the
operation log. A version mismatch is resolved by dropping the derived tables
and replaying, never by migrating in place, which is what makes changing the
schema free.

That only holds while the log is complete on disk, and "complete" now means
one of two things. Either `oplog` holds the whole payload of every record this
device has seen, which is the state of every silo that has not been compacted,
or it holds every record above a horizon and the `vault_base` table holds the
state at it. A rebuild restores that snapshot first and replays what is left
on top.

The snapshot is therefore the one row in `vault.db` that a replay cannot
produce, since it stands in for the records a replay no longer has. It is a
real format, versioned, and it is why `snapshot::prune_to` never drops a
record the bucket has not confirmed: until a record is pushed, the log row is
its only copy.

Two consequences worth stating:

- Adding a `VaultOp` variant must bump `SCHEMA_VERSION`. The rebuild is what
  applies records an earlier build stored but could not act on.
- Adding a `VaultOp` variant must also decide `VaultOp::is_skippable`. The
  match is exhaustive, so it will not compile until someone does.

## The fixtures

`crates/silentsilo-fixture/fixtures/<version>/` holds a silo and its storage
as written by that release, plus the exact contents they should produce.
`cargo test -p silentsilo-fixture` rebuilds each one from storage using only a
recovery code and compares.

Each era has two fixtures, not one. `v<version>` holds the full operation
log; `v<version>-compacted` holds the same silo after compaction, a snapshot
in the store and the records below its horizon pruned. They must produce the
same tree, and they prove different halves of recovery: the plain one that a
whole log still replays, the compacted one that a snapshot still restores and
the tail still lands on top of it. Without the second, the snapshot format
has no golden bytes and a break in it passes every test.

A change that alters a fixture's output is a break. The fixture is the
released format; updating it to match new behaviour only hides the problem
from the people who will hit it.

The one exception, and it expires with this release: while nothing had
shipped, the formats iterated freely and the fixture was regenerated to match,
because no silo written by an older iteration existed outside this repository.
From 1.0.0 onward that reasoning is gone and the rule above is the whole
rule.

## Per-blob content keys

Content is not encrypted under the vault DEK. Each blob gets a key of its
own, and that key travels wrapped under the DEK inside the operation record
that names the blob, and inside the snapshot once compaction has replaced
those records.

The reason is rotation. Rotating the vault key has to make a revoked security
key stop reading the silo, and with content under the DEK that would mean
re-encrypting every byte: hours or days for a large archive, and impossible on
a target that refuses deletes. With a key per blob the ciphertext never moves.
Rotation re-wraps a few hundred bytes per file and re-seals the records, and
someone holding the old DEK can no longer open the current records, so they
cannot reach the content key, so the unchanged ciphertext is closed to them.

Where each key lives, and where it deliberately does not:

- `encrypt_file` and `decrypt_blob` take a `ContentKey`, never the
  `MasterDek`. The key is not in the `.sslo` file: a key inside the object it
  protects would have to be rewritten to rotate, which is the cost being
  avoided.
- `AddFile` and `ReplaceFileContent` carry `blob_key`, the wrapping.
- `files` carries a `blob_key` column, rebuilt from the log like the rest.
- `FileRow` in a snapshot carries `blob_key`. A snapshot stands in for the
  records it replaced, so without this the keys would be lost at the first
  compaction.
- A password attachment's key lives in the sealed entry, its only reference.

### The content KEK

Content keys are wrapped under a key of their own, `content.kek.enc` in the
silo folder and `keys/content.kek` in storage, itself sealed under the vault
DEK. Password entries are sealed under it too.

The reason is the log's hash chain. `OpRecord::fingerprint()` is a hash of the
whole record, so anything inside a record can never be rewritten without
changing its fingerprint, breaking the `prev` chain, and leaving this device
disagreeing with every other about the bytes of the same operation. Both the
wrapped content key and a sealed password entry live inside records.

So the values in records never change, and rotation touches one key instead.
It re-wraps the KEK under the new DEK and re-seals the objects in storage,
whose bodies stay byte for byte identical. Someone holding the old DEK can no
longer open the current records, so the wrapping inside is out of reach even
though it has not moved.

Every device shares one KEK, fetched from storage when joining. A device that
minted its own would write files none of the others could open, so a join with
no KEK in storage is refused rather than made to work.

A silo written before this does not open. That was acceptable exactly once,
for the reason above, and the rule at the top of this page is the whole rule
from here on.

Add a fixture when a release changes anything on this page:

```
cargo run -p silentsilo-fixture -- create crates/silentsilo-fixture/fixtures/v<version>
```

One per format era rather than one per tag. Ten releases that change nothing
here share one fixture, named for the release where that format first shipped;
ten copies of the same bytes would prove nothing and cost a review every time.

Old fixtures are never removed.

`v1.0.0` opens the era this page describes: per-blob content keys, the
content KEK, and password entries sealed under it. It is the first era with a
public release behind it, so it is also the first that can never be
regenerated.
