# SilentSilo core

The engine behind [SilentSilo](https://github.com/silentsilo/desktop): the
cryptography, the persisted formats, the operation log, sync against storage
the user controls, and the standalone extraction tool. AGPL-3.0.

Nothing here knows about a user interface. The desktop application lives in
[silentsilo/desktop](https://github.com/silentsilo/desktop) and pins a tag
from this repository. Mobile clients will do the same.

> **No independent security audit has been done.** Nobody outside this
> project has been paid to attack it. The cryptography is specified in
> [`docs/CRYPTO.md`](docs/CRYPTO.md), the formats in
> [`FORMATS.md`](FORMATS.md), and all of this is readable here. That makes
> the design reviewable; it is not the same as an audit, and a serious flaw
> could sit in code that looks right and passes its tests.

## Crates

| Crate | Role |
|-------|------|
| `silentsilo-core` | Shared types and errors |
| `silentsilo-crypto` | AES-GCM streaming, envelope encryption, blob format |
| `silentsilo-vault` | Silo provisioning, keys on disk, `vault.db` encrypted at rest |
| `silentsilo-vfs` | Operation log, folder and file tree, name resolution, snapshots |
| `silentsilo-sync` | Bucket layout and the transport half of a sync pass |
| `silentsilo-store` | Backup storage: bucket, folder, WebDAV or SFTP |
| `silentsilo-s3` | S3-compatible object storage client |
| `silentsilo-fido` | FIDO2 security keys and Windows Hello |
| `silentsilo-extract` | Standalone recovery binary, no interface, no hardware key |
| `silentsilo-fixture` | Format compatibility corpus |
| `silentsilo-testkit` | Dev-only: hostile conditions, skip detector |

## Recovering a silo without this project

`silentsilo-extract` is the answer to "what if the project disappears". It
takes a silo folder or a bucket and a recovery code, and writes out the
files, the trash to one side, the passwords as CSV and the attachments. No
interface, no security key, one source that builds on Windows, Linux and
macOS.

Binaries for all three are attached to each release here, signed with the
same minisign key the updater checks. The public half is in
[`SIGNING-PUBKEY.txt`](SIGNING-PUBKEY.txt).

## Dev

```bash
cargo test --all
```

### Integration tests

The sync and storage tests run against real servers, and skip themselves
unless one is configured. `scripts/test-local.ps1` brings up MinIO, WebDAV
and SFTP in containers, points the tests at them, and runs the whole CI
sequence:

```bash
./scripts/test-local.ps1
```

It sets `SILENTSILO_TEST_REQUIRE_BACKENDS`, which turns a suite that skips
itself into a failure: asking for those tests and getting a silent pass is
how they went a development cycle without running. `-Stop` takes the
containers down again.

To point the tests at a server you already have, set the endpoint yourself:

```bash
SILENTSILO_TEST_S3_ENDPOINT=http://127.0.0.1:9000 cargo test -p silentsilo-s3 -p silentsilo-sync
```

### Compatibility fixtures

`cargo test -p silentsilo-fixture` rebuilds a silo written by a past release
from its storage, using only a recovery code, and compares what comes out. A
fixture whose output changes means released data no longer reads the same
way. The fix goes in the code, never in the fixture.

### A note for Windows

The fixture corpus has file names long enough that a clone into a deeply
nested directory can hit the 260-character path limit. If `git clone` reports
"Filename too long", enable long paths once:

```bash
git config --global core.longpaths true
```

## Docs

Persisted formats, their versions, and what an older build does when it meets
a newer one: [`FORMATS.md`](FORMATS.md)

Cryptography specification: [`docs/CRYPTO.md`](docs/CRYPTO.md)

How the pieces fit and which invariants a change must preserve:
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
