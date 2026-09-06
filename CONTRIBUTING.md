# Contributing to SilentSilo core

Thanks for considering a contribution. This repository holds the engine: the
cryptography, the persisted formats, the operation log, sync against storage
the user controls, and the standalone extraction tool. There is no server
component and no user interface here. The desktop application lives in
[silentsilo/desktop](https://github.com/silentsilo/desktop).

## Contributor License Agreement

Contributions are accepted under the terms of [CLA.md](CLA.md). Opening a
pull request constitutes acceptance; you keep the copyright to your work.
Please read it once before your first PR. It is short and written to be
readable.

## Before opening a PR

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all --locked
cargo check --all --locked
```

This is what CI runs. If these pass locally, CI should too. Run them from the
workspace root: without `--all` the cargo commands silently skip crates, and
clippy reuses cached results, so a run that prints only `Finished` has
checked nothing.

## The rule that matters most

SilentSilo is an encrypted archive with an installed base. A silo that fails
to open after an update is unrecoverable by the person who owns it.

If your change touches anything in [`FORMATS.md`](FORMATS.md), read that page
first, then answer one question: what does a client on the previous release
do with the new bytes? Only two answers are acceptable, and they must be true
by test rather than by argument.

1. It ignores the new thing safely.
2. It refuses explicitly and tells the user to update.

Anything else means the change needs a version field first.

`cargo test --all` includes the compatibility fixtures, which rebuild a silo
written by a past release and compare what comes out. A fixture whose output
changes means released data no longer reads the same way; the fix goes in the
code, never in the fixture. Old fixtures are never removed.

Never add an in-place SQLite migration or an `ALTER TABLE` compatibility
patch. The derived tables are dropped and rebuilt from the local operation
log, which is what makes schema changes free.

## Making changes

- Keep PRs focused. A bug fix does not need an accompanying refactor.
- Read [`docs/CRYPTO.md`](docs/CRYPTO.md) before touching anything under
  `silentsilo-crypto` or `silentsilo-vault`. It is the source of truth for
  the key hierarchy and the on-disk formats.
- Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) before changing sync,
  the vault, the oplog or the blob lifecycle. Its "Looks wrong, is
  deliberate" section exists to stop a plausible fix from undoing a
  deliberate decision.
- Add or update tests for anything in `silentsilo-crypto`,
  `silentsilo-vault`, `silentsilo-vfs` or `silentsilo-sync`. These are the
  crates where a silent regression is most costly.
- Nothing here may depend on a user interface, on a client application, or on
  an OS integration crate. CI enforces that with the `no-ui-deps` job.
- Comments explain why, not what: an invariant, a workaround, a constraint
  the code cannot express. If the code needs a what comment, rewrite the
  code.

## Reporting security issues

Please do not open a public issue for a security vulnerability. See
[SECURITY.md](SECURITY.md).
