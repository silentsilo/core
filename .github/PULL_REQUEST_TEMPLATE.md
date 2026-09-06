## What does this change?

## Why?

## Checklist

- [ ] I have read [`CLA.md`](../CLA.md) and accept it for this contribution.
      Opening this pull request is acceptance either way; ticking it says you
      read it first.
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --locked -- -D warnings`
- [ ] `cargo test --all --locked`
- [ ] `cargo check --all --locked`
- [ ] If this touches a storage backend: `scripts/test-local.ps1`, which runs
      the suites that skip themselves without a real bucket, share or SFTP
      account
- [ ] If this changes a persisted format (blob layout, `vault.db` encryption,
      envelope structure, operation-log records): the version constant is
      bumped, [`FORMATS.md`](../FORMATS.md) and
      [`docs/CRYPTO.md`](../docs/CRYPTO.md) are updated in this PR, and the
      answer to "what does a client on the previous release do with the new
      bytes" is written down and true by test
- [ ] The compatibility fixtures still pass unchanged. A fixture whose output
      changes is a break, not a fixture to update
- [ ] Tests added or updated for anything in `silentsilo-crypto`,
      `silentsilo-vault`, `silentsilo-vfs` or `silentsilo-sync`
