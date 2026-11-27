# compat

Crates that stand in for the versions the old core tags pin, so that
`silentsilo-fixture` can build those tags beside this build in one lockfile.
Nothing here ships: only the fixture's dev-dependencies reach them, through
`[patch.crates-io]` in the root `Cargo.toml`. That patch applies to this
workspace alone, so desktop and mobile never see it.

The old tags pin `rusqlite ^0.40`, which links SQLite through libsqlite3-sys
0.38, and cargo allows one crate with `links = "sqlite3"` per graph. Their
russh pins prereleases of `rsa`, `pkcs1` and `ssh-key` exactly. Without these
crates the whole workspace, the extractor included, would stay on SQLCipher
4.14 (RUSTSEC-2026-0459) and rsa 0.10.0-rc.18 (RUSTSEC-2023-0071).

- `rusqlite-0.40`: rusqlite 0.40.1 from crates.io, versioned 0.40.99, on
  `libsqlite3-sys = "0.40.0"` and `sqlite-wasm-rs = ">=0.6.3, <0.7.0"` (wasm
  only, but it carries a `links` key too). The old tags keep the 0.40 API;
  this build uses rusqlite 0.43, and both sit on the one libsqlite3-sys.
- `russh-0.62`: russh 0.62.7 from crates.io (v1.0.0, v1.6.1) with
  `rsa = "0.10"`, `pkcs1 = "0.8"`, `ssh-key = "0.7.0-rc.12"`, and one line in
  `src/keys/format/pkcs8.rs` taking `pkcs1::RsaPrivateKeyRef`, as russh
  0.65.4 does. `src/lib.rs` allows `deprecated`: rsa 0.10.0 deprecates the
  `RsaPrivateKey` alias it uses.
- `russh-0.63`: re-exports this build's russh under 0.63.99 (v1.10.0). The
  v1.10.0 code compiles against it unchanged.

Benches, examples, tests and dev-dependencies are removed from the two
vendored crates; their sources are otherwise as published. The fixture tests
never run SFTP, so the old russh is compiled, not used. `cargo audit` reads
registry crates only: these are local sources and are not audited, which is
why their advisories are not ignored in `.cargo/audit.toml`.

What the fixture no longer proves: the old tags run on this build's SQLite,
not the one they shipped with. `crates/silentsilo-fixture/working-copies/`
covers that: working copies an earlier SQLCipher wrote, opened by this one.

A tag made on rusqlite 0.43 and russh 0.65.4 or later needs nothing from
here. When this build moves to a newer libsqlite3-sys, `rusqlite-0.40` has
to move with it, or the two `links` collide again.
