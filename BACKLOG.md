# Backlog

What is knowingly left undone in the engine. Nothing here blocks a silo from
working; each entry says what breaks, and when. The desktop application keeps
its own list in
[silentsilo/desktop](https://github.com/silentsilo/desktop/blob/main/BACKLOG.md):
packaging, reproducible builds and dependency licences.

## Storage backends

`ObjectStore` is in place with four implementations (S3-compatible, a plain
folder, WebDAV and SFTP) and a contract suite that runs the same assertions
against every one of them. Nothing here is outstanding.

One thing SFTP deliberately does not support: an SSH agent. Keys are pasted
in and kept with the silo's other secrets, so a silo works the same on a
machine with no agent running and after the key file moves. Agent forwarding
would be a convenience for one kind of user and a second code path to keep
correct for everyone.

## Keys

### Rotation cannot reach a target that refuses overwrites

Rotating the vault key re-seals the objects in storage under the new key. On
a target that refuses to overwrite, an append-only bucket or one under object
lock, the old objects keep their old envelopes, so a revoked key still opens
the copies someone already holds. The rotation itself succeeds and every
device stays consistent, which makes this a limit worth stating rather than a
failure to handle. Which targets behave this way is in
[`docs/STORAGE.md`](https://github.com/silentsilo/desktop/blob/main/docs/STORAGE.md).

Nothing anywhere undoes the other half of it: what a person has already
copied stays copied.

## Recovery

### The extraction tool links libdbus on Linux

`silentsilo-extract` is the answer to "what if the project disappears", so the
machine it runs on is the one place to assume nothing is installed. It links
`silentsilo-vault`, which links `keyring`, which reaches D-Bus through
`dbus-secret-service` and `libdbus-sys`: the persistent Linux backend is
secret-service. The extractor never calls that code, but the binary needs
libdbus present to start, and a rescue system may not have it. Building it
also needs `libdbus-1-dev`, which is what the release workflow installs.
Making the keychain optional in `silentsilo-vault` is the fix; until then a
Linux recovery may need one package installed first.
