# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately to **security@silentsilo.com**. Please do
not open a public issue for anything that could be a vulnerability: anything
touching `silentsilo-crypto`, `silentsilo-vault`, key material, the FIDO2
flows, the recovery code, or what a silo writes to disk.

The same address covers
[silentsilo/desktop](https://github.com/silentsilo/desktop), where the
application, the updater and the OS integration live. Report to whichever
repository you found it in; it reaches the same person either way.

This is a one-person project, so reports are read by one person: the aim is
an acknowledgement within 72 hours, and you will get one as soon as I see it.
Please include steps to reproduce and the commit or release version you
tested against.

## Scope

This repository is the engine: the cryptography, the persisted formats, the
operation log, sync against storage the user controls, and the standalone
extraction tool. It has no user interface and opens no network connection of
its own except to the backup storage a client configures, which carries only
ciphertext plus one small manifest naming a random vault id.

The desktop application is in
[silentsilo/desktop](https://github.com/silentsilo/desktop) and has its own
policy covering the surfaces that live there: the updater, the breach check
and site icons in the credentials list. Report those there. Everything about
keys, envelopes, records, blobs and what a storage provider can see belongs
here.

The threat model, key hierarchy and on-disk formats are documented in
[`docs/CRYPTO.md`](docs/CRYPTO.md). That document is the reference for what
this project does and does not defend against.

One scope note about organisation-administered silos, since it is the one place
where a client enforces a rule against the person at the keyboard rather than
for them. A silo created that way carries keys its user cannot retire, and the
enforcement is in the client, not in the cryptography: those keys unwrap the
same vault key as any other, and someone editing the silo's files by hand or
running a modified build can clear the marking on their own disk. That is not a
vulnerability, it is the design. What actually holds is the copy the
organisation keeps on storage it owns. Reports that the marking can be bypassed
locally are welcome as documentation bugs if the docs overstate it, not as
security issues.

[`FORMATS.md`](FORMATS.md) lists every persisted format with its version and
what an older build does when it meets a newer one. A format change that could
leave a vault unopenable is treated as a security issue, not a compatibility
one: the data is unrecoverable by the person who owns it.

## Supported versions

Only the latest release receives fixes. Every release is free and complete,
so a security patch reaches everyone the same way.
