---
name: Bug report
about: Something isn't working the way it should
title: ""
labels: bug
---

**Describe the bug**
A clear description of what's wrong.

**To reproduce**
Steps to reproduce the behavior.

**Expected behavior**
What you expected to happen instead.

**Environment**
- OS + version:
- Core version / commit:
- SilentSilo version, if you reached this through the app:
- Security key model (if relevant):

If the problem is with the desktop application (a screen, a button, the
installer, the updater), report it in
[silentsilo/desktop](https://github.com/silentsilo/desktop/issues) instead.
This repository is the engine: formats, cryptography, sync and the extraction
tool.

**Logs**
Any relevant output from `cargo test`, or from the extraction tool run with
its output visible.

**Security-sensitive?**
If this could be a security vulnerability (e.g. anything touching
`silentsilo-crypto`, `silentsilo-vault`, or key material), please don't file
it here. See [`SECURITY.md`](../../SECURITY.md) instead.
