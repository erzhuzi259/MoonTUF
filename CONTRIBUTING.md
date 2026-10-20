# Contributing

Keep trust decisions deterministic and independent of HTTP or the filesystem.
Every changed security invariant needs a positive and negative test. Run
`moon fmt --check`,
`moon check --target all --deny-warn`,
`moon test --deny-warn`
and the examples before proposing changes. All warnings are fatal in CI.
For the affected Windows 20261016 toolchain use `tools/windows/moon.ps1`;
see `docs/WINDOWS_TOOLCHAIN.md`.
Document new accepted TUF profiles and
unsupported cases in `docs/POUF.md`.

Submit only code and fixtures whose license and provenance can be recorded in
`THIRD_PARTY_NOTICES.md`. Do not add private keys, production signing material,
credentials, proprietary corpora, or copied reference implementation code.
Report security issues privately as described in `docs/SECURITY.md`.
