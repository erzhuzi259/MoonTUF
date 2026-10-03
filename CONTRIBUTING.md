# Contributing

Keep trust decisions deterministic and independent of HTTP or the filesystem.
Every changed security invariant needs a positive and negative test. Run
`moon fmt --check`,
`moon check --target all --deny-warn --warn-list '-implicit_impl_as_method-test_unqualified_package-unused_package'`,
`moon test --deny-warn --warn-list '-implicit_impl_as_method-test_unqualified_package-unused_package'`
and the offline example before proposing changes. The scoped warning baseline
matches CI; new warning categories must not be suppressed without justification.
Document new accepted TUF profiles and
unsupported cases in `docs/POUF.md`.

Submit only code and fixtures whose license and provenance can be recorded in
`THIRD_PARTY_NOTICES.md`. Do not add private keys, production signing material,
credentials, proprietary corpora, or copied reference implementation code.
Report security issues privately as described in `docs/SECURITY.md`.
