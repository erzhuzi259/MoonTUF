# MoonTUF

MoonTUF is a MoonBit library for verifying software-update trust metadata. It
implements a bounded, embeddable TUF 1.x client core: the host supplies metadata,
time, target bytes, and persistence, while MoonTUF decides which metadata and
artifacts can be trusted. This repository is under development and is **not yet
released or security-audited**.

The same verification core can protect application self-updaters, package and
plugin managers, firmware distribution, model and rule bundle updates, and
internal artifact repositories. It does not download, install, or execute files.

The v1 interoperability profile targets JSON metadata, Ed25519 signatures and
SHA-256 hashes. Its four top-level roles are root, timestamp, snapshot and
targets. Planned checks include threshold signatures, sequential root rotation,
expiry and rollback resistance, length/hash chains, delegated target lookup,
and final artifact verification. Resource budgets are part of the API.

## Status and safety

This is a new local project. The API, examples and tests will be filled in over
verified development milestones. Do not use it to authorize production updates
until independent interoperability testing and a security review are complete.

The project will remain local until its maintainer separately authorizes GitHub
push and Mooncakes publication.

## Related MoonBit packages

`moonbit-community/proton_updater` defines a shared update manifest schema, not
the TUF four-role trust state machine. MoonEvidence handles provenance evidence
packages; moonseal and SBOM packages address components and license/compliance.
MoonTUF addresses *which remote update metadata and target bytes a client may
trust over time*. The ecosystem comparison and its search limitations are in
`research/ecosystem.md`.

## Sources and license

The implementation follows the public [TUF 1.0.36 specification](https://theupdateframework.github.io/specification/latest/)
without copying reference implementation code. Original project code is
licensed under Apache-2.0. Third-party dependencies and test-vector provenance
will be recorded in `THIRD_PARTY_NOTICES.md`.
