# Verification status and conformance gap

Local tests cover parsing limits, duplicate-key and numeric rejection,
Ed25519 thresholds, dual-signature root rotation, expiry and rollback,
metadata hash/length links, delegation order/limits, target bytes, checkpoint
restoration, update-cycle clock rollback, admission bundles, fail-closed
streaming, URL encoding and response metering. The crypto boundary includes
an independent [RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1)
known-answer signature, and root tests cover the different rollback rules
for online-key rotation versus root-only rotation.
Staged acceptance tests also reject unfinished root chains and expired
timestamp/snapshot parents before accepting their child metadata.

```sh
moon fmt --check
moon check --target all --deny-warn --warn-list '-implicit_impl_as_method-test_unqualified_package-unused_package'
moon test --deny-warn --warn-list '-implicit_impl_as_method-test_unqualified_package-unused_package'
moon build
moon run examples/offline
```

The repository CI repeats standard checks and example smoke tests. The scoped
warning baseline matches the README and is not a warning-free claim. Release
CI evidence is recorded in `RELEASE_0.1.0.md`. The upstream TUF suite
requires an `init`/`refresh`/`download` HTTP-and-disk CLI adapter; MoonTUF's
transport-agnostic core has no such adapter yet. A passing
local suite is **not** evidence that the upstream [TUF conformance suite](https://github.com/theupdateframework/tuf-conformance)
passes. That suite and independent security review remain future work. Do not
advertise MoonTUF as a certified or audited TUF client.

The upstream CLI contract, Linux test invocation, licensing and an adapter
plan are recorded in [the conformance research note](../research/tuf-conformance-adapter.md).
No upstream fixture was copied and no upstream suite result is claimed.
