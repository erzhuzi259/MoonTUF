# TUF 1.0.37 / Python-TUF comparison and delivery scope

## Positioning and reference

The review feedback asked MoonTUF to go beyond a JSON/Ed25519/SHA-256 subset. The 0.2.0 goal is a complete implementation of the necessary [TUF 1.0.37 client workflow](https://theupdateframework.github.io/specification/latest/), with explicit optional capabilities, matched against [Python-TUF 7.0.1](https://github.com/theupdateframework/python-tuf/tree/v7.0.1). Python-TUF is MIT OR Apache-2.0; the original MoonBit implementation is Apache-2.0. No reference implementation source was copied.

JSON is a documented wire format permitted by the specification, not a limitation to signature checks. The core value is the time-evolving trust state and verified artifact delivery across key rotations, metadata updates and delegated authorities.

| Capability | Python-TUF reference | MoonTUF 0.2.0 | Evidence / boundary |
| --- | --- | --- | --- |
| §5.1 fixed cycle time | Updater reference time | Caller fixed UTC instant, local monotonic-time policy | Expiry and clock regression tests |
| §5.2 trusted anchor | Out-of-band bootstrap bytes | Same external trust prerequisite, self-signature checks | Root/anchor replacement tests |
| §5.3 root progression | Sequential dual-authority verification | N+1 old/new thresholds; expiry of final root; authenticated online-key recovery | Core rotation and upstream key-rotation tests |
| §5.4 timestamp | Signature, version, snapshot pin, expiry | Same necessary checks, retained equal-version pins and interrupted-refresh recovery | Upstream rollback/expiry tests |
| §5.5 snapshot | Pin and metadata rollback checks | Exact supported hashes/length/version; every prior target role retained at nondecreasing version | Mix-and-match, role-removal, rollback tests |
| §5.6 targets | Pin, signatures, expiry | Same necessary checks, retain exact signed/raw bytes separately | Upstream metadata/target tests |
| §5.7 target and delegations | Ordered DFS, terminating roles, parent restrictions | Same checks; visited-role/metadata budgets, ancestor path rules, target length/digests | Official delegation graph and download cases |
| Signature schemes | Extensible securesystemslib backend | Ed25519, RSA-PSS-SHA256, ECDSA P-256/SHA256 | All three official keytype cases pass; PEM, DER and real reference vectors |
| Hash algorithms | Extensible hash registry | SHA-256 and SHA-512, all recognized supplied digests verified | Full SHA512-only chains and streamed target fixtures |
| Path restrictions | Shell pathname matching and path hashes | Unicode `*`, `?`, classes/ranges/negation; wildcards exclude `/`; SHA256 prefixes | Pattern boundary tests and upstream graph cases |
| Consistent snapshots | Version-prefixed metadata and digest-prefixed targets | Both names, deterministic supported-hash choice | Official consistent-snapshot cases |
| Special role names | Whole-name URL encoding and safe local cache mapping | Opaque role names including `?`, `#`, leading `/`/`..`; encoded cache filenames in adapter | Four official quoting cases |
| TAP15 succinct roles | Hash-bin support | 1..32-bit direct bin selection without allocating all bins | Model and end-to-end targeted regression |
| Unknown signed fields | Preserve in signed content | Detached AST + original envelope; canonical verification includes extra fields | Metadata roundtrip and static Sigstore repository |
| HTTP/storage updater | Fetcher interface and production ngclient | Portable byte-loader core, plus original real HTTP/disk conformance adapter | Official init/refresh/download execution; production redirects/locking host-owned |
| Persistence | Accepted metadata and local rollback history | MTUF1 complete checkpoint; MTUF2 partial-state/baseline store | Anchored restore, expiry and interrupted-refresh tests |
| Batch deployment planning | Individual target info APIs | **Additional** `resolve_plan`: explicit set, role-chain evidence, root/snapshot identity and shared bounded metadata loads | Plugin bundle example; no blanket enumeration of delegated roles |
| Multiple artifact mirrors | Host/fetcher integration | **Additional** `download_from_mirrors`: one pinned descriptor, bounded ordered attempts, exact verified bytes only | Corrupt/short/unavailable mirror tests and runnable example |
| Repository authoring / signing service | Metadata API and signer adapters | No private-key service or general repository manager in this client library | Explicit host/producer responsibility |
| Optional mirrors role | Not a portable deployment requirement | No signed `mirrors.json` parser; host-approved mirror list is separate | Excluded rather than silently claimed |
| Optional algorithm/TAP extensions | Depends on reference crypto backend | RSA SHA384/512, EC384/521, ML-DSA/TAP21 not implemented | Six upstream optional cases declared xfail, no required-client exclusions |

## Concrete completed deliverables

1. Portable MoonBit client/model/trust/crypto/wire packages implementing the necessary workflow and three interoperable signature schemes, with resource and trust boundaries documented in [POUF](POUF.md).
2. A real adapter that allows the official suite to operate against MoonBit; Python is only I/O and is not a hidden verifier. Actual result and optional expected failures are in [conformance evidence](CONFORMANCE.md).
3. Cross-delegation batch plans and exact-byte mirror fallback, with [complete use cases](SCENARIOS.md), assertions and tests.
4. Source, API, examples, licenses, continuous integration, tracked development and package release. A complete repository-signing platform or production security certification is not part of this claim.

Future optional algorithms, signing/backend services and additional TAPs are independent follow-up work. Applications remain responsible for anchor provisioning, a trustworthy clock, bounded transport, protected atomic storage, installation and whether authentic code is safe to execute.
