# MoonTUF

MoonTUF is a portable MoonBit client verification library for [The Update
Framework (TUF)](https://theupdateframework.github.io/specification/latest/).
It implements the necessary TUF client workflow: authenticated root rotation,
timestamp/snapshot/targets progression, delegated authorization, rollback and
expiry defenses, persistent accepted state, and exact artifact verification.
Applications, plugins, firmware, models and configuration packages share the
same interfaces; the host supplies transport, protected storage and installation.

**0.2.1 scope:** TUF 1.0.37 necessary client functionality, Ed25519,
RSA-PSS-SHA256, ECDSA P-256/SHA256, SHA-256/SHA-512, ordinary and succinct
delegations. The official upstream suite has passed **113 tests**, with six
expected failures limited to optional algorithm extensions. This is test
evidence, not independent security certification or a production security audit.
See [exact results and revisions](docs/CONFORMANCE.md).

- [Source](https://github.com/erzhuzi259/MoonTUF)
- [Mooncakes package](https://mooncakes.io/docs/erzhuzi259/moontuf)
- [Python-TUF comparison and scope](docs/REFERENCE_COMPARISON.md)
- [Complete runnable scenarios](docs/SCENARIOS.md)
- [Protocol profile](docs/POUF.md) and [security contract](docs/SECURITY.md)

## Install

```sh
moon add erzhuzi259/moontuf@0.2.1
```

Select subpackages in `moon.pkg`:

```moonbit
import {
  "erzhuzi259/moontuf/client",
  "erzhuzi259/moontuf/integrations/admission",
}
```

The library is MoonBit, with no Python/Node/native cryptographic binding.
The reference HTTP/disk conformance adapter uses Python and Node only as I/O
and execution hosts. Applications using the library do not need that adapter.

## Core capabilities

| Area | Delivered behavior |
| --- | --- |
| Root | Out-of-band anchor, sequential N+1 rotation under both old/new thresholds, final expiry and online-key recovery |
| Online roles | Signatures, fixed-cycle UTC expiry, version rollback, parent length/hash/version pins, consistent snapshots |
| Delegations | Ordered DFS, terminating roles, ancestor restrictions, repeated-role protection, shell path patterns, path-hash prefixes and TAP15 succinct bins |
| Algorithms | Ed25519, RSA-PSS-SHA256 (2048..8192-bit modulus), ECDSA P-256/SHA256; SHA-256 and SHA-512, every recognized supplied digest checked |
| Targets | Exact length/hash verification in memory or incremental streams; unverified bytes never become verified targets |
| Persistence | Anchored complete checkpoints and resumable partial accepted state with rollback history |
| Integration | Admission tickets, multi-file verification, top-level inventory/diff/cache plans, bounded HTTPS URL planning and diagnostic codes |

### Additional ecosystem capabilities

1. **Cross-delegation batch resolution** — `Client::resolve_plan` resolves an
   explicit deployment set, preserves order and role-chain evidence, records
   root/snapshot identity, and shares bounded metadata reads. Each target is
   independently authorized. A missing target fails the whole plan; this does
   not enumerate or implicitly authorize every delegated artifact.
2. **Verified mirror fallback** — `Client::download_from_mirrors` freezes one
   trusted target descriptor, tries host-approved mirrors with a bounded
   attempt list, and accepts only matching bytes. Missing, truncated and
   tampered responses cannot change the trusted hashes or metadata authority.

These support multi-publisher plugin releases, model/firmware distributions and
multi-region artifact delivery. Plans are not installation authorization for
unverified bytes, and mirror fallback is separate from optional `mirrors.json`.

## Run and verify

Validated with MoonBit **0.10.16**, `moon 20261016`:

```sh
moon update
moon fmt --check
moon check --target all --deny-warn
moon build --target all --deny-warn
moon test --target wasm-gc --deny-warn
moon test --target js --deny-warn
moon test --target native --release --deny-warn
moon run examples/offline
moon run examples/delegated_plan
moon run examples/verified_mirrors
```

On Windows, the 20261016 driver's extended paths can fail in its OCaml tools.
Use `./tools/windows/moon.ps1` in place of `moon` for these project commands;
the optional shim calls the installed official tools with normalized argv.
See [Windows setup and one-time core rebundling](docs/WINDOWS_TOOLCHAIN.md).
MSVC is required for this shim and Native builds. CI retains Windows coverage.

Examples use deterministic **public test keys**, assert accepted results and
rejected tampering, and must never supply production signing keys. The
delegated-plan example verifies two targets using one child-metadata fetch;
the mirror example rejects bad candidates before accepting exact trusted bytes.

## Host flow and trust boundaries

```moonbit
let initial = @client.open_trusted_root(authenticated_root_bytes, fixed_utc).unwrap()
let outcome = initial.refresh(host_load_metadata_response)
// Proceed only when outcome.status() is Complete.
let trusted = outcome.client()
let plan = trusted.resolve_plan(["plugins/editor.wasm", "plugins/theme.zip"], host_load_metadata)
// Resolve success is a plan. Verify every downloaded candidate before commit.
```

The host authenticates the initial root outside MoonTUF, supplies a trustworthy
clock, enforces read limits before buffering, and protects atomic state storage
against tampering/rollback. Metadata loaders distinguish authoritative absence
from transport failure. The host controls redirects, retries, temporary files,
installation transactions and execution policy. Authentic bytes can still be
unsafe application code. Full prerequisites are in [SECURITY](docs/SECURITY.md).

Optional repository-authoring/key services, signed mirrors metadata, RSA SHA384/
512, EC384/521, ML-DSA/TAP21 and arbitrary crypto registries are not implemented.
They are separated from necessary client requirements in the comparison table.
The claim is a complete necessary **client verification** scope, with explicit
resource limits, rather than every optional TUF extension or a server platform.

## Sources, maintenance and license

Apache-2.0. Protocol code and adapters are independently written. Cryptographic
group/hash operations use `moonbitstack/mooncrypt` 0.3.1 (Apache-2.0); MoonTUF
adds original TUF PEM/DER and RSA-PSS encoding verification adapters. Python-TUF
7.0.1 (MIT OR Apache-2.0) supplies behavioral comparison and generated synthetic
public fixtures, not runtime trust decisions or copied implementation code.
See [third-party provenance](THIRD_PARTY_NOTICES.md),
[complexity and limits](docs/PERFORMANCE.md), and
[contribution/security reporting](CONTRIBUTING.md).
