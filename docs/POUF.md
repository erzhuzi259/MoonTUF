# MoonTUF 0.2.0 protocol, operations, usage and format

The baseline is [TUF 1.0.37](https://theupdateframework.github.io/specification/v1.0.37/). The goal is the complete necessary **client verification workflow**, not just JSON signature validation. No independent security audit or certification is claimed. The optional authoring/server/mirrors-role surfaces are distinguished from client requirements in [the feature matrix](REFERENCE_COMPARISON.md).

## Wire and algorithms

- JSON signed/signatures envelopes with deterministic canonical signed bytes; raw envelope bytes are kept separately for parent hash/length checks. Unknown signed fields remain in the signed tree and original serialization.
- Ed25519 hex keys/signatures; RSA `rsassa-pss-sha256` SPKI PEM keys, at least 2048 and at most 8192 modulus bits; PSS uses MGF1-SHA256 and accepts digest-size or maximum-size salt. Exponents are odd, at least 3 and at most 2^31-1 to bound work.
- ECDSA `ecdsa-sha2-nistp256` SPKI PEM keys, DER signatures; curve/OID checks reject different curves, noncanonical integers, negative/zero/oversized r/s and trailing DER bytes. EC group arithmetic, SHA functions and Ed25519 come from mooncrypt; the TUF PEM/DER adapter and RSA-PSS encoded-message checks are original.
- SHA-256 and SHA-512 metadata/target hashes. All recognized supplied hashes must match. Unsupported-only hash sets fail closed. SHA-256 is preferred for consistent-snapshot target filenames when present, otherwise SHA-512. The legacy descriptor `sha256()` accessor returns an empty string if absent: use `hashes()` or `preferred_hash()` in generic consumers. Verified byte objects still expose their actually computed SHA-256.
- Positive bounded Int32 metadata versions, nonnegative Int64 target lengths, strict UTC expiry and caller-supplied fixed update time. Major version 1 is accepted with two or three numeric components (including historical `1.0`).
- Resource ceilings apply to raw metadata, JSON depth/nodes, target bytes, root rotations, delegated visits and batch/mirror requests. Limits are interoperability policy, not unlimited-size support.

## Trust progression

1. Bootstrap root is authenticated out of band. Sequential root N+1 is verified under both old and new root thresholds. Intermediate root expiry does not stop sequential recovery; final-root expiry does.
2. Timestamp, snapshot and targets follow signature, expiry, rollback and parent-pin checks. Timestamp-key or snapshot-key rotation discards online rollback baselines only after authenticated root rotation. Root-only rotation retains them.
3. Matching delegated metadata is checked against its immediate parent and snapshot. Ordered DFS, terminating roles, ancestor path restrictions, repeated-role handling, visit budgets, SHA-256 path-hash prefixes and TAP 15 succinct hash bins are implemented. Top-level targets is already visited and cannot be re-entered through a delegation; only child visits consume the delegated-role budget.
4. Shell wildcard `*`, `?`, bracket classes, ranges and negation operate on Unicode codepoints; wildcards do not cross `/`, following the specification's path-separator recommendation. Role names are opaque components (including `?`, `#`, `/` or `..`), never host filesystem paths; adapters percent-encode a whole metadata name. Target paths use a separate safe-relative-path policy.
5. Targets are exposed only after exact length and every supported declared digest match. Streaming callers keep temporary data private until `finish()` succeeds. Consistent snapshots prefix versions on metadata and a digest on the target basename.

## Storage, network and host contract

The portable runtime takes bounded byte loaders; no Python, Node, HTTP or filesystem is needed by library consumers. `tools/conformance/client.py` supplies a real bounded HTTP/disk adapter with a JS-compiled MoonBit bridge implementing the official init/refresh/download test protocol. The Python side never verifies signatures or decides trust. This adapter is also an integration reference, not a hardened generic downloader (redirect policy and production storage locking need host-specific work).

Root absence is distinct from transport failure. The adapter maps authoritative 404/403 to absence under its conformance repository policy; arbitrary network failures are never absence. Production adapters should only map responses that establish authoritative absence for their repository.

Complete checkpoints remain format MTUF1. The new MTUF2 local-state format retains partial accepted state and rollback baselines. `restore_state` requires the latest independently retained root bytes, checks cryptographic signatures and active parent pins, and preserves expired metadata only as rollback history. It is a **protected local store**, not a downloadable trust bundle. Its single authoritative file is saved atomically; ordinary role files are projections. Hosts protect it against replacement/rollback. The test adapter clamps its fixed update time to at least the protected prior cycle time; the library itself rejects explicit clock rollback.

`find_target_detail(on_verified~)` reports delegated bytes only after signature, version, length/hash and expiry checks, allowing safe persistent cache projection. Cached delegated bytes must be re-authorized under the current parent/snapshot when reused.

## Additional reusable capabilities

- `resolve_plan` resolves an explicit target set across delegated authorities, retaining order, role chains, repository names, root fingerprint and snapshot version. It shares bounded metadata bytes across lookups, but never skips each target's independent authorization. It is a planning record, not a replacement for byte verification.
- `download_from_mirrors` freezes one trusted descriptor before trying host-approved mirrors in order. Bad/missing candidates do not change metadata trust, hashes, versions or delegation order. It returns verified bytes only on exact match, records attempts, and performs no installation. It is distinct from optional signed `mirrors.json` metadata.

## Explicit exclusions

No optional mirrors-role parser, repository publishing/key-management service, RSA-PSS-SHA384/512, ECDSA P-384/P-521, ML-DSA/TAP21, arbitrary metadatum formats, custom hash registry, certificate PKI or package dependency solver is claimed. These do not weaken required-client checks or the three recommended interoperable signing schemes. No target execution/safety judgment, automatic trusted clock, installation, or production security audit is provided. See [conformance evidence](CONFORMANCE.md) for the exact tested revision and expected failures.
