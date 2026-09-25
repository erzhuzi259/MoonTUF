# MoonTUF interoperability profile

This records the implemented subset of TUF 1.0.36; it is not independent
certification. The normative source is [the TUF specification](https://theupdateframework.github.io/specification/latest/).

## Accepted metadata

- JSON `signed`/`signatures` envelopes; four top-level roles and delegated
  targets roles; `1.0.x` specification version.
- Ed25519 public keys and signatures in hex, SHA-256 hashes, canonical key
  IDs and signed payloads. Duplicate JSON keys and non-integer numbers fail.
- Strict UTC `YYYY-MM-DDTHH:MM:SSZ` expiry, nonnegative Int64 target lengths,
  resource limits, and safe relative target names.
- Sequential root rotation signed by both old and new root thresholds.
  Timestamp pins snapshot; snapshot pins targets and delegated metadata.
  Consistent-snapshot request names are supported.
- After authenticated timestamp or snapshot authority rotation, old online
  rollback baselines are cleared for fast-forward recovery; root-only rotation
  retains them. Target use is blocked until root-chain probing completes.
- Delegation order, terminating roles, path restrictions and visit limits;
  exact target length and hash verification in memory or by stream.

## Exclusions and host duties

No RSA/ECDSA, alternative target digests, signing/private key management,
repository server, automatic trusted clock, or built-in HTTP/storage backend.
The host authenticates the initial root out of band and protects locally
persisted trust state against rollback. Checkpoint SHA-256 detects accidental
corruption, not malicious replacement. The host caps reads, restricts
redirects, keeps a monotonic UTC cycle time, stages candidates privately and
atomically publishes only complete verified updates. MoonTUF does not execute
targets or judge their semantic safety.

Compare future releases with independent TUF conformance vectors before
production adoption.
