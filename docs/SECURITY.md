# Security model and integration requirements

`open_trusted_root` assumes the caller authenticated the exact root bytes out
of band. A self-signed root is not a bootstrap proof. The deterministic
`testkit` signers and example keys are public; never provision them in a real
repository.

Use one trustworthy UTC time per refresh. Expired metadata must not be revived
by a backward clock jump. Persist accepted root and checkpoint state
atomically, protected against local rollback. A checkpoint SHA-256 is a
corruption detector, not an anti-tamper MAC.

Changing timestamp or snapshot signing authority in a dual-signed root update
resets their old rollback baselines so a recovered repository can escape a
fast-forward attack. The host must persist that root change before relying on
new online metadata. A root-only key change does not reset these baselines.
Direct staged calls must finish the root chain before accepting timestamp;
snapshot and targets acceptance also reject expired upstream metadata. The
fixed update time still governs all expiration checks within one cycle.

Fetchers must enforce byte limits before buffering, including when a server
omits or lies about Content-Length. The transport helper percent-encodes path
bytes, but hosts must still restrict redirects, origin changes, decompression
and cache behavior. Keep the exact bytes passed to `accept_*`; do not parse
and reserialize before length/hash checks.

`Client::refresh` distinguishes a confirmed missing N+1 root from a fetch
failure. Treat only an authoritative not-found response as `MetadataAbsent`;
timeouts, HTTP/server failures, redirect rejection and local storage errors
must be `MetadataFailure` so root probing cannot terminate silently.

Stage targets privately until `verify_download`, `TargetStream::finish`, or
the entire `BundleSession` succeeds. The host handles atomic multi-file
commit, rollback, permissions, and post-verification execution policy.

Choose budgets for each deployment; defaults are not universal guarantees.
Log `report.diagnose(error).to_json()` rather than raw attacker-controlled
metadata. The official upstream suite has run against the actual MoonBit
verifier; exact revisions, results and optional expected failures are in
[CONFORMANCE](CONFORMANCE.md). Passing tests is not a security audit or
independent certification. Report vulnerabilities through GitHub's private vulnerability
reporting channel at
[Report a vulnerability](https://github.com/erzhuzi259/MoonTUF/security/advisories/new).
Include the affected version, reproduction and impact. Do not disclose a
working exploit in a public issue.

0.2.0 adds RSA-PSS-SHA256, ECDSA P-256 and SHA-512. Key parsing checks
algorithms/curve identifiers and DER structure. RSA modulus/exponent bounds
limit verification work. Unsupported keys cannot contribute to a signature
threshold; supported but malformed key material is rejected. An invalid
individual signature contributes zero and cannot prevent other distinct valid
signatures from meeting a threshold. All recognized declared hashes must match.

MTUF2 restores partial state only against the caller's exact latest trusted
root. It is not an authenticated remote update bundle or protection against a
local attacker replacing both anchor and state. Delegated caches are reverified
against the current parent and snapshot. Root online-key recovery intentionally
resets appropriate online rollback baselines; the host must persist that change.

Batch resolution shares bytes, not authorization. Verify candidate bytes after
planning and stage the entire release before the host commits it. Mirror
fallback fixes one verified descriptor and never trusts a mirror's own metadata
or digest claims. Fetch callbacks enforce their supplied length budget while
reading; checking a buffer afterward cannot undo an unbounded allocation.
