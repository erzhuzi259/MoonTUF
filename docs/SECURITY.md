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
metadata. No independent security audit or official TUF conformance run has
been completed. Before public release, establish a private vulnerability
reporting channel; do not disclose a working exploit in a public issue.
