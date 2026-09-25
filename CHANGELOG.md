# Changelog

## 0.1.0 — local development

- Added bounded JSON TUF profile, Ed25519/SHA-256 verification and four-role
  trusted-state progression.
- Added root rotation, rollback/expiry enforcement, delegated target lookup,
  target streams, checkpoints and repeatable update cycles.
- Corrected authenticated online-key rotation to clear stale timestamp and
  snapshot rollback baselines for fast-forward recovery, while retaining them
  across root-only key changes; target use remains gated until the root chain
  is finished.
- Added an independent RFC 8032 Ed25519 verification vector and rotation
  regression tests.
- Preserved the actual repository request name in refresh results, including
  versioned root, snapshot, and targets metadata names.
- Added host admission policies, multi-artifact verification, URL planning,
  response metering, diagnostics, synthetic fixtures and runnable examples.
- Added local tests and continuous-integration configuration.

No GitHub release or Mooncakes publication has been made.
