# Changelog

## 0.1.0 — local development

- Distinguished authoritative absence of the next root from a metadata fetch
  failure in the refresh loader; transport faults now stop root probing.
- Removed quadratic duplicate scans for untrusted signature and delegation
  identifiers; indexed declared-key lookup and threshold verification to
  bound work for large, attacker-controlled signature lists.
- Reject direct online-stage acceptance until the root chain is finished and
  each upstream metadata role remains fresh at the fixed update start time.
- Made interrupted refreshes resumable with the retained timestamp pins and
  expiry checks, even when the repository timestamp version is unchanged.
- Isolated public signed/custom JSON trees from verified metadata through
  recursive copies of mutable containers.
- Added delegated DFS, terminating-role and budget-overrun regressions; made
  offline scenario mismatches fail the process for CI smoke validation.
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
- Extended the CI plan with JavaScript backend tests and an offline smoke run
  after confirming 91/91 local JavaScript tests pass.

No GitHub release or Mooncakes publication has been made.
