# ADR 0002: Clear online baselines only after authenticated authority rotation

Status: Accepted (2026-09-25)

After a root update MoonTUF blocks target use until the root chain is finished.
If the online signing-key sets are unchanged, accepted metadata and rollback
baselines remain valid; discarding them would make an ordinary root-key
change spuriously fail when timestamp has not advanced. If the trusted root
changes the timestamp or snapshot signing-key set, however, MoonTUF discards the
online metadata and both baselines. [TUF 1.0.36 §5.3.11](https://theupdateframework.github.io/specification/latest/)
requires this recovery path after possible fast-forward attacks. Only a root
successor signed under both old and new root thresholds can authorize the
reset, and no target is usable until a fresh four-role chain verifies.
