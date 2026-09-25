# ADR 0003: Resume incomplete refreshes under retained metadata pins

Status: Accepted (2026-09-26)

TUF treats an equal-version timestamp as unchanged, but a fetch failure after
accepting that timestamp can leave the snapshot or targets stage incomplete.
MoonTUF resumes only missing descendants under the original verified snapshot
pin, reuses a fresh retained snapshot when available, and checks expiration
before and after completion. This preserves the specification's equal-version
rule while allowing a transient transport failure to recover without requiring
the repository to publish a new timestamp; accepting replacement pins from an
equal-version timestamp would let one version identify different snapshots.
