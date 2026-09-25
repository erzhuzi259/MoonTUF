# MoonTUF domain context

MoonTUF has one bounded context: deciding whether proposed update metadata
and target bytes can advance an existing trusted state.

## Language

**Trusted root**: Locally anchored metadata defining the top-level role
authorities. _Avoid_: self-signed root, downloaded root.

**Candidate root**: A proposed successor to the trusted root, accepted only
through sequential old- and new-authority approval.

**Role**: A named authority for root, timestamp, snapshot, targets, or
delegated targets metadata.

**Signature threshold**: Minimum number of distinct authorized key IDs whose
valid signatures are required for a role.

**Trusted state**: Accepted metadata and history that determine whether a
later update may be trusted.

**Rollback baseline**: Last accepted metadata versions retained for rollback
checks across update cycles. An authenticated change to the timestamp or
snapshot signing-key set discards both online baselines to permit recovery
from a fast-forward attack.

**Update start time**: One caller-supplied instant fixed for a complete update
cycle's expiry decisions.

**Target descriptor**: Trusted metadata binding one target path to expected
length and digest.

**Candidate target**: Bytes supplied by the host for comparison with a
trusted target descriptor.

**Verified target**: A candidate whose exact bytes match a trusted descriptor;
this says nothing about whether execution or installation is safe.
