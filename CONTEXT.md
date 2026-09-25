# MoonTUF domain context

MoonTUF has one bounded context: a client deciding whether proposed update
metadata and target bytes can advance an existing trusted state.

| Term | Meaning |
| --- | --- |
| Trusted root | Locally anchored root metadata that defines keys and thresholds for top-level roles. |
| Candidate root | A newly supplied root that may replace trusted root only after sequential old/new authorization. |
| Role | A named authority (`root`, `timestamp`, `snapshot`, `targets`, or delegated targets). |
| Metadata | Signed, versioned, expiring role document. |
| Signature threshold | Minimum number of distinct authorized key IDs that verify one metadata document. |
| Trusted state | The last accepted versions and metadata that protect the next update against rollback and mix-and-match. |
| Update start time | One caller-supplied instant fixed throughout a refresh, used for expiry decisions. |
| Target descriptor | Trusted metadata binding a target path to an exact length and hashes. |
| Candidate target | Bytes supplied by the host for verification against a trusted descriptor. |
| Rejection | Structured reason a proposed transition or target cannot be trusted. |
| Resource budget | Explicit maximum sizes and graph visits for untrusted inputs. |

The core decides trust; the host owns transport, persistence, installation,
clock sourcing and private keys. A verified target is only an authentic byte
sequence for a path, not a statement that it is safe to run.
