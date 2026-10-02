# ADR 0004: Distinguish root absence from fetch failure

Status: Accepted (2026-09-26)

TUF root probing normally stops when the next sequential root is absent, but
an I/O failure does not establish that absence. The earlier optional-byte
loader conflated these outcomes and could let a failed root fetch silently
complete the chain. The public refresh loader now returns present, absent, or
failed explicitly: only authoritative absence ends probing; failure preserves
verified partial state and reports a retryable error. This makes host adapters
slightly more verbose but keeps transport faults outside the trust decision.
