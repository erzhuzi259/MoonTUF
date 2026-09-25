# Complexity and performance boundaries

The trust core processes metadata as bounded in-memory JSON. For metadata of
size `M`, parsing and canonicalization require `O(M)` storage and roughly
`O(M + Σ k log k)` work where each object has `k` members to sort for canonical
signing bytes. Signature verification adds one Ed25519 operation per distinct
authorized signature inspected, bounded by role keys and metadata size.

Delegated target lookup visits at most the configured role budget (default
32, hard cap 64). Its ordered DFS uses an array for visited-role membership,
so the bookkeeping worst case is `O(V²)` over `V` visited roles, plus parsing
and signature verification for visited metadata. With this small cap, crypto
and metadata fetch usually dominate. If deployments need hundreds of roles,
the first change should be a bounded hash set and verified-role cache keyed
by trusted snapshot version, with explicit invalidation on refresh.

In-memory target verification hashes `B` bytes in `O(B)` time and retains
the caller's byte buffer. `TargetStream` hashes the same `B` bytes using
`O(1)` verifier state beyond the caller's chunk. A multi-file plan scans at
most `F` requested files (default 16, hard cap 1024) and currently uses
linear duplicate and installed-digest searches, giving `O(F²)` bookkeeping.
For the default small release bundle this avoids extra state; larger bundles
should use a bounded map after measurement. The trust checks remain unchanged.

No formal throughput benchmark or latency guarantee is claimed. Local Native
debug execution of the cryptographic demonstration was noticeably slower
than Native Release; CI therefore uses Release mode for Native tests and the
smoke example. A representative performance study should record compiler,
backend, CPU, metadata/key sizes, role count and target bytes before proposing
an algorithm or crypto-backend change.
