# Complexity and performance boundaries

The trust core processes metadata as bounded in-memory JSON. For metadata of
size `M`, parsing and canonicalization require `O(M)` storage and roughly
`O(M + Σ k log k)` work where each object has `k` members to sort for canonical
signing bytes. Signature verification adds one supported crypto operation per distinct
authorized signature inspected, bounded by role keys and metadata size.

Attacker-controlled signature IDs and delegated-role names are now copied,
sorted and scanned for duplicates. For `S` signatures and `R` delegated
roles, this changes duplicate detection from worst-case `O(S² + R²)` to
`O(S log S + R log R)` time and `O(S + R)` temporary space. Each metadata
document prepares one sorted key-ID index; role key references then use
`O(log K)` membership checks instead of scanning `K` declared keys. This
matters when a valid byte/node budget still permits thousands of small JSON
entries. The additional arrays are bounded by the same parsed metadata and
do not alter trusted role order or signature order.

Threshold verification also copies and sorts the authorized key IDs (`A`)
and available public keys (`K`) once, then probes each of `S` signatures by
binary search. Its non-cryptographic lookup cost changes from worst-case
`O(S(A + K + S))` to `O(A log A + K log K + S(log A + log K))`, with
`O(A + K)` temporary space. For a single signature and very large key sets,
the sorting can cost more than the former scan; the benefit is bounded
worst-case work when untrusted envelopes contain many signatures.

The public `Envelope::signed()` and `TargetFile::custom()` getters copy the
mutable JSON containers recursively. A returned tree of `N` nodes costs
`O(N)` time and space, with stack depth bounded by the parser's nesting limit.
Internal metadata parsing reads the private tree directly. Hosts should reuse
their detached policy view within an operation when repeatedly inspecting a
large custom object.

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

## 0.2.0 additions

Shell path matching uses rolling dynamic programming over pattern tokens and
Unicode target codepoints: O(P*T + P²) time, O(T + P) memory, including class
token scans. Unterminated `[` is classified once per token, rather than
rescanning the suffix for each target position. Patterns/paths are bounded to
1024/4096 UTF-8 bytes. `*`, `?` and classes cannot consume `/`. This removes
exponential wildcard backtracking while retaining ordered path semantics.

Succinct delegation computes SHA-256 and directly extracts 1..32 leading bits:
O(T) hashing time and O(1) bin bookkeeping. Even 32-bit bins do not allocate
2^32 roles. The selected role still undergoes snapshot pin/signature checks.

RSA verification cost depends on modulus bit length b and public exponent e:
modular exponentiation uses roughly O(log(e)) modular multiplications, each
using the dependency's BigInt arithmetic. Supported b is 2048..8192, e is odd
and at most 2^31-1. PSS decoding/hash work is linear in the encoded-message
length; the adapter does not claim constant-time secret operations because
this is public-key verification, with no signing/private-key API. Multiple
declared supported hashes cause two linear digest passes or two streaming
contexts. No performance parity with optimized native Python crypto is claimed.

`resolve_plan` bounds target count F (default 256, hard cap 1024) and unique
metadata fetch count D (default 32, hard cap 64). Hash maps give expected O(F)
duplicate validation and O(F*V) cache lookups for V visited roles per target,
plus repeated per-target parsing/signature authorization. Hash collision worst
cases may increase map work; explicit counts still bound it. Shared
metadata is fetched at most D times and retained in O(D*M) bytes under the
metadata limit M; output is O(F*V) role evidence. Caching verified authority
without a parent/snapshot key would be unsafe. This design saves loader calls,
not every cryptographic operation; two targets in one role assert one fetch.

Mirror fallback resolves once and checks at most N mirrors (default 8, hard
cap 32). Hash-map identifier validation is expected O(N); byte verification is
O(N*B), with one candidate buffer plus the returned verified buffer rather
than all mirror payloads. Hosts must bound reads before returning B-byte
buffers. Rejected buffers are not retained. This is deterministic bounded
fallback, with no concurrent requests, bandwidth or latency guarantee.
