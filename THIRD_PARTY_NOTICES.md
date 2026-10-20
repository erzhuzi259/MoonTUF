# Third-party notices and specification sources

MoonTUF's implementation code is original and licensed under Apache-2.0.

Runtime dependency: `moonbitstack/mooncrypt` 0.3.1, Apache-2.0. It supplies
Ed25519, SHA-256/SHA-512, RSA public modular arithmetic and P-256 group
verification. MoonTUF adds original SPKI/PEM, DER ECDSA signature adaptation
and RFC 8017 RSA-PSS encoded-message verification (including MGF1-SHA256).
These adapters are not copied from another library. Its transitive dependencies are `moonbitstack/moonbase`
0.4.0 and `moonbitstack/moondate` 0.1.0; their installed `moon.mod` files also
declare Apache-2.0. Recheck the license and dependency graph when refreshing
versions.

Upstream repositories: [mooncrypt](https://github.com/moonbitstack/mooncrypt),
[moonbase](https://github.com/moonbitstack/moonbase), and
[moondate](https://github.com/moonbitstack/moondate). Dependency source and
license files remain in the package manager's cache; they are not vendored
into this repository.

Protocol semantics were researched from [The Update Framework Specification
1.0.37](https://theupdateframework.github.io/specification/latest/) and its
[canonical JSON reference](https://wiki.laptop.org/go/Canonical_JSON). Reference
implementation and conformance tests are used as behavioral comparison only:
[python-tuf](https://github.com/theupdateframework/python-tuf) and
[tuf-conformance](https://github.com/theupdateframework/tuf-conformance).
No source files from those projects are copied into MoonTUF.

Reference fixture generation uses pinned Python-TUF 7.0.1 (Apache-2.0 OR MIT),
securesystemslib 1.5.1 (MIT), and cryptography 50.0.2 (Apache-2.0 OR BSD-3-Clause).
They are development tools, not bundled runtime dependencies. The original
generator at `tools/reference/generate.py` signs independently chosen synthetic
metadata, verifies it through Python-TUF, and writes public data and original
test assertions. It never writes private RSA/EC keys. Generated files are
identified by name and excluded from handwritten source counts. Their fixtures
are original synthetic inputs/results, not copied reference test cases.
See the pinned [requirements](tools/reference/requirements.txt).

The official conformance action is MIT licensed and is referenced at commit
`1bc18916ee35f753b6eb8ee19dabb98449ca7326`. Its source is not redistributed here.
The HTTP/CLI adapter and bridge in `tools/conformance` / `tools/bridge` are
original code. The independently written Windows argv shim uses only platform
headers and does not redistribute Microsoft or MoonBit toolchain binaries.

Algorithm descriptions were also consulted in
[RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html),
[RFC 5480](https://www.rfc-editor.org/rfc/rfc5480.html), and
[TAP 15](https://github.com/theupdateframework/taps/blob/master/tap15.md).
No RFC/TAP implementation or prose is reproduced by these new adapters.

`testkit/fixture.mbt` creates synthetic metadata and signatures from fixed
public test seeds. The scenario bytes and fixture code are original to this
repository; no private or production signing material is included. Any later
imported vector must include its source and license here.

`crypto/crypto_test.mbt` includes the public Ed25519 TEST 1 key/signature
from [RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1),
used solely as a verification known-answer vector. It does not include the
private test seed.

RFC 8032's notice attributes copyright to the IETF Trust and its authors
(2017), under BCP 78 and the [IETF Trust Legal Provisions](https://trustee.ietf.org/documents/trust-legal-provisions/)
applicable at publication. Only the public key and signature data constants
are reproduced here, not the RFC's example implementation or prose. This
notice identifies the source terms and does not relicense the RFC itself.
The SHA-256 `abc` expected digest is a computed algorithm result; the test
and assertion code are original, with no external implementation copied.
