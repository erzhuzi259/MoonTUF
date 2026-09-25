# Third-party notices and specification sources

MoonTUF's implementation code is original and licensed under Apache-2.0.

Runtime dependency: `moonbitstack/mooncrypt` 0.3.1, Apache-2.0. It supplies
Ed25519 signature verification and SHA-256; MoonTUF does not reimplement
cryptographic primitives. Its transitive dependencies are `moonbitstack/moonbase`
0.4.0 and `moonbitstack/moondate` 0.1.0; their installed `moon.mod` files also
declare Apache-2.0. Recheck the license and dependency graph when refreshing
versions.

Upstream repositories: [mooncrypt](https://github.com/moonbitstack/mooncrypt),
[moonbase](https://github.com/moonbitstack/moonbase), and
[moondate](https://github.com/moonbitstack/moondate). Dependency source and
license files remain in the package manager's cache; they are not vendored
into this repository.

Protocol semantics were researched from [The Update Framework Specification
1.0.36](https://theupdateframework.github.io/specification/latest/) and its
[canonical JSON reference](https://wiki.laptop.org/go/Canonical_JSON). Reference
implementation and conformance tests are used as behavioral comparison only:
[python-tuf](https://github.com/theupdateframework/python-tuf) and
[tuf-conformance](https://github.com/theupdateframework/tuf-conformance).
No source files from those projects are copied into MoonTUF.

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
