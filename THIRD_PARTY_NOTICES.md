# Third-party notices and specification sources

MoonTUF's implementation code is original and licensed under Apache-2.0.

Runtime dependency: `moonbitstack/mooncrypt` 0.3.1, Apache-2.0. It supplies
Ed25519 signature verification and SHA-256; MoonTUF does not reimplement
cryptographic primitives. Its transitive dependencies are `moonbitstack/moonbase`
0.4.0 and `moonbitstack/moondate` 0.1.0. Their licenses should be verified again
when the dependency lock is refreshed.

Protocol semantics were researched from [The Update Framework Specification
1.0.36](https://theupdateframework.github.io/specification/latest/) and its
[canonical JSON reference](https://wiki.laptop.org/go/Canonical_JSON). Reference
implementation and conformance tests are used as behavioral comparison only:
[python-tuf](https://github.com/theupdateframework/python-tuf) and
[tuf-conformance](https://github.com/theupdateframework/tuf-conformance).
No source files from those projects are copied into MoonTUF.

Synthetic fixtures written for this project will be documented alongside the
tests. Any later imported vector must include its source and license here.
