# Verification and conformance evidence

## Actual upstream test execution

The official [tuf-conformance](https://github.com/theupdateframework/tuf-conformance) suite ran against **MoonTUF's actual MoonBit client** via the original pipe bridge and HTTP/disk adapter. The MoonBit core performs parsing, signature verification, trust transitions, delegation lookup and target-byte checks. The adapter does not delegate trust decisions to Python-TUF.

Passing development-branch run: [39387549863](https://github.com/erzhuzi259/MoonTUF/actions/runs/39387549863), source `5e5a73a`; result **113 passed, 6 expected failures** (173.09 seconds on that GitHub runner). The upstream action revision is pinned to `1bc18916ee35f753b6eb8ee19dabb98449ca7326`. Later final-release evidence is recorded by its actual CI runs, not inferred from this earlier run.

The six declared expected failures are optional algorithms outside the three recommended signing schemes:

- RSA-PSS SHA-384 and SHA-512: 2 parameter cases.
- ECDSA P-384: 1 case.
- ML-DSA-44/65/87 (TAP21): 3 cases.

No required-client case is marked expected failure. RSA-PSS SHA-256, ECDSA P-256 and Ed25519 tests actually pass. Expected-failure declarations are visible in `tools/conformance/client.xfails`, rather than being omitted from the test invocation. A suite pass is compatibility evidence for that suite/revision; it is not official certification or a security audit.

## Reproduction

On a host with current MoonBit, Python 3, Node 22 and the official suite's Linux dependencies:

```sh
moon update
moon fmt --check
moon check --target all --deny-warn
moon build --target all --deny-warn
moon test --target all --deny-warn
moon build tools/bridge --target js --release
chmod +x tools/conformance/client
# Run the pinned official action, or its pytest suite with:
pytest /path/to/tuf-conformance/tuf_conformance --entrypoint "$PWD/tools/conformance/client"
```

The upstream suite requires `faketime`; use the pinned GitHub action in `.github/workflows/conformance.yml` for the full environment. Windows toolchain 20261016 currently passes extended `\\?\` paths to OCaml tools that reject them. Use `./tools/windows/moon.ps1` in place of `moon` on this affected version; the wrapper invokes the installed official driver/compiler through an argv-only path normalizer, with no global environment change. Rebundle the core through the same path adapter after installation; see [Windows toolchain notes](WINDOWS_TOOLCHAIN.md). CI checks Windows as well as Linux.

## Independent reference and regression coverage

`tools/reference/generate.py` uses Python-TUF 7.0.1 and securesystemslib 1.5.1 to sign original synthetic repositories and verifies their role signatures/target hashes there before generating public MoonBit fixtures. No private keys or upstream test corpus are committed. Generated tests are clearly marked and excluded from handwritten LOC. Ordinary MoonBit tests use the committed fixtures with no Python dependency.

The MoonBit suite additionally checks malformed keys/signatures, duplicate identifiers, unsupported algorithms, expiry/rollback/mix-and-match, sequential root recovery, path/hash/bin delegations, parent authorization, raw metadata pins, exact and streamed target hashes, checkpoint/local-state trust boundaries, namespace admissions, bundle atomicity, metadata limits, mirror failure/verification and shared delegated resolution. Public APIs are tested with explicit package qualifications, and the old compiler warning suppression baseline has been removed.

New executable scenarios:

```sh
moon run examples/delegated_plan --target wasm-gc
moon run examples/verified_mirrors --target wasm-gc
moon run examples/offline --target wasm-gc
```

The fixtures use public deterministic test keys; they must not be used to authorize production updates. The offline scenarios include desktop/plugin, firmware, model, rule/configuration and atomic bundle workflows. Adapter HTTP, deployment filesystem semantics and production key custody require environment-specific review beyond these library tests.
