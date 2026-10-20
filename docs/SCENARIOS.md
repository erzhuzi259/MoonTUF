# Reusable update workflows

The examples use original synthetic public test keys. They model integration workflows with bounded in-memory loaders and assertions, not deployed services or measured network throughput.

## 1. Plugins, extension bundles and multi-team artifacts

A platform owns root/timestamp/snapshot; a separate team owns delegated `apps/*.bin` targets. The application requests two plugin files. `resolve_plan` authorizes each path against the full delegation chain, retains input order and returns version/digest-prefixed repository names plus `targets -> team` evidence. Both files share the same delegated document: the example asserts **one metadata load for two files**. A missing, unauthorized or budget-exceeding file fails the whole plan. The plan does not authorize unverified target bytes; the application verifies each candidate and may use the existing admission bundle API to gate atomic installation.

```sh
moon run examples/delegated_plan --target wasm-gc
```

This applies to IDE plugins, desktop extensions, internal binary packages, configuration bundles and independently maintained model components. It reduces repeated metadata downloads while preserving per-file trust checks.

## 2. Models, rules and firmware behind multiple mirrors

The client first resolves one trusted `models/rules.bin` descriptor. Three host-approved sources are attempted: unavailable region A, corrupted region B and a healthy offline cache. `download_from_mirrors` accepts neither unavailability nor a matching filename as proof; it checks exact length and all supported declared digests, succeeds only on the third source and records the attempt outcomes. The all-invalid example returns no `VerifiedTarget`.

```sh
moon run examples/verified_mirrors --target wasm-gc
```

This applies to geographically distributed clients, constrained device gateways, package caches and air-gapped staging sources. Mirror choice never changes trusted versions, hashes or authorities. The host handles bounded HTTP/file reads and installation; there is no downgrade-to-unsigned fallback.

## 3. General application, device and configuration update trust

`examples/offline` exercises desktop application, plugin, firmware, model and rule/configuration candidates plus an atomic plugin bundle. Each runs a four-role chain, verifies target bytes, applies namespace/size/role policy and rejects a tampered candidate. These workflows are independent of artifact format. Streaming verification lets a host stage a large device image or model file without retaining the entire content in verifier memory.

```sh
moon run examples/offline --target wasm-gc
```

For a real HTTP-and-disk workflow, build `tools/bridge` and use the `tools/conformance/client` protocol. The actual official suite also covers sequential key rotations, expiry, replayed/rollback metadata, role removal, consistent snapshots and a static Sigstore repository. See [conformance evidence](CONFORMANCE.md) before making interoperability claims.

## Shared integration contract

Provision the initial root securely; keep one trustworthy update time; protect accepted state against local rollback; meter reads before allocation; verify exact bytes before publishing files. A trusted plan is not a signature over a deployment manifest, and verified bytes do not imply safe behavior. Multi-file filesystem transactions, role-specific application policy, production key custody and actual rollout execution belong to the host.
