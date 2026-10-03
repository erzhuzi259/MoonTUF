# MoonTUF

MoonTUF is an embeddable MoonBit verification core for [The Update Framework
(TUF)](https://theupdateframework.github.io/specification/latest/) metadata.
It lets an updater decide whether remote metadata and target bytes are trusted
without coupling that decision to HTTP, disk layout, installation, or private
key management. The same API serves application, plugin, firmware, model, rule,
and internal artifact updates.

Status: **local pre-release; not security-audited or independently certified as
TUF-conformant**. Do not use it as the sole authorization mechanism for
production updates yet. The repository is intentionally local until the
maintainer authorizes a GitHub push and Mooncakes publication.

October additions: bounded and paged inventories of verified top-level targets (not delegated targets), plus explicit distinction between an absent next root and a failed fetch during refresh. See [October features](docs/OCTOBER_FEATURES.md) for trust prerequisites, limits, and tests.

## What it verifies

- An out-of-band trusted root anchor; Ed25519 threshold signatures and
  sequential N+1 root rotation signed by both the old and new authorities,
  including online-key-rotation recovery from fast-forwarded versions.
- Timestamp, snapshot, and targets expiry, rollback, version pinning, and
  metadata length/SHA-256 chains. One fixed UTC time is supplied per cycle.
- Depth-first delegated targets (including terminating roles), path matching,
  bounded role visits, signed delegated metadata, and final target bytes.
- Exact target length and SHA-256, either in memory or through bounded
  incremental streams; checkpoint restoration tied to the trusted root.
- Resource ceilings for metadata, JSON nesting/nodes, root rotations,
  delegation visits, and target bytes; duplicate-key and non-integer rejection.

`integrations/admission` adds per-host namespace, role and size policy,
download tickets, multi-file plans and fail-closed streaming bundles.
`integrations/transport` constructs HTTPS request URLs, encodes untrusted path
bytes and meters response sizes; it never performs network I/O. `report`
exposes stable redacted diagnostic codes.

## Run locally

Install a recent MoonBit toolchain and run from this repository root:

```sh
moon update
moon check --deny-warn
moon test --deny-warn
moon run examples/offline
```

The example uses **deterministic public test keys only**. It exercises five
single-artifact scenarios and one atomic plugin bundle, including a rejected
tampered candidate. For native integration, use `moon run --target native
examples/offline` after native tools are configured. See
[`docs/INTEGRATION_CASES.md`](docs/INTEGRATION_CASES.md).

## Minimal host flow

```moonbit
let client = @client.open_trusted_root(
  authenticated_root_bytes,
  "2026-09-25T00:00:00Z",
).unwrap()
let outcome = client.refresh(fn(name) { host_load_metadata_response(name) })
// Only continue when outcome.status() is Complete.
let trusted = outcome.client()
let rules = @admission.policy(prefix="plugins", max_bytes=64L * 1024L * 1024L).unwrap()
let choice = @admission.evaluate(trusted, "plugins/widget.wasm", rules, host_load_metadata)
// Download a ticket's repository_name into temporary storage, verify bytes,
// then let the host atomically publish the candidate.
```

The root bytes must be authenticated **outside MoonTUF** (for example bundled
with an application or provisioned by a secure channel). Never bootstrap from
a root merely because it is self-signed. Persist the checkpoint and accepted
metadata atomically; protect it from local rollback. The host supplies a
trustworthy UTC clock, limits reads before allocation, handles retries and
redirects, stages files and commits a whole bundle atomically. A `VerifiedTarget`
does not mean the file is safe to execute. Full boundaries are in
[`docs/SECURITY.md`](docs/SECURITY.md).

The refresh loader returns `MetadataPresent(bytes)`, `MetadataAbsent`, or
`MetadataFailure`. Return `MetadataAbsent` for the next root only when the
repository has authoritatively reported that it does not exist (for example
an accepted 404 response). Timeouts, server errors and local read failures
must return `MetadataFailure`; they never finish root rotation.

## Interoperability profile and limitations

The first profile accepts JSON TUF 1.x metadata using Ed25519 signatures and
SHA-256. It does not implement RSA/ECDSA, other target hashes, repository
mirrors, download/install logic, private key handling, automatic trusted-clock
acquisition, or a general-purpose HTTP client. Some optional TUF extension
surfaces are not yet independently tested. See [`docs/POUF.md`](docs/POUF.md)
and [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md) before interoperability use.
Complexity and performance limits are recorded in
[`docs/PERFORMANCE.md`](docs/PERFORMANCE.md).

## Ecosystem value

`moonbit-community/proton_updater` specifies a shared update manifest schema,
but does not provide this four-role TUF trust progression. MoonEvidence handles
provenance evidence; moonseal and SBOM packages address related component and
compliance concerns. MoonTUF's reusable boundary is the time-evolving trust
decision for remote update metadata and exact artifact bytes, independent of
the artifact's type. The search, comparison and uncertainty are documented in
[`research/ecosystem.md`](research/ecosystem.md); new packages may emerge.

## Project and license

Module: `erzhuzi259/moontuf`. MoonBit is the implementation language.
Apache-2.0 applies to original code; cryptographic primitives are supplied by
`moonbitstack/mooncrypt` 0.3.1 (Apache-2.0). No reference TUF implementation
code was copied. See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
Contributions and security reports are described in [`CONTRIBUTING.md`](CONTRIBUTING.md).
Local build/test evidence and deliberately pending release gates are in
[`docs/VERIFICATION.md`](docs/VERIFICATION.md).

## 十月第二轮：受信清单差异与缓存同步计划

`Client::diff_top_level_inventory(previous, prefix?, max_results?, max_changes?)` 比较完整链中的顶层目标，仅按长度和 SHA-256 分类新增、删除与内容变化，不比较 custom；两个客户端各用其宿主提供的时间检查有效期。宿主须确认两者属于同一仓库；该报告不是更新授权或回滚验证的替代品。

`plan_top_level_sync(cached, prefix?, max_targets?, max_cached?)` 将当前受信目标与宿主实际测得的本地指纹比较，返回 current、missing、changed、orphaned。缓存重复路径、非法路径/长度/指纹及超预算报错；orphaned 仅是指定命名空间内提示，不执行删除。委托目标须走原有委托解析；下载仍须校验实际字节后安装。运行 `moon run examples/offline --target js`。详见 [本轮审查与复杂度](docs/SECOND_REVIEW.md) 和 [十月申报资料稿](十月项目申报书.md)。
