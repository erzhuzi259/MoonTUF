# Reproducible integration cases

Run `moon run examples/offline` from the repository root. It needs no network
and uses synthetic Ed25519 keys made from fixed public test seeds.

| Scenario | Trusted target | Host use |
| --- | --- | --- |
| Application | `apps/client.bin` | Self-updater staging a new binary |
| Plugin | `plugins/sample.wasm` | Extension marketplace or server plugin |
| Firmware | `firmware/router.img` | Device fleet update agent |
| Model | `models/weights.bin` | ML model refresh |
| Rules | `rules/policy.dat` | Policy/configuration distribution |
| Bundle | Two `plugins/*.bin` files | Atomic multi-artifact release |

Each single-target case constructs four-role metadata, refreshes trust,
evaluates a namespace/size policy, computes a consistent-snapshot request
name, verifies exact candidate bytes, recognizes an installed digest and
rejects modified content. The bundle case plans two files under one trusted
snapshot and releases streaming receipts only after both verify. The example
does not actually download or install anything.

For a real HTTPS host, `integrations/transport` converts trusted request names
to encoded URLs and meters response bytes. Transport success is not trust
success: feed the exact downloaded bytes through the client. For large files,
use `open_download_stream` or `open_bundle_session`; finish each stream and
atomically move staged files into place. Retry with a nondecreasing UTC time.

`RefreshOutcome::accepted()` lists successfully accepted metadata in order.
Each entry's `name()` is the actual repository request path, including a
version prefix for rotated roots and consistent snapshots. It is not a
mandatory local filename: the host chooses its storage layout, preserves its
previous trusted state until the new state is durable, and must not promote a
partially verified target bundle.
