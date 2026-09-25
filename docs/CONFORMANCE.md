# Verification status and conformance gap

Local tests cover parsing limits, duplicate-key and numeric rejection,
Ed25519 thresholds, dual-signature root rotation, expiry and rollback,
metadata hash/length links, delegation order/limits, target bytes, checkpoint
restoration, update-cycle clock rollback, admission bundles, fail-closed
streaming, URL encoding and response metering.

```sh
moon fmt --check
moon check --deny-warn
moon test --deny-warn
moon build
moon run examples/offline
```

The configured repository CI repeats standard checks and example smoke tests
once pushed to GitHub; no remote run has occurred yet. A passing
local suite is **not** evidence that the upstream [TUF conformance suite](https://github.com/theupdateframework/tuf-conformance)
passes. That suite and independent security review remain future work. Do not
advertise MoonTUF as a certified or audited TUF client.
