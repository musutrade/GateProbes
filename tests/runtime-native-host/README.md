# Native adapter / actual Core host acceptance (test-only)

This directory is test-only and unreleased. It builds the native adapter from
the current GateProbes checkout and runs it through the private Core
`runtime_host_v2` at the exact commit in `core.lock.json` using a disposable
fake Unix socket. There is no real daemon/container, no CLI, no installed
artifact authority and no release claim.

The Core pin is `b6ef961` (PR169 merge), not released Core `v0.6.0`
(`bbf65b4`). The patch `native_acceptance.patch` only appends a `#[cfg(test)]`
seam to `runtime_host_v2.rs`; it changes no production statement, Core
dependency, parser or host behavior. `prepare-core.sh` checks out the fixed
`tests/runtime-native-host/core-pin` path, verifies the clean full Git status,
the original file and Cargo.lock SHA-256, applies only the allowlisted patch,
and verifies the patched hash before the test.

`run-acceptance.sh` requires a clean native source tree, builds with
`--locked --release`, derives the binary SHA-256 after the build and the version
from `Cargo.toml`, applies the Core seam, runs exactly the named ignored test,
and asserts `1 passed / 0 failed / 0 ignored`. The fake server has bounded
read/write timeouts and the script has an outer timeout. On exit the Core
checkout is restored only if it still matches the verified patched hash;
unexpected changes are preserved for review.

Run locally:

```sh
GATEHOUSE_REPO=/path/to/GateHouse ./scripts/run-acceptance.sh
```

`GATEHOUSE_REPO` is an optional local mirror; the committed lock uses the public
repository. Set `PROXY_ENV` for network access if needed. `core-pin/` and
`target/` are ignored.

## CI

The required Linux `runtime-wire` job runs the existing 51 Python adapter tests
and 24-test wire acceptance, then native `fmt`/`clippy`, exactly 45 native tests
with zero skips, and the exact-count actual-host acceptance above. Every count
is asserted and an empty or skipped result fails the job. The native binary is
built from the PR checkout with `--locked`; Core remains the fixed `b6ef961`
test-only pin. No CI step publishes, registers, or contacts a real daemon.
