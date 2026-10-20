# Runtime v2 wire acceptance

Independent, fixture-only acceptance for the Linux sealed-memfd runtime entry.
The matrix is a test-only consumer: it does not edit production, start a
daemon/container, install a plugin, publish, or claim v2 host authority.

## Binding

- The candidate is the **current checkout** at `plugins/docker-runtime`. The
  runner refuses a dirty runtime source tree and computes a host-side SHA-256
  over the complete Python source set listed in `source-set.json`
  (`config.py`, `fixture_wire.py`, `observation.py`, `unix_http.py`). No
  candidate commit or source hash is committed; a fixed head must never make CI
  test an old snapshot.
- The fixture entry has no self-version. `source-set.json` carries an explicit
  host-owned version (`gateprobes-docker-runtime-fixture/1`) that the harness
  places in the expected binding. It is not self-declared by stdin.
- Core is checked out at
  `1d066cc624b8bf706c7973e2c91d81c75489ad1f` in the fixed
  `tests/runtime-v2-wire/core-pin` directory. `core.lock.json` records every
  tracked file in `tools/harness-gate/runtime-protocol`; `prepare-core.sh`
  verifies the exact commit, a clean tracked checkout, the complete tracked
  crate file set, and every file digest. `Cargo.toml` points only at that fixed
  checkout, so there is no unchecked path override.
- Rust dependencies are locked by `Cargo.lock` and run with `--locked`.

The harness links the real `gatehouse-runtime-protocol` crate and calls
`v2::parse_response` for every accepted response. It does not copy or reimplement
the parser.

## Run

```sh
cd tests/runtime-v2-wire
./scripts/run-acceptance.sh
```

For a local mirror or proxy, set `GATEHOUSE_REPO` and/or `PROXY_ENV`; the default
Core repository is the public pin recorded in `core.lock.json`. CI runs the same
script with an isolated `CARGO_TARGET_DIR`.

`prepare-core.sh` creates/updates `core-pin` (ignored by Git) and fails on any
tracked modification or crate-file drift. `run-acceptance.sh` runs the matrix and
requires exactly `24 passed; 0 failed; 0 ignored` (non-vacuous count and zero
skips).

## Matrix (24 tests)

- host spawns with `env_clear`, no application arguments beyond the script path,
  inert cwd `/`, bounded stdin, sealed memfd fd3=config and fd4=expected;
- missing fd3/fd4, unsealed fd3/fd4, regular-file fd, non-0600 memfd and extra
  live fd5 are rejected before connect;
- pread is independent of descriptor offset; oversized config/actual input is
  rejected;
- strict typed equality accepts byte-different but typed-equivalent actual input
  and rejects typed mismatch, unknown top-level fields and binding pin mismatch;
- config digest and every config-derived binding pin must match before connect;
- Capabilities is Inspect-only with null observations and zero connections;
- Remove is a static failure with empty stdout and zero connections;
- Inspect Present is wrapped in the full expected binding/operation and parsed by
  Core; a 404 is Unavailable (observations null), never Absent;
- an oversized Present result fails with empty stdout, so no partial protocol
  output is emitted.

`fake_docker.rs` is a disposable Unix-socket HTTP double. It never contacts a real
daemon and does not claim engine authenticity.

## CI

The Linux CI job checks out this repository at the actual PR commit, runs the
51 Python runtime adapter tests with count and zero-skip assertions, then runs
this matrix against the pinned Core checkout with `CARGO_TARGET_DIR` outside the
repository. The Core source is external test input, not a GateProbes production
dependency. A future harness or Core pin change must update the relevant lock
deliberately and rerun the matrix.

## Limits

Fixture-only presentation surface. No installed-artifact/bootstrap authority, no
real Docker/Podman compatibility, no Absent, no mutation, no persistence, no
namespace attestation. The fake observations are adapter assertions, not daemon
proof. PR127 and issue #62 are outside this harness.
