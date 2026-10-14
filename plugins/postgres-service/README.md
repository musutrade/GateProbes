# Postgres service plugin

Candidate `gateprobes-postgres` 0.1.0; MIT (see [LICENSE](LICENSE)). GateProbes owns
Postgres URL parsing, test-database isolation, external health, container recipes,
ecosystem templates and legacy conversion. Core owns execution, requiredness,
service lifecycle/cleanup and final blocking. Engineering Policy thresholds,
baseline/debt/ratchet, measurement series and release authority are unchanged.

## Installation and compatibility

Linux x86_64 is the current acceptance scope. This candidate is not published.
The future independently verified archive is
`gateprobes-postgres-0.1.0-linux-amd64.tar.gz`, tag `postgres-service-v0.1.0`.
Verify its exact-tag GateProbes `collector-release.yml` Sigstore identity,
checksums and provenance using the [shared release procedure](../../docs/independent-releases.md)
before extracting. Keep the executable at an absolute stable path. The archive
includes license, identity, protocol, catalog/setup resources and precompiled
program; it does not bundle Rust, Python, Docker or Postgres client tools.

Requires a compatible Core exposing `service_checks` / `gate-service-check/v1`.
Released v0.4.9 is incompatible and its pin remains unchanged. Hosted contract
and package acceptance must fail until an independently verified compatible
released Core is explicitly pinned; no locally compiled Core is substituted by
release tooling. Local candidate evidence is separate from released compatibility.

For source development: Rust >=1.88, `cargo build --locked --release` and
`cargo test --locked`. External URL health requires `pg_isready` on PATH. Managed
containers use a locally prepared Docker/Podman image and explicit health recipe;
images/dependencies are not installed automatically. Python 3 is only a setup,
test and packaging dependency; the installed check and migration command are Rust.

## Required installed binding

Run the installed program, not a source-tree wrapper:

```bash
/opt/gateprobes/gateprobes-postgres --version
/opt/gateprobes/gateprobes-postgres migrate --input legacy.flow.toml \
  --output flow.migrated.toml --project my-project
harness-gate --project-root /path/to/project config check
```

Adopt the reviewed migrated file at the configured Core flow path before config
check. Migration retains input, refuses overwrite (including symlinks), and binds
its own absolute executable path, SHA-256, version and protocol. It supports the
legacy v1 database recipe and v2 `external_value_policy`; it preserves existing
steps, required-step policy and separate quality config, and makes the service
Doctor check required. Unknown legacy policies fail. Do not remove the old policy
field alone or replace required checks with an empty list. Existing generic v2
bindings are retained; replacing/upgrading a binding requires explicit review of
its executable, digest and version.

The binding forwards only `DATABASE_URL`, `HARNESS_GATE_ALLOW_REMOTE_TEST_DATABASE`,
`PATH` and `SYSTEMROOT`. Core injects `GATE_CHECK_PROTOCOL`, `GATE_CHECK_MODE`
(`external`/`managed`) and external `GATE_CHECK_VALUE` in a cleared environment.
No URL/password appears in argv or emitted diagnostics. External URLs require
postgres/postgresql, `_test` or `-test` database suffix, loopback unless explicitly
opted into remote test use, and a target distinct from production `DATABASE_URL`.
`pg_isready` receives the URL through `PGDATABASE`; failure/missing tool blocks.
The JSON result pins protocol/plugin/version/mode and success. Managed mode
acknowledges plugin identity while Core executes the recipe's container healthcheck.

The plugin-owned v1 recipe emits a Docker service, POSTGRES_USER/PASSWORD/DB,
loopback `{host_port}` connection and `pg_isready -U USER -d DB`; Docker/Podman
lifecycle and cleanup remain Core's responsibility. No daemon or user-owned
infrastructure is provisioned by migration or preset preparation.

## Current ecosystem preset

The original GateProbes catalog and packs remain migration snapshots. Generate
a new catalog with the installed artifact; all existing execution and quality
pack gates are retained:

```bash
python3 prepare-preset.py --binary /opt/gateprobes/gateprobes-postgres \
  --output /tmp/postgres-presets
harness-gate init --preset angular-rust-postgres \
  --presets-dir /tmp/postgres-presets --project-root /path/to/project
harness-gate config check --project-root /path/to/project
```

A source checkout uses `../../presets`; an installed archive includes those
resources. `--presets-dir` can select an explicit reviewed seed catalog. Output
must be new. Inspect `postgres-binding.json` and generated required checks before
adoption. The Core loader reads local files; it neither downloads plugins nor
falls back to the removed builtin policy.

## Upgrade, rollback and evidence

Independent upgrades do not rebuild Core: verify the new installed artifact and
explicitly rebind digest/version (or regenerate from retained legacy source),
then validate. Rollback restores the retained flow/catalog and its compatible
immutable Core/plugin artifacts together. Transition exits when active configs
use explicit required checks and a verified compatible released pair; it does
not leave a Postgres implementation in Core.

`contract.py --binary INSTALLED_PLUGIN --core-binary CORE --output REPORT` uses
fixed installed bytes for doctor/service-step/verify positive and negative cases,
secret omission and explicit upgrade rebind, asserting Core's digest is unchanged.
The deterministic `pg_isready` fixture proves orchestration and fail-closed behavior;
the contract also checks migration followed by offline Core import, retaining
required checks and every step while runtime authority remains blocked. The
package entry exercises this contract after extracting the archive and generates
an SBOM through the pinned Core tooling.

Local candidate acceptance on 2026-10-14 additionally passed the 43 service case
records with real `pg_isready` in an isolated `postgres:16-alpine` container
(`sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea`),
using `docker exec` with no published ports and removing the container afterward.
The release-profile candidate archive, extracted setup resources and all original
execution/quality pack gates passed local acceptance; its CycloneDX 1.5 SBOM
contains 62 components. The final installed contract has 44 records including
offline import. These are Linux candidate results. Hosted quality, compatible
released Core, signed publication and other client/platform paths remain pending.
