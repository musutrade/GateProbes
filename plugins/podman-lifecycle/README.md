# Podman lifecycle adapter

This Linux x86_64 product has two explicitly separated installation profiles:

- `podman-lifecycle/0.3.0` speaking `gate-runtime/lifecycle-v1`, with native
  Libpod 5.7 rootless create/status/start/stop/remove/health mutation.
- `podman-lifecycle/0.2.0` speaking `gate-runtime/lifecycle-v2`, with the
  immutable read-only capture profile. Its published bytes and behavior remain
  unchanged.

A 0.2.0 capture host or a mixed engine/version descriptor is rejected by Core
before mutation. Read-only capture never acquires lifecycle authority.

## Native lifecycle 0.3.0

Core 0.13.0 explicitly selects a protected lifecycle host, verifies the held
installation, executable and configuration bytes, and supplies the request on
sealed descriptors. This adapter only performs engine I/O after Core has already
persisted a durable reservation/journal generation. It does not retry create or
start, and it does not own leases, fencing, cleanup policy or recovery.

The mutation profile is deliberately narrow:

- Podman `5.7.0`, rootless only, local Unix Libpod API.
- Podman has no Docker daemon UUID; the protected configuration pins the observed
  host name (`daemon_id`), graph root (`scope`), API/server version and rootless
  flag. These are observations, not authentication or restart proof.
- Resolve-image returns a full image ID; create uses only that resolved ID, an
  exact name, ownership labels, environment, one loopback TCP mapping and an
  optional bounded command. No pull, restart policy, privilege, mounts, devices,
  auto-remove or volume removal is added.
- Create returns only a full Libpod ID after an exact inspect proves created state.
- Start and stop re-inspect the exact ID before and after. A Podman 5.7 rootless
  stop may report a network-cleanup error after the container is already terminal;
  the adapter accepts that transition only when a fresh exact-ID inspection proves
  a terminal state. Otherwise the result is Unknown and Core retains the journal.
- Remove is non-forced, requires a terminal pre-state and accepts only the exact
  returned ID. Only a separate exact 404 response establishes absence.
- Health creates one detached exec, starts it once, polls the exact exec ID under
  the original deadline, and requires the container to remain running.
- Ambiguous transport, malformed responses, timeout and cancellation return
  Unknown. Core retains the record for explicit operator recovery; there is no
  automatic create/start replay.

The full chain was validated locally against rootless Podman 5.7.0 with the
pinned Alpine image and a uniquely named container owned by that test. The
Core-managed service created, started, health-checked, stopped, removed and
proved absence, and the test project reported PASS. No unrelated container,
volume, service, proxy or network was modified.

## Capture 0.2.0

The 0.2.0 profile captures image metadata through an explicitly selected native
Libpod 5.7.0 or 6.1.4 read-only API. The 6.1.4 profile remains unchanged. Core
0.12 invokes it through `podman-capture --trust-host`. It performs exactly
info/image/info GET requests and returns canonical evidence; it never mutates,
executes, leases or recovers resources. Its published archive and acceptance
remain immutable historical evidence.

## Installation and acceptance limits

The archive contains the static executable, manifest, pinned Core identity,
acceptance script, source build metadata, license and third-party notices. The
operator supplies protected canonical installation/context descriptors and the
fixed host file; automatic discovery does not run lifecycle or capture.

The in-repository tests use fake Unix sockets for exact route, response and
Unknown-retention coverage. The real-engine PASS above is local development
evidence, not a downloaded-release, signature, registry, daemon-restart or OS
containment acceptance. Same-UID/root replacement, escaped descendants and
kernel regular-file I/O remain outside this boundary.

The candidate dependency matrix is protocol `0.6.0`, Core `0.13.0`,
onboarding-presets `1.0.8` and runtime-importer `0.6.0`. Publication has not
happened; no archive hash, signature or Core pin is claimed in advance. The
checked-in `core-pin.json` still identifies the last published Core `0.12.0`;
replace it only from the actual `0.13.0` release, never with a candidate hash.
