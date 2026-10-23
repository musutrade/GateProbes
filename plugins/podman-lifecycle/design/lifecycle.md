# Native Podman 5.7 lifecycle profile

Status: development candidate, not published.

## Separation from capture

The read-only 0.2.0 profile remains a `gate-runtime/lifecycle-v2` capture
installation. The mutation profile is a separate `podman-lifecycle/0.3.0`
installation speaking `gate-runtime/lifecycle-v1`. Core accepts only the exact
`(product, version, engine, protocol, config schema)` tuple for each profile.
Pointing `lifecycle_host` at a `gate-runtime/podman-host-v1` capture descriptor,
a 0.2.0 installation, or a Docker lifecycle descriptor fails before any lease or
engine call.

## Authority

Core owns the project/resource identity, fresh invocation, operation key,
generation, durable reservation, journal, fence, deadline, cancellation and
operator recovery. The adapter receives sealed protected inputs only after Core
has persisted the intent. It performs no retry, name discovery, adoption or
implicit cleanup.

## Libpod 5.7 semantics

Routes are `/v5.7.0/libpod/...` only. The profile is rootless-only. Podman has no
Docker daemon UUID, so the protected configuration pins the observed host name as
`daemon_id`, the graph root as `scope`, the exact API/server version, the rootless
flag, socket path/owner and principal UID. Equal observations do not prove daemon
restart continuity or authenticate a peer.

Create uses a full image ID, exact name, ownership labels, environment, one
loopback TCP mapping with a Podman-allocated host port and an optional bounded
command. Create returns a full ID only after an exact inspect proves `created`.
Start requires `created`, then proves `running`. Stop requires a fresh terminal
state; a 5.7 rootless network-cleanup error after terminal state is accepted only
with that fresh exact-ID proof, otherwise the result is Unknown. Remove is
non-forced, requires a terminal pre-state and accepts only the exact returned ID.
Absence is established solely by the exact container route's 404 with Podman's
exact message. Health uses one detached exec, started once and polled by exact ID.

## Core integration

Core service `runtime = "podman"` plus an explicit `lifecycle_host` selects this
profile. `readiness_host` remains the separate Docker v3 read-only route.
`external_env` remains incompatible with `lifecycle_host`. The optional `command`
field is accepted only for this Podman lifecycle profile. Normal teardown reuses
the lifecycle journal and exact absence proof; the operator cleanup command
requires the same explicit host, runtime, fence and invocation.
