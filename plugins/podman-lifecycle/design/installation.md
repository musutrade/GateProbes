# Podman read-only installation boundary

The held installation boundary and native capture entrypoint are implemented in
published Core 0.11.0, protocol 0.4.1 and
[podman-lifecycle 0.1.0](https://github.com/musutrade/GateProbes/releases/tag/podman-lifecycle-v0.1.0).
The immutable 0.1.0 archive retains its pre-publication README wording; its release
status is recorded by the release above. This document describes the implemented
boundary and supersedes the earlier design proposal.

The product tuple is `podman-lifecycle/0.1.0/gate-runtime/lifecycle-v2/podman`.
Docker lifecycle-v1 descriptors cannot select it. Core explicitly selects the
fixed `.harness-gate/runtime/podman-capture-v1/host.json` in the canonical project
root through `podman-capture --trust-host`.

## Descriptors and canonical bytes

The host has exactly `schema`, `installation_path`, `installation_sha256`,
`config_path`, and `config_sha256`. Its schema is `gate-runtime/podman-host-v1`.

The installation has exactly `schema`, `product`, `version`, `protocol`,
`executable_path`, `executable_sha256`, and `config_schema`. Its schema is
`gate-runtime/podman-installation-v1`; `config_schema` is
`gate-runtime/podman-context-v1`. These field lists are the serialization order:
compact JSON, no trailing newline, no unknown or duplicate fields. Sorting keys
alphabetically produces noncanonical Podman installation bytes.

The separate versioned context wrapper contains `schema` and `context`, embedding
the expected engine context. The loader verifies the held wrapper bytes and feeds
the protected context from those bytes. It does not reinterpret old unwrapped
configuration or reopen a caller-selected path to acquire engine authority.

## Held files and capture

`VerifiedPodmanInstallation` holds the host, installation, configuration and
executable files. Descriptors require the current effective UID, one link,
0400/0600 mode, bounded size, no symlink and protected ancestors. The executable
must be a regular ELF with the expected digest and one link: current-user owned
0500/0700, or root-owned 0555/0755. The loader verifies path identity, held metadata
and bytes, then revalidates them when the installation is used.

Core launches the held executable on Linux with an empty environment and fixed
working directory. Protected context on fd3 and a sealed per-invocation binding
on fd4 tie the capture request to its selected installation. The adapter accepts
only `gate-runtime/podman-capture-v1`; it performs native Libpod 6.1.4
info/image/info GET requests. There is no ambient socket selection or Docker
compatibility fallback.

A live installation can compare saved `PlanRecord` assertions through a separately
scoped match value that revalidates its held installation. Saved evidence does not
recreate a verified handle, change `installation_verified()` into an authority
claim, or mint an operator token or lease. Core returns canonical capture evidence
without persisting it; callers must discard partial output from failed capture.

## Verification boundary and remaining work

Published-package acceptance covers 21 fake Unix socket cases: two successful
captures and nineteen refusals with zero connections. It verifies exact command
exits, canonical output and no persistence. Protocol 0.4.1 includes the musl
O_PATH socket-handle repair; historical protocol and product releases remain
immutable.

Real Podman 6.1.4, rootless operation, daemon restart and OS containment have not
been established by these tests. A compatible operator-provisioned environment
is required for real-engine acceptance. Same-UID/root replacement after checks
is outside the boundary. Bounded socket/pipe deadlines do not preempt kernel
regular-file I/O, and process-group cleanup does not contain escaped descendants.

Podman create/start/stop/remove operations and durable service lease integration
remain separate implementation work. Read-only installation and plan evidence
must not be promoted into that authority.
