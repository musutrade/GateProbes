# Podman read-only capture adapter

This Linux x86_64 product captures image metadata through an explicitly selected
native Libpod 5.7.0 or 6.1.4 read-only API. The 6.1.4 profile remains unchanged. Core 0.12 explicitly invokes it through `podman-capture --trust-host`.
It performs exactly info/image/info GET requests and returns canonical evidence;
it does not create, start, stop, remove, or execute inside containers.

The candidate product tuple is `podman-lifecycle/0.2.0/gate-runtime/lifecycle-v2/podman`.
The native entry accepts only `gate-runtime/podman-capture-v1` requests, with
protected configuration on fd3 and a sealed per-invocation binding on fd4.
Core holds and verifies the executable before spawning it with an empty
environment. There is no Docker wire, CLI fallback, or ambient endpoint selection.

## Installation and explicit use

The archive contains the static executable, manifest, pinned Core identity,
acceptance script, source build metadata, license and third-party notices.
It does not install a host or generate engine configuration. The operator must
supply protected canonical installation/context descriptors and the fixed host
file at `.harness-gate/runtime/podman-capture-v1/host.json` in a canonical project
root. The host file is the explicit trust root and may reference protected
members outside the project. Automatic project discovery does not run capture.

Use downloaded Core 0.12 with an explicit absolute `--project-root`, the
`podman-capture` command, `--trust-host`, a full image ID, and bounded name/label/
optional port inputs. Successful stdout is canonical PlanRecord JSON without a
newline. Core does not persist it; a caller may explicitly retain evidence only
after checking successful exit and the complete response. Partial output from a
failed command must be discarded. Evidence hashes and operator epochs are not
authentication, freshness, restart detection, or mutation/lease authority.

## Acceptance and limitations

`accept.py` verifies externally supplied archive and Core hashes before testing
an extracted package. Its 21 cases cover two successful captures and 19
zero-socket refusals, with exact exits, output and no-persistence checks. All
network fixtures are local fake Unix sockets. No importer is used.

This candidate is not yet published. It pins published protocol 0.5.0 and
Core 0.12.0; both preserve the protected socket handle and prior releases remain
immutable.

The 21-case package acceptance uses fake sockets. A separate local real-rootless
Podman 5.7 read-only capture passed; production, daemon-restart, remote
authentication and OS containment remain unproven. Same-UID/root tampering remains outside the protection
boundary. Deadlines bound socket and pipe operations; kernel regular-file I/O
is not preempted. Process-group cleanup does not contain escaped descendants.
Podman service mutation and lease integration remain separate work.
