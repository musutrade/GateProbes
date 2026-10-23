# Podman read-only capture adapter

This Linux x86_64 product captures image metadata through the native Libpod
6.1.4 API. Core 0.11 explicitly invokes it through `podman-capture --trust-host`.
It performs exactly info/image/info GET requests and returns canonical evidence;
it does not create, start, stop, remove, or execute inside containers.

The product tuple is `podman-lifecycle/0.1.0/gate-runtime/lifecycle-v2/podman`.
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

Use downloaded Core 0.11 with an explicit absolute `--project-root`, the
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

This candidate is not yet published. It pins published protocol 0.4.1, whose
musl O_PATH repair preserves the protected socket handle. Protocol 0.4.0 and
historical products remain immutable.

There is no real Podman, rootless, daemon-restart, remote authentication, or OS
containment acceptance. Same-UID/root tampering remains outside the protection
boundary. Deadlines bound socket and pipe operations; kernel regular-file I/O
is not preempted. Process-group cleanup does not contain escaped descendants.
Podman service mutation and lease integration remain separate work.
