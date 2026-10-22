# Docker lifecycle development

This separate, unpublished product implements protected-input Docker create,
status, start, stop and remove. It does not extend runtime v2 or readiness v3.
It is not registered or packaged; Core service orchestration is still absent.
Only fake Unix sockets have been exercised. Resolve-image and health-exec return
RejectedBeforeEffect until implemented; healthcheck recipes are not usable yet.

Development requires the paired unreleased Core lifecycle protocol source through
an explicit local Cargo `patch.crates-io.gatehouse-runtime-protocol.path` override.
The published protocol 0.2.0 does not contain this module. The manifest version is
only the current development source identity; release wiring must bump and publish
the additive protocol before pinning an installable lifecycle product. No absolute
local checkout path is committed, and no released protocol capability is claimed.

The builder preserves exact image ID, ownership labels and environment, requests
one Docker-allocated loopback TCP binding, disables automatic removal/restart and
privileged execution, and adds no mounts/devices/command overrides. Image-declared
configuration still applies. This is not a container sandbox or mutation authority.


The executable reads bounded exact stdin plus sealed config fd3 and expected fd4.
It uses a private nonblocking Unix HTTP transport, one monotonic deadline, bounded
headers/body, no redirects/chunked encoding/proxy/environment/CLI or retries. The
socket identity is checked before/after each call. Matching version/info including
the configured rootless flag is observed before/after every complete operation.
These observations do not authenticate a daemon, prove rootless isolation or detect
all restarts (a daemon can retain its ID). No OS containment is claimed.

Create requires a full ID, no warnings and a subsequent exact inspection before
Created. Start/stop/remove require an exact preinspection; stop uses the bound grace,
remove is non-force and does not delete volumes. Remove returns only a claim;
only a separate status 404 with the exact ID-specific Docker message can assert
absence. All ambiguity, malformed bodies or changed identity returns Unknown.
The Core host persists these outcomes and requires separate reconciliation.

Development tests use the explicit local protocol patch described above. Both
native binary and library must be tested with the paired Core source before any
publication; existing runtime/readiness artifacts remain unchanged.
