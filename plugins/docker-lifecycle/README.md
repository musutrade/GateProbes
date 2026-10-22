# Docker lifecycle development

This separate, unpublished product currently contains only an exact create-request
builder. It cannot open sockets or execute operations. It does not extend runtime
v2 or readiness v3 and must not be registered or packaged as an installable adapter.

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
