# Docker runtime adapter (unreleased implementation)

This directory currently contains only the protected local configuration reader.
It is not a registered or released plugin, does not implement the runtime wire
protocol, and never connects to a daemon or runs a command.

`config.load(path, expected_sha256)` requires an independent SHA-256 pin for the
exact configuration bytes. The private regular single-link config is owned by
the current uid. Config and Unix socket paths must be canonical absolute paths,
with no symlink components; ancestors must belong to root/current uid and have
no group/world write bits. Socket ownership and client principal are separate.
The socket must exist and be a Unix socket, but no connection is made. A frozen
Config records file/socket identities and revalidates by rereading the pins.
Tests must provision private roots under a protected parent, not shared /tmp.

The exact config fields are schema (`gate-runtime-engine-config/v2`), engine
(`docker`), transport (`unix-http`), socket_path, socket_uid, principal_uid,
rootless, api_version, server_version, daemon_id and scope. Missing/extra/duplicate
fields reject. Rootless is an expectation, not proof. No environment or context
fallback is supported. The digest must later match the v2 binding's
adapter_config_sha256; this reader alone does not validate request bindings.

This is a cooperative protected-filesystem boundary, not hostile same-account
isolation or authenticated daemon evidence. Path checks do not eliminate all
races with privileged actors. Server/API observations, strict bounded HTTP,
correct-route absence, v2 request/response handling, packaging and real-engine
acceptance remain unfinished. Podman, TCP/TLS and CLI transport are unsupported.

Direct `Config(...)` construction is disabled. Only successful `load` creates a
validated frozen instance; revalidation is still required before/after future
I/O. This guards normal API use, not hostile Python code in the same process
(which can bypass language-level object protections). Root-owned socket positive
acceptance has not been exercised by the unprivileged test account; this must not
be claimed from the current-user fixtures or foreign-owned config rejection.

## Staged read-only HTTP transport

`unix_http.get` accepts a loaded config and only `/version`, the selected
`/v{api}/info`, or `/v{api}/containers/{full-64-hex-id}/json`. It uses AF_UNIX
with no proxy, environment, context, redirect or CLI fallback. Config/socket pins
are revalidated before and after I/O. A monotonic total socket budget (at most
30 seconds) and short socket waits check cancellation; filesystem revalidation
has no hard time bound. Headers are bounded to 16 KiB/64 fields, body to at most
1 MiB. Duplicate headers, invalid status/header syntax, compression, transfer
encoding, missing length, truncation and oversized payloads reject.

This first framing subset requires Content-Length. Chunked and EOF-delimited
responses are unsupported and fail closed; real Docker compatibility is not yet
established. Reply status/body are transport data only: even HTTP 404 does not
establish absence here. JSON identity/error normalization and pre/post engine
observations remain future work. No mutation requests are supported, and tests
must use only disposable fake Unix sockets, never a daemon socket.
