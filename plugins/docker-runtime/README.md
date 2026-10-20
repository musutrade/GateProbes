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
