# Unreleased native Docker runtime adapter

This crate is under development, unregistered and unpublished. Its single native
executable has no Core production dependency and does not launch Python. The
launching host supplies executable identity, trusted expected inputs and process
supervision; this does not establish installed artifact or loader/library trust.

On Linux, the entry accepts no arguments, reads config/expected from sealed
host-owned fd3/fd4 and actual request from bounded stdin, and refuses extra live
fds. It strictly validates requests, original config-byte SHA-256 and every pin.
It checks canonical protected socket paths, socket owner and client euid without
claiming daemon authentication. Capabilities returns Inspect only without connect.
Remove requests are rejected. No other platform is supported by the entry.

Inspect uses GET /version, versioned /info, full-ID /containers inspection, then
/version and /info again under one five-second budget. Only exact Present facts
with matching before/after identities are emitted; errors and every non-200,
including 404, are Unavailable. Absent is never emitted. JSON duplicate keys and
malformed identities/labels are refused. Labels remain facts for Core comparison.
Responses are fully encoded and size-checked before stdout is written; protocol
errors have static diagnostics. Caller-owned Core cancellation and supervision
are still required; the native entry has no graceful signal/cancel protocol.

Transport uses nonblocking Unix sockets, 16 KiB/64-field headers and Content-Length
bodies up to 1 MiB. Chunked/compressed/redirect behavior is refused. Filesystem
checks are not hard-time-bounded; delayed trailing bytes after a complete body are
not waited for. Local socket identity is rechecked before/after I/O. These checks
do not prove rootless mode, user namespaces, daemon restarts or adversarial OS
isolation. No real Docker compatibility has been established.

Independent fake-socket tests and actual unreleased Core host/parser acceptance
are required before delivery. Released Core v0.6.0 does not contain that v2 host.
No registration, tag, release, service integration or lease migration is included.
