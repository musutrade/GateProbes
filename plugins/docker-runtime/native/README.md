# Unreleased native Docker runtime adapter

This crate is under development and is not registered or released. It currently
contains adapter-side typed input validation and Linux sealed-fd bootstrap. It
also checks canonical protected socket paths, socket owner and client euid, with
pre/post identity revalidation. These checks do not connect or authenticate a
daemon. Linux HTTP transport now supports only GET /version, versioned /info
and full-ID /containers inspection. It uses nonblocking sockets and one deadline,
16 KiB/64-field headers, Content-Length-only bodies up to 1 MiB, and pre/post
socket revalidation. Chunked/compressed/redirect behavior is refused. A raw 404
is not absence. Filesystem checks are not hard-time-bounded; delayed trailing
bytes after a complete body are not waited for. No real Docker compatibility
has been established. There is no executable entry or host hookup yet.
Bootstrap requires only fd3/fd4 plus stdio, bounded sealed euid-owned memfds and
no application arguments. It does not authenticate its launching host.

The production dependency list does not contain Core or a Python launcher. Core's
own parser remains the independent authority in future integration acceptance.
Input checks reject mutation requests and accept only capability discovery and
full-ID inspection. SHA-256 binds original config bytes, not a normalized object.
All errors are static. This module performs no filesystem or identity observation.

Do not treat this building block as a published adapter or claim real Docker,
rootless, daemon, loader/library or installed-artifact authentication.
