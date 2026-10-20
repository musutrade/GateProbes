# Unreleased native Docker runtime adapter

This crate is under development and is not registered or released. It currently
contains adapter-side typed input validation and Linux sealed-fd bootstrap. It
has no executable entry, socket access, HTTP implementation or host hookup.
Bootstrap requires only fd3/fd4 plus stdio, bounded sealed euid-owned memfds and
no application arguments. It does not authenticate its launching host.

The production dependency list does not contain Core or a Python launcher. Core's
own parser remains the independent authority in future integration acceptance.
Input checks reject mutation requests and accept only capability discovery and
full-ID inspection. SHA-256 binds original config bytes, not a normalized object.
All errors are static. This module performs no filesystem or identity observation.

Do not treat this building block as a published adapter or claim real Docker,
rootless, daemon, loader/library or installed-artifact authentication.
