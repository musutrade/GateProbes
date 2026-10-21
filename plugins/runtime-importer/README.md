# Runtime importer 0.1.0 (unpublished candidate)

This distribution packages the offline runtime importer separately from the
immutable docker-runtime-v0.1.1 native archive. It contains no Core or adapter
binary and performs no daemon operation. Linux and Python 3.11+ are required.

Verify this importer's own archive digest and release provenance independently
before extracting or executing it. The bundled runtime release pin is a reviewed
operator input, not self-authentication. The importer checks the four supplied
runtime assets against that pin, publishes a new protected installation without
replacement, and writes the installed descriptor. Signatures and provenance are
external prerequisites, not verified by the importer.

The direct installed-host path requires released Core0.8.0. It does not broaden
runtime0.1.1 plugin-manager metadata or its accept.py Core0.7.1 compatibility.
Acceptance must use extracted importer bytes, downloaded Core0.8.0 and unchanged
published runtime0.1.1: installation/modes/descriptor, capabilities without fake
socket connections, and pin/descriptor/executable tamper rejection. No real
Docker compatibility, zero-spawn, sandbox, rootless or restart proof is claimed.

See the bundled tools/runtime_import/README.md for protected path, cooperative
filesystem, no-overwrite and post-publication fsync failure semantics. The
standalone artifact and downloaded fixed-pair acceptance are not published yet.
