# Runtime importer 0.3.0 candidate

This offline distribution installs immutable `docker-lifecycle-v0.1.0` for
released Core 0.10.0. Linux and Python 3.11+ are required. Historical importer
0.1/runtime and importer 0.2/readiness release pins and artifacts remain unchanged.

Before extraction, use `tools/release/verify_importer_archive.py` from a separately
trusted checkout with external archive/SBOM SHA256 pins and `--version 0.3.0`.
It checks bounded decompression, exactly eight regular members, modes and SBOM
hashes. The caller selects the version; archive contents cannot select it.
Verify signatures and provenance separately. Never load a verifier from an
unverified archive. Hostile same-user filesystem races are outside this boundary.

The package includes `core-pin-lifecycle.json` and `release-pin-lifecycle.json`.
The release pin is separately reviewed operator authority. Supply the four
published lifecycle assets to `tools/runtime_import/install.py --pin <protected-pin>
--assets <assets> --destination <new-protected-directory>`. The importer validates
all 13 adapter archive members and publishes without replacement. It creates a
canonical seven-field lifecycle `installation.json`, mode 0400; executable mode
is 0500 and all data is 0400.

The importer creates no config or host, infers no engine identity, performs no
network or daemon operation, and executes neither adapter nor Core. The operator
supplies protected canonical lifecycle config and host descriptors, binding the
installation digest and explicit engine observations. Core owns durable leases,
recovery, cancellation and mutation authority.

The separate acceptance harness verifies and extracts the importer before running
its installer. Downloaded Core 0.10 consumes the actual installed descriptor with
an independently supplied fake-engine config/host through service-bound `verify`.
Fourteen cases cover normal cleanup, failed health with explicit operator cleanup,
and twelve zero-socket identity negatives. This proves fake-socket package
integration only; rootless, restart and real-engine package acceptance remain
unproven. Downloaded importer-release acceptance follows publication.

See bundled `tools/runtime_import/README.md` for protected-path, no-overwrite and
post-publication fsync-failure semantics. No implicit legacy lease migration occurs.
