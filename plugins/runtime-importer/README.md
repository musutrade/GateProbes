# Runtime importer 0.7.0 candidate

This offline distribution installs immutable `podman-lifecycle-v0.3.0` for
released Core 0.14.1 on Linux with Python 3.11+. Core 0.13.0 remains declared
because the same extracted archive and descriptor were accepted by the published
0.13.0 binary as well. It grants no engine or mutation authority. Historical
importer 0.1 through 0.6 pins, released packages and the fixed 0.6 fixture remain
unchanged.

Before extraction, use `tools/release/verify_importer_archive.py` from a separately
trusted checkout with external archive/SBOM SHA256 pins and `--version 0.7.0`.
The verifier checks bounded decompression, exactly eight regular members, modes
and SBOM hashes. The caller selects the version. Verify signatures and provenance
separately; never load a verifier from an unverified archive.

The package includes `core-pin-podman.json` and `release-pin-podman.json`.
Supply the four released adapter assets to the extracted
`tools/runtime_import/install.py --pin <protected-pin> --assets <assets>
--destination <new-protected-directory>`. The installer checks all twelve adapter
archive members, the externally pinned digests, Core 0.14.1 identity and the
lifecycle mutation manifest. It publishes without replacement, with executable
mode 0500 and data mode 0400. Its seven-field canonical
`gate-runtime/lifecycle-installation-v1` descriptor uses
`gate-runtime/lifecycle-config-v1`, without a trailing newline.

The installer does not execute Core or the adapter, contact an engine, create a
context or host, or infer engine identity. The operator separately supplies a
protected lifecycle config and host binding the actual installed descriptor and
executable. Official Core 0.14.1 consumes that descriptor directly for the
create/start/health/stop/remove chain.

The package acceptance proves the extracted importer installs the downloaded
`podman-lifecycle-v0.3.0` assets and emits the exact 0400 descriptor. The local real
acceptance uses the downloaded official Core 0.14.1 and rootless Podman 5.7.0
with one fresh Core-owned container, then proves release and absence. The same
archive is also accepted by the published Core 0.13.0 binary. Capture-only
configuration and mixed 0.2/0.3 profiles are refused; the historical 0.5 and 0.6
profiles and their immutable pins remain available and are tested from fixed
fixtures.

See the bundled `tools/runtime_import/README.md` for protected paths, no-overwrite
and post-publication fsync-failure semantics. Hostile same-user filesystem races
are outside this boundary.
