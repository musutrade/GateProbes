# Runtime importer 0.5.0 candidate

This offline distribution installs immutable `podman-lifecycle-v0.2.0` for
released Core 0.12.0 on Linux with Python 3.11+. It grants no engine or mutation
authority. Historical importer 0.1 through 0.4 pins and released packages remain unchanged.

Before extraction, use `tools/release/verify_importer_archive.py` from a separately
trusted checkout with external archive/SBOM SHA256 pins and `--version 0.5.0`.
The verifier checks bounded decompression, exactly eight regular members, modes
and SBOM hashes. The caller selects the version. Verify signatures and provenance
separately; never load a verifier from an unverified archive.

The package includes `core-pin-podman.json` and `release-pin-podman.json`.
Supply the four released adapter assets to the extracted
`tools/runtime_import/install.py --pin <protected-pin> --assets <assets>
--destination <new-protected-directory>`. The installer checks all twelve adapter
archive members, the externally pinned digests, Core 0.12 identity and capture-only
manifest. It publishes without replacement, with executable mode 0500 and data
mode 0400. Its seven-field `gate-runtime/podman-installation-v1` descriptor uses
the protocol field order, without a trailing newline.

The installer does not execute Core or the adapter, contact an engine, create a
context or host, or infer engine identity. The operator separately supplies a
protected `gate-runtime/podman-context-v1` and `gate-runtime/podman-host-v1`, binding
the actual installed descriptor and executable. `podman-capture --trust-host`
returns read-only plan evidence; that evidence confers no mutation authority.

The trusted-checkout acceptance harness first verifies and extracts the importer,
then installs the downloaded adapter and makes downloaded Core 0.12 consume its
actual 0400 installation descriptor. Twenty-one cases cover normal read-only
capture, no persistence, and nineteen zero-connection refusal cases. A separate
local real rootless Podman 5.7 capture consumes the same importer-installed
descriptor directly; restart, authentication and containment remain unproven.

See the bundled `tools/runtime_import/README.md` for protected paths, no-overwrite
and post-publication fsync-failure semantics. Hostile same-user filesystem races
are outside this boundary.
