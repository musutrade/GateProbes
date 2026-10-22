# Runtime importer 0.2.0 candidate

This distribution packages the offline importer for the immutable
`docker-readiness-v0.2.0` archive and released Core 0.9.0. It contains no Core or
adapter binary and performs no daemon operation. Linux and Python 3.11+ are required.
Historical importer 0.1.0/Core 0.8/runtime 0.1.1 artifacts and pins remain unchanged.

Before extraction, use `tools/release/verify_importer_archive.py` from a separately
trusted checkout with external archive/SBOM SHA256 pins and `--version 0.2.0`.
It checks bounded decompression, exact eight regular members, modes and SBOM
hashes. The version comes from the caller, never from archive bytes. Verify
signatures/provenance separately; never load the verifier from the unverified
archive. This does not defend against hostile same-user filesystem races.

The package includes `core-pin-v3.json` and `release-pin-v3.json`. The runtime pin
is reviewed operator input, not self-authentication. Supply the four downloaded
readiness assets to `tools/runtime_import/install.py --pin <protected-pin>
--assets <assets> --destination <new-protected-directory>`. Installation validates
the assets, publishes without replacement and writes the installed descriptor.
The importer does not execute Core, probe the daemon or verify release signatures.

The separate acceptance harness externally verifies and extracts the importer,
runs its installer, and invokes downloaded Core 0.9 doctor with installed-v2 host
configuration and a fake Unix socket. It checks readiness, missing/unavailable
images, identity change, timeout, forbidden fixed expected input, descriptor and
executable tampering, and schema tampering even after rebinding the host digest.
It retains artifact/descriptor hashes, exact exits, stderr and request lists.
Core still owns service lifecycle coordination; no real Docker/Podman, rootless,
restart, OS containment, mutation, Remove, Absent or lease migration is proved.

See the bundled `tools/runtime_import/README.md` for protected-path, cooperative
filesystem, no-overwrite and post-publication fsync failure semantics. Candidate
CI uses a freshly built importer package and downloaded dependencies. Downloaded
importer-release acceptance follows publication; it is not claimed by local CI.
