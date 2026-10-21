# Offline runtime import preflight (candidate)

`preflight.validate(pin_bytes, archive, sbom, inventory, checksums)` validates
in-memory release bytes against a separately reviewed operator pin. It returns
member bytes only: no paths, extraction to disk, install, subprocess, network,
Core invocation or daemon operation occurs. It is not yet a complete importer.

The required pin schema is `gateprobes-runtime-release-pin/v1`, with repository
`https://github.com/musutrade/GateProbes`, tag `docker-runtime-v<version>`, version,
40-hex source_commit, and 64-hex archive_sha256, sbom_sha256, inventory_sha256,
checksums_sha256 and executable_sha256. All fields are required; unknown and
duplicate pin fields are refused. Pin authority must come from independent
review of the release, not from the supplied archive, descriptor, or checksum
list. This module does not verify signatures or confer authority on a pin.

Validation binds all four asset hashes, the exact checksum subjects, inventory
source/tag/member sizes, binary identity and SBOM file hashes. Only the nine
known flat native runtime package members are accepted, with exact modes and
without links, aliases, duplicate members or extensions. Compressed input is
limited to 16 MiB, decompressed tar to 32 MiB, and JSON documents to 1 MiB. Content
is never executed. Errors are static and do not echo input fields.

Next, a separate protected importer must read an authoritative pin safely,
materialize verified bytes into a new immutable destination without overwrite,
and write the Core `gate-runtime-installation/v1` descriptor atomically. This
preflight alone does not establish filesystem protection, publisher authenticity,
installed identity, rollback protection, or real Docker compatibility. It does
not extend the data-only onboarding/preset installer.
