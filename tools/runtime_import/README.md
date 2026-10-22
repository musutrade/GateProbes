# Offline runtime import preflight (candidate)

`preflight.validate(pin_bytes, archive, sbom, inventory, checksums)` validates
in-memory release bytes against a separately reviewed operator pin. It returns
member bytes only: no paths, extraction to disk, install, subprocess, network,
Core invocation or daemon operation occurs. It is the byte-validation layer of the candidate importer.

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

## Explicit installation (Linux candidate)

Run `python3 tools/runtime_import/install.py --pin /protected/reviewed-pin.json
--assets /absolute/downloaded-assets --destination /protected/new-installation`.
The pin must be a current-euid-owned 0400/0600 single-link regular file under
canonical root/euid-owned ancestors with no group/world write. The existing
destination parent must additionally be euid-owned. The importer never derives
pin authority from downloaded assets; the operator must review signatures and
release evidence separately before supplying the pin.

All input files are opened no-follow, bounded and revalidated before publication.
Validated members are written into a private sibling staging directory, executable
0500 and data0400; files and staging directory are synced. The installation
contains `installation.json` (0400) with Core schema
`gate-runtime-installation/v1`, independently supplied provenance and exact
installed executable path/hash/version. Linux `renameat2(RENAME_NOREPLACE)`
publishes the directory without overwriting any existing destination, then the
parent directory is synced. No missing parent is created and no imported script
or binary is executed. No subprocess, network, Core or daemon is invoked.

A failure after directory publication retains the installed directory and returns
failure; inspect it before retrying. There is no rollback, overwrite or repair
command. The trust model is cooperative local storage with protected ancestors,
not hostile same-uid/root isolation, guaranteed power-loss recovery or arbitrary
filesystem durability. Metadata checks do not hold every ancestor directory fd.
The descriptor records local operator assertions, not publisher authentication.
Core main has the installed entry; released Core0.7.1 does not.

## Validation scope

The lightweight gate runs 19 offline tests with no skips. A separate required
Ubuntu24 job runs the joint installed-host test (20 mandatory tests total), using
Core source a4e6dba7b2d6ad06336c67e79d1132eb96a5bab7 built with --locked, and four
immutable docker-runtime-v0.1.1 release assets. Missing inputs fail. Only the
additional published-assets smoke remains local-only. Core0.7.1 cannot supply
the installed entry; this is source-built Core acceptance, not a released-Core claim.

release-pin.json records independently reviewed batch60 release identities
(source29c619b, release run39538813308, archive/SBOM/inventory/binary and checksum
file). It is checked in separately from downloads; CI does not derive authority
from their contents or use an asset cache. Signatures/provenance were reviewed at
release time; this job checks fixed hashes, not fresh publisher authentication.
The build logs record Core lockfile and binary SHA256. Protected HOME fixtures
exercise offline installation, exact capabilities and no fake-socket connections,
plus descriptor/executable/pin tamper rejection. No real daemon is contacted;
rejection/no output is not presented as OS-level process or network containment.

### Staged readiness profile

The offline validator and installer also recognize the explicit trusted tag
`docker-readiness-v0.2.0`. That profile requires the dedicated
`gateprobes-docker-readiness` member, `docker-readiness` manifest/SBOM identity,
and `gate-runtime/v3`. The archive cannot choose its own profile. Installation
preserves the protected destination, exact modes, and no-overwrite boundary.

This is source preparation with synthetic fixtures, not importer 0.2.0 delivery.
The checked-in v2 release pin is unchanged. A v3 release pin must come from real,
independently reviewed release assets; no placeholder digests are provided.
Released Core 0.8.0 does not contain the v3 host. Downloaded acceptance requires
a new Core release carrying that host and a verified new compatibility pin.
