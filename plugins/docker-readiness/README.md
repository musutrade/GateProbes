# Docker readiness 0.2.0 candidate

This independent product carries the gate-runtime/v3 readiness binary from the
shared native source. Core 0.9.0 is published; the dedicated `core-pin.json` pins
its released Linux binary. This readiness package is not yet released.

`accept.py --core /absolute/core --binary /absolute/adapter --version 0.2.0
--report /absolute/report.json` runs six fake Unix-socket cases: present, missing,
unavailable, identity change, timeout and injected fixed expected input. It uses
Core doctor with the protected installed-v2 host and verifies no CLI fallback.
Use a protected HOME/.cache. The report identifies the exact supplied binaries;
source-built results are not downloaded-release evidence.

No real Docker daemon, Podman, rootless, restart detection, daemon authentication,
OS containment, mutation, Remove, container Absent, or lease migration is proved.
Core still owns service lifecycle operations. Historical runtime0.1.1 artifacts
and their v2 compatibility declarations remain unchanged.

The release path verifies the dedicated Core 0.9.0 digest and version, builds the
native binary twice, then runs the bundled acceptance script from the extracted
archive. CI compares archive/SBOM bytes across Ubuntu22/24 and runs downloaded-Core
acceptance on Ubuntu24. The retained report identifies both binary digests.
Importer0.2 distribution is separate unfinished work.
