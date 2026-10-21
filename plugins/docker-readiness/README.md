# Docker readiness 0.2.0 candidate

This independent product carries the gate-runtime/v3 readiness binary from the
shared native source. Core 0.9.0 is its intended acceptance target, not a published
compatibility claim. The package and Core are not released.

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

The build-only product profile is available, but publication dispatch intentionally
refuses until a new externally verified Core0.9 release pin and extracted package
acceptance are wired. Importer0.2 distribution is separate unfinished work.
