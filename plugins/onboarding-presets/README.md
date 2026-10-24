# Rust and Python onboarding distribution

This archive distributes the existing rust-minimal and python-minimal products together with their installer and reproducible acceptance command. It does not install a system toolchain, add quality policy, or execute a publisher. Python 3.11+, OpenSSL, Git and the chosen project toolchain remain operator prerequisites.

Verify SHA256SUMS and repository release workflow provenance before extracting. Run `python3 tools/onboarding/plugin_manager.py --help` from the extracted directory. Installation manifests use an operator-owned Ed25519 key; repository OIDC provenance does not replace operator trust. No private key, signature or generated lock is shipped.

Against a protected released Core binary, `python3 tools/onboarding/acceptance.py --core /absolute/path/harness-gate --work-dir /new/acceptance-directory` runs both real projects, trust/tamper negatives, and upgrade/rollback. The bundled product declarations list supported targets; this release acceptance establishes Linux x86_64 only, not execution on every declared platform. Minimal presets are execution-only and do not claim language quality coverage.

## Core version compatibility

Version 1.0.1 retains the declared Core 0.5.0 and 0.6.0 compatibility and adds
0.7.0 to both product manifests. The Core contract pin remains the released
0.6.0 binary during this transition. Acceptance against a source-built 0.7.0
candidate is candidate evidence only; downloaded-release acceptance must be
recorded separately after Core 0.7.0 is published. Existing 1.0.0 artifacts
remain immutable.

Version 1.0.2 additionally declares Core 0.7.1 compatibility for the registry
packaging repair. Acceptance against source-built 0.7.1 is candidate evidence;
released 0.7.0 acceptance remains separately attributed. This declaration does
not update the repository's released Core contract pin.

Version 1.0.3 adds Core 0.8.0 for the installed-runtime host release. Initial
0.8.0 acceptance uses a source-built candidate and is not released-Core evidence.
Acceptance against downloaded Core 0.7.1 remains separately attributed; after
0.8.0 publication, repeat against the downloaded binary. The repository Core
contract pin and all prior immutable artifacts remain unchanged.

Version 1.0.4 adds Core 0.9.0 as an onboarding compatibility prerequisite.
Its initial Core0.9 validation uses the source-built candidate; downloaded
Core0.9 acceptance must be repeated after release. This does not declare v3
runtime package compatibility. Published1.0.3 and its pins remain immutable.

Version 1.0.5 adds Core 0.10.0 to both execution-only product declarations.
Initial validation targets the source-built candidate; downloaded Core 0.10.0
acceptance remains required after publication. This does not declare lifecycle
adapter compatibility, rootless or daemon-restart acceptance. Existing 1.0.4
artifacts and the repository's released Core pin remain immutable.

Version 1.0.6 adds Core 0.11.0 to both execution-only product declarations.
Validation initially uses the pinned source-built Core0.11 candidate; downloaded
Core0.11 acceptance remains required after publication. This does not declare
Podman adapter compatibility, real-engine behavior, mutation or lease authority.
Existing1.0.5 artifacts/pins remain immutable.

Version 1.0.7 adds Core 0.12.0 to both execution-only product declarations.
Validation uses the source-built Core0.12 candidate; downloaded Core0.12
acceptance remains required after publication. This does not declare Podman
adapter, real-engine, mutation or lease compatibility. Existing1.0.6 artifacts
and pins remain immutable.

Version 1.0.8 retains Core 0.5.0–0.12.0 and adds Core 0.13.0 to both
execution-only product declarations. Validation uses the candidate Core 0.13.0
source build; downloaded Core 0.13.0 acceptance remains required after
publication. Publish this compatible package before Core CI binds it exactly.
This declaration does not claim Podman real-engine, mutation or lease behavior.
Existing 1.0.7 artifacts and pins remain immutable.

Version 1.0.9 retains every previously declared Core version and adds Core
0.14.0 to both execution-only products for the Core CLI retirement release.
Validation covers the source-built 0.14.0 candidate and the downloaded 0.13.0
predecessor separately. Downloaded Core 0.14.0 acceptance remains pending until
that release exists. Publish this prerequisite before updating Core CI's archive
pin; do not relax Core's exact-version check or rewrite 1.0.8. The repository
released Core pin and runtime/importer compatibility declarations are unchanged.

Version 1.0.10 adds exact Core 0.14.1 compatibility for its protocol publication
repair. All prior declarations, execution policy and released Core pins remain
unchanged. Candidate acceptance is separate from downloaded Core acceptance;
v0.14.0 was tagged but its publication failed, so a new Core version is required.
Historical preset releases remain immutable.
