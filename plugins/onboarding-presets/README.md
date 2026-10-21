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
