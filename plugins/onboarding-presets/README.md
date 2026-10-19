# Rust and Python onboarding distribution

This archive distributes the existing rust-minimal and python-minimal products together with their installer and reproducible acceptance command. It does not install a system toolchain, add quality policy, or execute a publisher. Python 3.11+, OpenSSL, Git and the chosen project toolchain remain operator prerequisites.

Verify SHA256SUMS and repository release workflow provenance before extracting. Run `python3 tools/onboarding/plugin_manager.py --help` from the extracted directory. Installation manifests use an operator-owned Ed25519 key; repository OIDC provenance does not replace operator trust. No private key, signature or generated lock is shipped.

Against a protected released Core binary, `python3 tools/onboarding/acceptance.py --core /absolute/path/harness-gate --work-dir /new/acceptance-directory` runs both real projects, trust/tamper negatives, and upgrade/rollback. The bundled product declarations list supported targets; this release acceptance establishes Linux x86_64 only, not execution on every declared platform. Minimal presets are execution-only and do not claim language quality coverage.
