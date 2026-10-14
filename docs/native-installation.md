# Native Rust plugin installation

GateProbes owns installation, upgrades, rollback, exact versions, native asset
names and plugin signing identities. GateHouse installs Core only. The active
Core installer retires plugin execution: legacy flags fail before downloading
or changing either executable. Historical tagged Core installers stay frozen;
they retain their original versions, repositories and certificate identities.

## Fixed public entry

Install a trusted Cosign verifier explicitly before running this command.
Download the reviewed installer from its full source commit and verify its
SHA-256 before executing it. On macOS use shasum -a 256 --check for the script
checksum; Windows requires Bash (Git Bash/MSYS2/Cygwin).

~~~bash
curl --fail --show-error --location --proto '=https' --tlsv1.2 \
  -o /tmp/gateprobes-install-native.sh \
  https://raw.githubusercontent.com/musutrade/GateProbes/1507805205944229950e0fe57d4fe1f17fc3e130/tools/install/install-native.sh
printf '%s  %s\n' 317e7f98e3863d44d32640106091596e227be0795463dd81adcd26ef6797bce6 /tmp/gateprobes-install-native.sh | sha256sum --check
bash /tmp/gateprobes-install-native.sh --version 0.1.0-rc.8 \
  --install-dir "$HOME/.local/bin"
~~~

No default plugin version, environment version override, latest lookup,
download-and-execute mutable script or repository/signer fallback exists.
The installer requires Bash, curl or wget, SHA256 tooling and Cosign. It only
diagnoses missing dependencies. It never installs Rust, LLVM, Python or Cosign.
Collection's external toolchain requirements and explicit doctor command are
in the [native contract](https://github.com/musutrade/GateHouse/blob/v0.5.0/docs/quality/native-external-toolchain.md).
Installing a binary does not certify measurement capability or adopt a baseline.

## Trust and replacement

Every install verifies both the SHA256SUMS signature and executable signature,
the exact selected executable checksum, the GitHub Actions OIDC issuer
https://token.actions.githubusercontent.com, and this exact certificate SAN:

~~~text
https://github.com/musutrade/GateProbes/.github/workflows/native-collector-release.yml@refs/tags/rust-collector-v<SELECTED_VERSION>
~~~

RC8 remains a prerelease with legacy mutable assets. The installer additionally
pins its original signed manifest digest
d8f2302dc56108b6db8d971bed18c7d3bf0265506768663de8fb91d27011444b
from the [public receipt](quality/issue-17/rc8-public-verification.json).
A signed same-tag replacement with different bytes is rejected. Historical
release assets, tags and signatures are never rewritten. Future publication
must meet the [immutable release requirements](quality/issue-17/README.md).

Supported asset dispatch is Linux x86_64, macOS Intel/ARM and Windows x86_64.
There is no ABI/platform fallback. Verification finishes before activation.
Private absolute directories and regular files are required; symlink paths,
traversal and group/other-writable destinations are rejected. Replacement uses
a temporary file in the destination directory and atomic rename. Download,
verification, copy, chmod, rename and HUP/INT/TERM failures retain the previous
executable and clean the operation's own temporary files.

## Upgrade and rollback

Retain the previous exact version and executable digest in your project record.
Use the same checksum-verified installer with an explicitly selected release:

~~~bash
# Upgrade, after choosing a published compatible version:
bash /tmp/gateprobes-install-native.sh --version "$NEW_PLUGIN_VERSION" --install-dir "$HOME/.local/bin"
# Roll back to your recorded previous release:
bash /tmp/gateprobes-install-native.sh --version "$PREVIOUS_PLUGIN_VERSION" --install-dir "$HOME/.local/bin"
~~~

RC8 is currently the only GateProbes native release. The two-version
upgrade/rollback test uses clearly marked signed-fixture doubles; it does not
claim that GateProbes RC4 is published. A version absent from GateProbes fails;
the installer will never switch to the old Harness-Gate repository to find it.
Restore an older Harness-Gate release using that release's original installer
and signer. Roll back config/executable pins together only after reviewing the
measurement continuity contract; installing never edits configuration/history.

## Core migration and ownership

| Old active Core invocation | New invocation |
| --- | --- |
| --rust-only --rust-version X | Verified GateProbes installer --version X |
| --with-rust --rust-version X | Run Core --version vY, then plugin --version X |
| --rust-root DIR | Plugin --install-dir DIR/bin |
| HARNESS_GATE_RUST_VERSION=X | Plugin explicit --version X |
| --cache-dir DIR | Provision trusted verifier on PATH; no provisioning cache |
| Historical --offline bundle | Historical tagged installer |

The exit condition for the Core compatibility bridge is satisfied in this
change: no plugin installer is executed by Core. Only diagnostic stubs remain.
There is one editable plugin install implementation,
tools/install/install-native.sh, maintained in GateProbes. GateHouse owns its
Core installer and historical Core signer cutover. GateProbes owns native
release assets, signing, version selection and install/upgrade/rollback tests.

This changes no collector protocol, engine, measurement series or Core policy.
Core retains requiredness, thresholds, baseline/debt/ratchet, final decisions
and release authority. GateProbes only supplies facts and check results.

Run bash tools/install/tests/test_install.sh for offline four-platform dispatch,
signed-fixture upgrade/rollback, wrong repository/workflow/tag, checksum and
missing signature, missing verifier, pollution, path safety, atomic failure and
signal cleanup tests. These tests are required before CI classification.
The production RC8 pin is checked against the independently retained receipt.

[Public fixed-source installation receipt](native-installer-acceptance.json): Linux x86_64, two real Cosign checks and exact released binary digest. Fixture platform dispatch is not new four-host runtime acceptance.
