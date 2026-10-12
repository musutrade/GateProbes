# Standalone native collector

Retains `rust-native-production-mir-block/1` and the existing native driver,
normalizer, re-export verification and Core policy bridge. The Rust launcher
embeds our precompiled driver, adapter sources, schemas and license notices.
It checks those bytes before running external isolated Python (`-I -S -B -X utf8`).

See the [delivery and installation contract](../../../docs/quality/native-external-toolchain.md).
Direct `evaluate` requires `--repository-root` and `--policy-binding`; the existing
project policy rule supplies its CRAP ceiling. See [configuration and failure
behavior](../../../docs/quality/native-crap-policy.md). No unconfigured fallback
is packaged.

The release builds natively for Linux x86_64, macOS Intel, macOS Apple Silicon,
and Windows x86_64 MSVC, matching Core's executable targets. Each target runs the
real measurement and Core acceptance suite before its asset can be published.
The commands below use Linux filenames; on Windows the driver and Core have
`.exe` suffixes. `build.py --target TARGET` requires a matching host rustc and
emits the target-specific executable and SBOM listed in the delivery contract.
No compiler, interpreter, linker or LLVM distribution is included.

Build with external prerequisites already installed:

```sh
RUSTC_BOOTSTRAP=1 CARGO_TARGET_DIR="$PWD/target/native-driver" \
  cargo +1.97.1 build --manifest-path tools/quality/rust-native-driver/Cargo.toml --release --locked
python3 tools/quality/rust-native-plugin/build.py \
  --driver target/native-driver/release/harness-gate-rust-native-driver \
  --rustc "$(rustup which --toolchain 1.97.1 rustc)" \
  --output target/native-package
```

Build-only components: `rustc-dev`, `rust-docs` (standard-library notices),
GNU `strip`; fetch locked Cargo dependencies before offline packaging. Runtime
components: the matching compiler/sysroot, `llvm-tools-preview`, Python 3.12+
and the project's native build dependencies. The builder authenticates crate
sources/notices against Cargo.lock and writes a CycloneDX SBOM using Core's tool.

Run mandatory acceptance (missing inputs or skipped tests fail):

The disposable protocol-v2 request signer needs OpenSSL with Ed25519 `pkeyutl
-rawin` support. On macOS, put the existing Homebrew OpenSSL 3 `bin` directory
on PATH (`export PATH="$(brew --prefix openssl@3)/bin:$PATH"`); the system
LibreSSL command does not implement that signing interface. OpenSSL is an
acceptance-test dependency, not embedded in the plugin. Windows measurement
passes `/INCREMENTAL:NO` to the MSVC linker so its padding cannot corrupt LLVM
profiling sections. The complete fixture and Cargo acceptance checks require
valid raw profiles and no incremental `.ilk` artifacts.

```sh
NATIVE_PLUGIN_BINARY="$PWD/target/native-package/harness-gate-rust-collector-linux-amd64" \
NATIVE_DRIVER="$PWD/target/native-driver/release/harness-gate-rust-native-driver" \
NATIVE_DRIVER_SYSROOT="$(rustc +1.97.1 --print sysroot)" \
HARNESS_GATE_NATIVE_POLICY_BINARY="$(command -v harness-gate)" \
  python3 tools/quality/rust-native-plugin/accept.py
```

Use a fresh package output. `Cargo.toml` declares the independently released
version; the std-only launcher is compiled by `build.py`, not Cargo. The driver
has its own unchanged Cargo manifest/lockfile. An arbitrary `--driver` supplied
to a local build is not release provenance: the hosted release always builds it
from the selected commit before packaging and testing those exact bytes.
