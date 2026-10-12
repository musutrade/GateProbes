# Pinned native production measurement

The [standalone native plugin](../rust-native-plugin/README.md) packages this
unchanged engine with external dependencies. `rustc-dev` is needed to build the
driver; running its binary needs the matching compiler libraries/sysroot and
LLVM tools, without requiring the build-only development crates.

This page documents source development commands. Users of the published optional
Rust plugin should start with the [installation guide](../../../docs/quality/rust-collector-installation.md)
and [current compatibility record](../../../docs/release-status.md#compatibility).

This opt-in development collector uses rustc **1.97.1**, commit
`8bab26f4f68e0e26f0bb7960be334d5b520ea452`, LLVM **22.1.6** and
`rustc-mir-block-inventory/3`. It needs the matching `rustc-dev` and `llvm-tools`
components. It does not install or change a project's official gate or baseline.
Generic Core remains language independent; the released Rust CLI evaluates policy.

From this repository, with that Rust toolchain already available:

```sh
python3 tools/quality/rust-native-driver/bootstrap.py \
  --sysroot "$(rustc --print sysroot)" --output target/native-driver
export NATIVE_DRIVER="$PWD/target/native-driver/build/debug/harness-gate-rust-native-driver"
export NATIVE_DRIVER_SYSROOT="$(rustc --print sysroot)"
python3 tools/quality/rust_native_driver.py cargo \
  --source target/arc-admin/backend/Cargo.toml --output target/native-backend \
  --driver "$NATIVE_DRIVER" --sysroot "$NATIVE_DRIVER_SYSROOT" \
  --sample openapi_contract --sample permission_template_contract
```

Use a fresh output directory. `bootstrap.py --archive PATH` reuses a downloaded
archive after checking the same pinned official SHA. All installation overlays,
source copies, builds and profiles stay inside this checkout. The base toolchain
is read only. Run sampling only against project-owned tests and disposable test
services where needed. These two Arc-Admin contract tests need no database.

The collector prints a manifest SHA. Retain it in a trusted review record apart
from the evidence. Certification re-merges the original profiles and re-exports
LLVM data from the original binaries; it does not execute archived programs:

```sh
python3 tools/quality/rust_native_driver.py certify \
  --evidence target/native-backend/raw --anchor REVIEWED_SHA \
  --output target/native-backend/report.json
```

A successfully mapped report can exit **1** for real threshold failures. A
measurement exception also exits 1 but produces no successful report. Check the
report and retained stderr. No synthesized JSON constitutes native success.
Commands, exits, source hashes, selected Cargo targets/features/cfg, resolution
inputs, compiler definitions, expansion edges, binaries, raw profiles, and LLVM
export remain in the sealed evidence directory. Never reseal changed evidence to
reuse a reviewed anchor. Host-reviewed anchors provide integrity, not remote
producer attestation. Tool paths may be relocated only in a separately reviewed
capture; their bytes and versions remain part of the series identity.

## Ownership and counting

The driver installs independent physical LLVM counters at every typed MIR basic
block, including async bodies, closures, constructors and derived methods that
stock rustc coverage omits. Virtual `.mir-map` files make the block-to-LLVM join
bijective. All function definitions must have observed LLVM instances, including
zero-count instances. An uninstantiated/unmapped generic is an error. A parent's
counter never supplies a child's count. Distinct symbols of the same compiler
owner are summed; duplicated symbols/regions or ambiguous owners are errors.

Definition IDs are rustc DefPathHash values. Source spans carry SourceMap IDs,
bytes and complete recursive expansion call/definition sites and macro definition
IDs. The inventory also records every post-analysis compiler definition in index
order. Non-function constants/statics retain actual constant-evaluation MIR and
its SHA; expanded types retain declaration identity. Runtime definitions must
exactly match the runtime owner list. This accounts for constant/type-producing
`macro_rules!` without inferring runtime absence from the source AST.

`rust-native-production-mir-block/1` is a new series: **regions mean independent
MIR basic blocks, not stock rustc source coverage regions**. Lines are the union
of all local source origins attached to the block's statements and terminator,
including expansion definition and invocation lines. Any positive owned block
covers a projected line. Shared lines count once globally; separate owners and
blocks remain separate. Function coverage uses each owner's independent entry
counter. Complexity is E−N+2 on the typed normal CFG with one common exit;
parallel edges count, while unwind/cleanup, imaginary and coroutine-drop paths
are excluded. CRAP is exactly `CC² × (1 − covered_lines / lines)³ + CC`.
These rules intentionally differ from the old source/LLVM series; no old baseline
is imported, rewritten, or treated as comparable.

All declared lib/bin Cargo targets must be compiled. Separate integration-test
crates are recorded and excluded by target ownership, with their counters retained.
Mixed `cfg(test)` production library builds are unsupported and fail closed.
Dependency/std/generated dependency regions require a unique declared source root;
unknown roots fail. Project source files absent under the selected cfg remain in
the lexical source inventory as `compiler_loaded=false`, not "no executable code".
Build scripts remain raw build evidence and are excluded from application metrics.
Incremental compilation is disabled and rejected: cached custom MIR cannot safely
reuse generated SourceMap identities. Flags, selected cfg/features/targets, tool
hashes, Cargo manifests/lockfile, collector and projection rules partition history.

## Policy and tests

`../rust_native_policy.py --help` accepts two separately anchored captures,
reviewed base/head contexts, explicit hotspot selections, `--repository-root`,
`--policy-binding` and a released
`harness-gate` binary. It emits generic typed evidence and calls `quality evaluate`.
The [project policy](../../../docs/quality/native-crap-policy.md) supplies the exact
CRAP ceiling; line/region thresholds remain 80%. Aggregate coverage is required;
changed CC>10 functions and selected hotspots require all thresholds, other
changed functions require CRAP, and all historical rows require non-regression.
Unchanged debt is reported, not erased. Missing or incompatible history rejects.
Compiler owner identity supports conservative content comparison across moves;
renames/splits/merges require reviewed `--mappings`, validated by Generic Core.
No permissive name heuristic or automatic baseline acceptance is provided.

```sh
export CARGO_TARGET_DIR="$PWD/target/native-validation"
export HARNESS_GATE_NATIVE_POLICY_BINARY="$PWD/target/native-validation/debug/harness-gate"
cargo build --locked --manifest-path tools/harness-gate/Cargo.toml
python3 -m unittest discover -s tools/quality/tests -p test_rust_native_driver.py -v
```

The real tests require the two `NATIVE_DRIVER*` variables above; without them they
report an explicit skip. They retain each real compile/sample/export and the
Rust policy outputs under `target/gh-220/driver-tests`. Small fixtures establish
their own scope only. The pinned Arc-Admin report and scope limitations are indexed
in [GH-220 evidence](../../../docs/quality/gh-220/README.md).

## File classification

`../rust_native_classify.py` projects a complete native mapping onto **every**
production source. `--evidence RAW --anchor REVIEWED_SHA --output REPORT` performs
native certification before classification. Runtime owners retain real counts;
zero hits require positive measured denominators. Loaded declaration/CTFE-only
files can be `not_applicable` for that compilation, with null metrics. Module
exports do not imply parent machine code; macro calls can generate runtime owners.
Neither a filename nor a missing LLVM row is an exclusion rule.

For feature exclusions, compile the same project twice with the same `--sample`
selection and optional Cargo `--feature NAME`. Pass the second raw capture as
`--witness RAW --witness-anchor SHA`. Only an otherwise compatible complete mapping
with executable origins for the absent source proves feature-scoped exclusion.
Unexported sources, missing owners and incompatible configurations remain errors.
The fixture test retains both real captures under `target/gh-221/file-tests`.

Reviewed historical archives require **both** `--reviewed-report REPORT.json.gz`
and its independently trusted `--report-sha256 SHA`, in addition to the original
manifest anchor. This mode checks every retained artifact, replays Cargo selection
and the full compiler-to-LLVM join against the accepted report, and records absent
original binaries. It does not re-export LLVM or access recorded external paths.
Classification success is exit 0 even if the preserved measurement fails coverage
thresholds; this report never accepts a baseline or changes a gate.
The [GH-221 evidence](../../../docs/quality/gh-221/README.md) includes all 47 backend
files, the five historical omissions and reproducible retained-archive inspection.
The old LLVM file-summary series remains separate and unresolved.
