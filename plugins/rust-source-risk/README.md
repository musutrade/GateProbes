# Rust source-risk collector

This is an independent Harness-Gate collector plugin. It does not modify Core,
change a policy threshold, sign its own requests, or replace the MIR measurement
series. The original MIR collector remains useful for generated-code diagnostics.

## Local thiserror candidate (unpublished)

The working source adds the restricted metadata subset below. Published 0.2.0
bytes and `core_acceptance.json` are unchanged and still reject these helpers.
The inherited development `plugin.json`/collector version remains 0.2.0; it is
**not** the identity of a new published 0.2.0 artifact. Candidate receipts use
`rust-source-risk-local-candidate-acceptance/v1`, scope
`local-unpublished-candidate`, a pinned archive/member manifest and source commit.

Only the literal syntactic path `derive(thiserror::Error)` on a struct/enum
establishes context. Each struct or direct enum variant requires one `error`
attribute. Context does not propagate into other items, methods or nested types.
Other derives in that context are limited to unqualified built-in spellings
`Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, `PartialOrd`, `Ord`, `Hash`, `Default`.
Unknown custom derives/attributes fail closed. Derive attributes are allowed
only on the owning struct/enum; every derive attribute on a direct variant is
rejected, including empty and malformed lists. Derive behavior outside this
context is unchanged. These spellings do not prove macro dependency origin:
there is no Rust name resolution, alias/re-export support, or proof against
shadowing. Real acceptance binds the fixture Cargo.lock (thiserror 2.0.20),
compiler/LLVM identity, original source and exact implementation hashes.

The template grammar is exactly one `LitStr`, containing ordinary text, `{{`,
`}}`, or `{field}`/`{field:?}`. `field` must be an existing named field or a
canonical decimal tuple index (`0`, `1`, ... with no leading zeros). Empty or
nonexistent fields, mismatched braces, additional arguments/expressions,
callbacks, and all other format specifications are rejected. `error(transparent)`
is the only non-string form and requires exactly one field.

`from` and `source` must be argument-free flags on direct fields. A single field
named `source` is explicitly treated as an implicit source. A `from` field also
selects the source, and requires a one-field owner. Repeated flags, multiple
source fields, and combined explicit `from` plus `source` are rejected. Explicit
`source` on the implicitly named source field has the same meaning, not a second
source. Transparent wrappers may use `from`, but explicit/implicit `source` with
transparent is outside this subset. Backtrace helpers, a field named `backtrace`,
and direct `Backtrace` type spellings are rejected; aliases are not resolved.
Unsupported conditional field/variant/member attributes remain rejected.

All handwritten functions, methods and closures are still traversed at their
original spans and exact anchors. No unknown/generated native record is filtered
by this change. Native mapping still rejects unmatched/ambiguous owners,
multifile expansion and missing authored counters. The integration fixture
executes literal/tuple/named formatting, transparent conversion, explicit and
implicit `Error::source`, and handwritten branches/methods/closures. The native
test adds an unexecuted function and checks its zero coverage and CC, then injects
faults into actual LLVM export/inventory inputs to verify mapping rejection.

Build the inventory, run `test_thiserror_native.py` with a capture-compatible
isolated Cargo environment, then from a clean committed worktree run:

```sh
python3 plugins/rust-source-risk/local_candidate.py --output /absolute/new-output \
  --core /absolute/published/harness-gate-linux-amd64
```

This builds and hashes an unpublished local archive, captures from its extracted
runtime, and calls the separate `candidate_acceptance.py` entrypoint. That
entrypoint requires `--pins` and `--pins-sha256`, rejects release claims and
changes to the fixed published Core identity, and runs the existing signed
collect/evaluate chain, ten protocol/evidence negatives and real fixture-policy
failure. `core_acceptance.py` without the internal candidate entrypoint keeps the
published-release schema/inventory checks and existing current-release CI pins.
No CI workflow changes are included in this local candidate.

A future independently published version requires a reviewed version/tag/asset
and immutable inventory/provenance, updated collector identity and contracts,
new downloaded-artifact acceptance, and then a separate Core consumer review.
Even before a version bump the changed inventory binary changes the existing
series rule digest; fixture Cargo.lock and toolchain affect the tool digest.
Do not relabel old reports/baselines or add a native MIR compatibility row.

Checking the historical four #107 producer files is source-inventory evidence
only: the candidate accepts audit/errors.rs and scope/errors.rs; secrets/mod.rs
still rejects anyhow macros, and verify/mod.rs still rejects anyhow, print and
env macros. This does not revive #107 or certify full production measurement.
Risk registration/series, explain coverage/mutations and critical-path binding
remain separate Core consumer responsibilities. Core gains no Rust parser,
threshold, baseline, debt, ratchet or policy change here. Linux x86_64 only.

## Measurement contract

`rust-explicit-decisions` starts each source callable at 1 and adds:

- 1 for each `if`/`if let`, `for`, `while`, `?`, `let ... else`, `&&`, and `||`;
- `max(match arms - 1, 0)` plus 1 per match guard;
- 1 for `matches!`, plus 1 for its optional guard.

An unconditional `loop` adds no decision. Functions, methods, default trait
methods, closures and explicit async blocks have separate owners. Nested owners
are not charged to their parent. Async state machines and generated derive/logging
control flow do not contribute to source complexity. This is a **new series**;
its numbers are not interchangeable with MIR CC or another tool's CC definition.

Supported expression macros are `matches!`, comma-separated expression arguments
of `tracing::{info,warn,error,debug,trace}!`, and `sqlx::migrate!`. User expressions
inside those arguments are visited (including `?`). Unsupported macro grammar,
other macros, item macros, unsupported conditional-compilation attributes and unrecognized
attributes fail closed. The collector does not pretend to measure arbitrary Rust
macro expansions. Generated derive bodies are outside this source-only scope.

Original source positions are parsed with pinned `syn` 2.0.119. UTF-8 character
columns are converted to LLVM byte columns. LLVM 3.1.0 code-region exports join
only at exact AST entry anchors, never by a function name or basename fallback.
Every inventoried source callable needs a native mapping. Unknown region kinds,
cross-file expansions, duplicate native instances and ambiguous joins are rejected.
All `.rs` files under explicitly approved source roots are inventoried, including
files with only declarations. These declaration files have no function metrics.

Async factory counters do not cover the async body: only its execution/poll
mapping contributes to line, region and function coverage. Equal source ranges
from distinct native instantiations are merged by covered/not-covered status.
Innermost code ranges override enclosing ranges; nested callable ranges are
removed from the parent. A non-whitespace code interval is a line opportunity,
and any covered opportunity covers that line. Unknown gap/expansion region kinds
are currently rejected rather than guessed. This is source region coverage, not
branch coverage or a claim about implicit error/cleanup paths in MIR.

`CRAP = CC + CC² × (1 − covered_source_lines / source_lines)³`, represented as a
reduced exact rational. A missing denominator is not applicable, never zero risk.
Core alone evaluates the required **CRAP ≤ 10** policy. Full coverage therefore
passes CC=10 and still fails CC=11.

## Trust and transport

`capture.py` copies explicitly listed build/test inputs before executing locked
Cargo tests. It retains original binaries and `.profraw` counters, hashes source,
configuration, inputs and native tools, and records the exact toolchain. Capture
is a **local host utility**, not a production signing or isolation service.
A source commit field identifies the baseline; hashes bind actual dirty input
bytes. It is not an assertion that the capture is a clean checkout of that commit.

The collector revalidates those bytes and independently runs pinned
`llvm-profdata merge` and `llvm-cov export`. It does not trust a supplied coverage
summary. Raw native capture files remain in the receipt's retained `raw_root`;
archive this directory with the bundle for replay. Emitted evidence contains the
re-exported LLVM data and capture receipt. Production hosts must protect both
capture provenance and the signing key from repository-controlled tests.

The adapter-v2 bridge validates Core invocation context, signed binding digest,
complete subject/capability claims, and configuration identity. Core authenticates
signatures, rejects stale/replayed requests, validates artifacts and evaluates
policy. A transport `PASS` means collection succeeded, not that quality passed.

Artifacts use an exclusive `artifact_subdir` inside Core's shared output root so
other independent collectors can publish their own directories in the same run.
Existing files in this plugin's directory are rejected. Collectors never issue
quality overrides or contain signing keys.

## Build and use (source checkout)

The following build commands require the repository checkout. The published
archive already includes `inventory` and its runtime `ast/Cargo.lock`; preserve
both when installing or moving the plugin.

```sh
cargo build --locked --release --manifest-path ast/Cargo.toml
# Copy the resulting harness-gate-rust-source-inventory binary to ./inventory.
python3 -m unittest discover -s . -p 'test_*.py' -v
python3 plugin.py discover --request /absolute/request.json
python3 plugin.py collect --request /absolute/request.json
```

Capture binds the recorded target/cfg and rustc version to the actual snapshot cwd and
fails closed on compiler, wrapper, target, rustflags/rustdocflags, linker/runner or
`[env]` overrides from the repository, snapshot ancestors or `CARGO_HOME`. A clean
`CARGO_HOME` without such overrides is required; the user's global configuration is
never modified. Project `build.rs`/custom `build =` scripts are rejected because
`cargo:rustc-cfg` output is not part of `rustc --print cfg`; `feature` and other
custom cfg predicates are likewise rejected. A supported capture environment therefore
does not claim that the base compiler cfg is the complete effective cfg for arbitrary
build scripts.

`capture.py --help` documents snapshot arguments. `acceptance.py --bundle BUNDLE
--plugin PLUGIN_DIRECTORY` is the older backend-only, ephemeral-key Core
rehearsal. It refuses a real checkout and checks signature, stale context,
expiration, replay and artifact tampering. It is not the required CI gate.

## Pinned Core current-consumer acceptance

`core_acceptance.py` is the required CI acceptance for the immutable published
0.2.0 archive. It does not build, republish or relabel 0.2.0. The fixed release
and Core pins are in `core_acceptance.json`; the script rejects a missing,
changed or extra archive member, a changed archive, release inventory or Core
binary, a wrong Core version, a wrong toolchain, a missing clean `CARGO_HOME`,
and a non-empty artifact root.

```sh
python3 core_acceptance.py   --bundle /path/to/fresh/capture/bundle.json   --archive /path/to/harness-gate-rust-source-risk-0.2.0-linux-amd64.tar.gz   --release-inventory /path/to/release-inventory.json   --core /absolute/path/to/harness-gate-linux-amd64   --presets-dir /path/to/GateProbes/presets   --output /path/to/acceptance/receipt.json
```

The runner performs a fresh `capture.py` on the committed
`fixtures/core-acceptance` project before this command. The acceptance keeps the
one-time signing key and replay state outside the measured workspace, verifies
the complete signed `harness-project-collector-request/v1` path, runs the
separate `quality evaluate` policy path, and writes a machine receipt with all
source, archive, member, tool, Core, series and result identities. The replay
ledger is a private directory under the system temporary root, so Core's
ancestor protection check does not depend on unrelated runner-directory modes.

The ten required negatives are layered: four signed-collect failures
(`stale-context`, `expired`, `tampered-signature`, `replay`), then six
evaluate failures (`tampered-artifact`, `wrong-target`, `wrong-version`,
`wrong-source`, `missing-metric`, `missing-evidence`). Each case asserts its
specific expected reason; an unexpected success or a generic nonzero exit is a
failure. A separate real measured policy-fail case uses a fixture-only CRAP
limit to prove that transport `PASS` is not a final policy `PASS`.

The CI job `source-risk-core-acceptance` is a **current consumer regression**
against the already published 0.2.0 archive and the published Core 0.14.1
binary. It does not claim that the historical 0.2.0 publication was gated by
this acceptance. A future source-risk release must run the same acceptance
against its candidate archive after the static `contract.py` check; that
packaging integration is a separate release-design change, not a 0.2.0
re-release.

The native MIR `rust-collector-compatibility.json` matrix does not apply to this
generic project collector, so no matrix row is added. The `thiserror`
`error`/`from`/`source` macro attributes remain unsupported; this acceptance
does not broaden them.

Future release-gate design (not implemented for 0.2.0): after the existing
static `contract.py` check in `tools/release/package_plugin.py`, extract the
candidate archive and run the same signed collect/evaluate matrix against that
candidate, deriving archive/member pins from the candidate release inventory.
Do not substitute the immutable 0.2.0 archive for a candidate, and do not treat
the current 0.2.0 consumer regression as candidate-artifact acceptance.

The reviewed GH-288 Linux x86-64 matrix passed for Rust 1.97.1 / LLVM
22.1.6 and Rust 1.99.0 / LLVM 23.1.1: each ran the existing 26 tests and
seven compatibility tests, using cargo-llvm-cov 0.9.0 and Python 3.14.
The retained Core build is bb813b8; its production sources are byte-identical
to 3d887's Core, and its recorded identity is preserved. This does not certify
later changed Core bytes or the Rust 1.99 compiler-private native ABI.
The combinations have distinct measurement series and adopt no baseline.
New syntax/LLVM formats require compatibility tests and a new identity before
adoption; existing captures and baselines are never relabeled.
See [the completed matrix and evidence contract](https://github.com/musutrade/Harness-Gate/blob/main/docs/quality/gh-288-source-risk-compatibility.md)
for exact evidence paths, identities, rejection boundaries and source/native choice.

References: [LLVM coverage mapping](https://llvm.org/docs/CoverageMappingFormat.html)
and [Rust instrument-coverage](https://doc.rust-lang.org/rustc/instrument-coverage.html).

## rc.2 business-source support

Declarative Serde deny-unknown-fields, tag/content, rename and skip metadata are
accepted; callback/custom metadata remains unsupported. json!/serde_json::json!
containers recursively visit every Rust expression, including object keys, nested
arrays, branches and closures. format!/std::format! visits expression arguments.
Unknown macros and malformed grammar still fail closed. Generated macro/derive
control flow remains outside this source-only metric. Exact LLVM entry anchors
include the argument of single-argument Ok/Err/Some closure bodies, where Rust
lowering omits the constructor wrapper. No nearest-position/name fallback is used.

## Select source syntax candidate

Fully qualified `tokio::select!` accepts `biased;`, future branches, optional
preconditions, block handlers without commas, and a final `else`. Complexity
adds alternatives minus one, syntactically refutable patterns, and preconditions.
Source decisions in futures, guards, and handlers are visited normally; nested
closures and async blocks retain their own source owners. Macro-generated poll
loops are excluded. Identifier bindings, wildcards, and empty tuple patterns are
syntactically irrefutable under this rule; this is not name/type resolution.
Malformed syntax and unknown nested macros fail closed. This syntax support does
not waive exact LLVM ownership or missing execution counters.

## Closure entry mapping candidate

Closure entry anchors follow the leading source AST expression through constructor
wrappers (`Ok`, `Err`, `Some`, including generic arguments), tuples, arrays, struct
fields, parentheses, unary/reference/cast/try/await expressions, and the first
operand or condition. Only structurally derived entry positions are accepted;
there is no nearest-position, name-based, or arbitrary contained-region fallback.
Nested callable ownership and source decision counts remain separate. A closure
returning an async block can have its factory counter at the closing brace;
this does not count the future as polled or cover its body.

`test_closures.py` compiles and executes real instrumented Rust fixtures, exports
LLVM coverage, and checks the joined metrics. The tests include uncalled closures,
unpolled async blocks, nested owners, and rejection of a later tuple element
masquerading as the entry. Set `RUST_SOURCE_INVENTORY` to test a candidate binary.

Set `RUST_SOURCE_TEST_EVIDENCE` to a new evidence directory to retain original
sources, binaries, raw profiles, merged profiles, exports, exact tool identities,
command/status/stdout/stderr records and measured/rejected results from
`test_measure.py` and `test_closures.py`. Without that option their disposable
fixtures retain the existing cleanup behavior. The two-toolchain certification
runner sets this option and builds its own AST analyzer in each combination's
fresh target directory. Normal unittest discovery adds only its static contract
test; expensive certification is an explicit command. Missing prerequisites in
that command block certification, never silently skip or use another toolchain.

Some trivial projection closures (for example `|value: &i32| *value`) have no
independent coverage record in the tested compiler output. These still reject:
source syntax does not prove execution, and a parent's execution count must not
be substituted. Missing mappings are reported together, with source locations
and callable kinds, instead of requiring repeated attempts to expose each one.

The production view evaluates item-level `cfg` predicates for `test`, `unix`, `windows` and
`target_os` (linux/macos/windows), including recursive `not`/`all`/`any`, using the exact
target configuration recorded by capture. Exact `cfg(test)` modules and items are excluded;
`cfg(any(test, ...))` evaluates the remaining production branch. Item-level
`cfg_attr(test, derive(...))` is removed from the production view; other `cfg_attr` predicates,
inner attributes and positions fail closed. Item-level filtering covers `syn::Item` positions;
conditional attributes on fields, enum variants, trait/impl members, expressions, match arms
and file attributes remain unsupported and fail closed. The measurer retains its existing
field/impl/expression support; this is a documented position difference, not a claim that both
tools accept every position. Unsupported predicates such as `feature` and unrecognized
attributes (including thiserror `error`/`from`/`source` metadata) still fail closed.

## Signed candidate distribution

The Linux x86-64 archive includes the compiled `inventory`, Python entrypoints,
license, manifest and this guide. Rust/LLVM and Python remain external. See the
[release installation guide](https://github.com/musutrade/Harness-Gate/blob/main/docs/releases/0.4.8.zh-CN.md).

## rc.6 package completeness

RC6 includes the dependency lockfile read by the measurement-series fingerprint.
The published RC5 archive omitted this file and cannot form a series. RC6 keeps
the measurement formulas unchanged, but its new collector identity and executable
pins require explicit host binding review. Release acceptance now extracts the
archive and runs the full runtime suite against its installed files.

## rc.7 complete compatibility diagnostics

Capture scans every production source file in the captured input snapshot before
starting cargo/llvm-cov. Unsupported syntax and Serde metadata are collected
across files, including all diagnostics emitted for each file. A rejected source
inventory never becomes a partial production boundary.

After native coverage is available, measurement collects unmatched or ambiguous
entry anchors, uninventoried project functions, and missing source-owner counters
before reporting failure. No measurements or successful capture bundle are
returned when any mapping is missing or ambiguous; parents' hits are never
substituted. Unsafe paths, unavailable tools, malformed native data and duplicate
native identities still stop immediately because continuing cannot be trusted.

This change does not broaden accepted Rust syntax, change coverage/CRAP formulas,
or lower thresholds. The new version and implementation digest require an
explicit host binding update; existing signed captures retain their old identity.

## Stable distribution boundary

The 0.2.0 identity does not change measurement algorithms or toolchain pins; it adds the recorded target configuration to the series identity and supports the conditional-compilation subset above. `coverage.region` retains its documented exact source-region meaning; it is not branch coverage or MIR cleanup coverage. The historical archive's README and manifest say v0.6.0; the repository's static release contract actually pinned Core v0.7.1 (`docs/ownership.json`). Neither statement is a full Core 0.14.1 consumer gate. The separate current-consumer acceptance above uses published Core 0.14.1 and the immutable 0.2.0 archive. `release-gated` identifies this release-controlled distribution, not a production isolation/signing service. Linux x86_64 is the accepted distribution scope; previous RC evidence remains historical.
