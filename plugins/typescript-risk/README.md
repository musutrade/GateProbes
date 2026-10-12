# TypeScript risk collector plugin (candidate 0.1.0-rc.4)

An independently installed Node measurement plugin. Core owns thresholds,
requiredness, ratchets and final decisions. Existing reference presets and Core
code are unchanged. This candidate does not relabel legacy unsupported evidence.

## Installation and tests

```sh
npm ci --ignore-scripts
npm test
HARNESS_GATE_BINARY=/absolute/core-0.4.5 npm run test:core
npm pack
npm install --prefix /private/plugin-root ./harness-gate-typescript-collector-0.1.0-rc.4.tgz
/private/plugin-root/node_modules/.bin/harness-gate-typescript-collector --version
```

Node 24 and TypeScript 6.0.2 are explicit dependencies. The npm shrinkwrap pins
installation. No parent repository Python modules or Core checkout are runtime
dependencies. Install the package and dependencies in a trusted runtime and pin
the entire runtime, including Node and transitive code. npm version metadata does
not authenticate package bytes or grant a signing identity. Signed candidate packages are distributed as GitHub release assets; see
[the Harness-Gate release guide](https://github.com/musutrade/Harness-Gate/blob/main/docs/releases/0.4.8.zh-CN.md).

## Measurement contract

Original TypeScript is instrumented with istanbul-lib-instrument 6.0.3 **before
transpilation**. Native Istanbul maps must join exact TypeScript AST coordinates;
remapped Angular CLI/V8 coverage, TSX and generated template functions are not
accepted. Angular application acceptance uses original-source instrumentation,
then the real Angular builder and Vitest. It certifies original TypeScript
measurement, not template branch coverage or equivalence with mapped V8 reports.

Every `.ts` file under the caller's source root is inventoried, including names
ending in `.spec.ts` or `.test.ts`. Ambient `.d.ts` files are excluded automatically;
other exclusions must be exact, host-approved paths. Source symlinks, escapes,
invalid UTF-8/TypeScript, missing/extra coverage files, duplicate functions, stale
bytes, malformed counters and ambiguous coordinates fail closed.

Function identities contain source SHA-256, path, AST kind, UTF-16 span and
project/component/target/boundary. Named declarations and function expressions
join at the name; methods and accessors join at node start. Nested callable
bodies have their own owner and never inherit parent complexity or coverage.

CC is a versioned AST decision count: 1 plus if, conditional expression, loop,
catch, non-default switch case, short-circuit operator, logical assignment,
optional chain and parameter/binding default initializer. It is not Rust MIR
complexity, a full control-flow graph or cognitive complexity.

Function line coverage uses native statement-start lines owned by the innermost
function, with maximum hits on a shared line. Optional `include_files: true` also
emits file-level line coverage for **all** statement-start lines, including code
outside functions. This is line coverage, not branch coverage. A tested condition
and untested return on the same line may share a covered line.

CRAP = CC² × (1 − covered/total)³ + CC, emitted as an exact reduced rational.
There is no threshold option or rounding fallback. Empty denominators emit
`not_applicable` without numeric values. File subjects mark function-only
metrics not applicable; no aggregate file CRAP is invented. All records declare
the complete series capability set as required by Core.

AST discovery reports `declarationOnly` only for empty files, interfaces, type
aliases and explicit type-only imports/exports. The host may use this to select
executable files for coverage policy while retaining declaration source identities
and evidence. A zero native denominator alone never authorizes an exclusion.
Side-effect imports, classes, functions and variables are not declarations-only.

## Measurement and project protocols

Without arguments, stdin is `harness-collector-request/v1` and stdout is exactly
one `harness-collector-response/v1`, containing `harness-evidence/v1` facts and raw
artifact descriptors. `inventory` emits discovery candidates for host review.
The request contains project/component/collector/context, canonical roots,
requested capabilities and parameters: source_root, boundary, coverage, subjects,
receipt, optional exclude and include_files.

The receipt schema is `typescript-original-coverage-receipt/v1`. It binds:

- `request`: `binding()` context and source scope, including file participation.
- `sources`: exact sorted path/SHA-256 inventory; `coverage_sha256` and original
  absolute `coverage_root` bind retained native counters.
- `toolchain`: TypeScript, instrumenter, original instrumentation rule and Node.
- Optional `pipeline`: `typescript-capture-pipeline/v1`, with tool versions and
  configuration/script path hashes. It contributes to measurement-series identity.
- Optional `inputs`: capture source/test/template path hashes, checked against
  retained source bytes. These bind the capture without treating every source
  edit as a toolchain-series migration.

`project --binding /absolute/binding.json --binding-sha256 HEX` implements the
published signed adapter-v2 envelope. The host-produced
`typescript-project-collector-binding/v1` contains `input` (the exact compiled
`harness-project-collector-request/v1`), `config_digest`, and `request` (the
measurement request above). The bridge verifies Core invocation environment,
signed arguments, binding digest, context, complete subject/capability/series
claims and source/capture pins before publishing artifacts. Project requests
must select the complete four-metric series. Use subject-scoped policy rules
for file line coverage and function complexity/coverage/CRAP respectively.

Core authenticates the adapter executable, signature, freshness and nonce. Its
response is `schema_version: "1"`, transport `status: "PASS"`, matching invocation,
artifacts and `harness-project-collector-response/v1` collection. Transport PASS
only means measurement completed; Core still evaluates policy. The plugin never
creates signing keys, trust stores, approved baselines or production workflow state.

## Acceptance scope

15 unit tests cover native maps, exact arithmetic, top-level coverage and erased
types. Four integration tests cover released Core's exact 10/11/partial-coverage
boundary, artifact tampering, independent executable protocol, and the project
binding bridge. CodexSymphony additionally runs its real Angular tests followed
by host-signed Core collection/evaluation and negative tests for stale context,
expired signatures outside Core's clock-skew allowance, tampered signatures,
replay and changed artifacts. See the repository's retained acceptance record.

Local frontend acceptance does not certify whole-project Rust/API-contract gates,
production host isolation, hosted CI protection, templates or all Angular projects.
The package remains a candidate until reviewed release and deployment acceptance.
