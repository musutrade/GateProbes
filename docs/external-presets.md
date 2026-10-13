# External ecosystem presets

`presets/catalog.json` owns the Rust, Angular and mixed Angular/Rust/Postgres
initialization templates and their Rust, TypeScript and API-contract packs.
[Migration provenance](preset-migration.json) records the original Core commit,
source/destination paths and byte digests. Generic flow, audit/secrets templates,
quality base and initialization/decision behavior remain Core-owned.

The Core file-loader change uses an explicit directory:

```sh
harness-gate presets --presets-dir /path/to/GateProbes/presets
harness-gate init --preset rust-api --presets-dir /path/to/GateProbes/presets
```

`HARNESS_GATE_PRESETS_DIR` is the equivalent CLI default; an explicit flag takes
precedence. Select a reviewed, fixed GateProbes checkout. The Core does not fetch
or execute catalog code, search the network, or fall back to historical fixture
copies. The embedded `generic` preset remains available without this directory.
The released Core 0.4.8 predates this loader; it still embeds its original presets.
Use a Core build with the loader before using the new option.

The catalog contains `schema: harness-preset-catalog/v1`, a `presets` object
(name to description/flow/optional recipe), and a `packs` object (name to JSON
path). Paths are relative to the catalog. Core rejects unknown schemas, duplicate
JSON keys, path traversal, symlink input paths, non-regular/missing inputs and
oversized files. Preset names cannot replace `generic`. Existing generated
project configurations need no migration.

## Acceptance

The required `External preset compatibility` job downloads the digest-pinned
Core 0.4.8 binary and checks every migrated template against its embedded output,
including generated flow, every pack file, policy/collector participation and
`config check`. This proves unchanged migration data; it is not evidence that
Core 0.4.8 understands the new loader. The aggregate rejects a failed, skipped,
cancelled or missing selected preset job. Pure documentation does not fetch Core.

For a candidate Core with the new loader, run:

```sh
python3 tools/presets/accept.py --core /absolute/path/to/harness-gate --external
```

This initializes real temporary projects from the external files and checks the
same output and policy boundaries. No plugin measurements or baseline are
fabricated. A future template change must explicitly update its compatibility
contract; unchanged copied bytes alone never establish new ecosystem support.

The native acceptance suite also carries the unchanged portable-artifact tests
and real file-classification tests recorded in
[native test provenance](native-test-handoff.json). It supplies a real driver and
sysroot on all four native platforms and fails on any skip. Legacy runtime,
historical TypeScript formats and generic Core policy/reference tests remain
with their existing Core consumers.
