# GateProbes

Independent collector plugins for [Harness-Gate](https://github.com/musutrade/Harness-Gate).
GateProbes owns language/tool-specific measurement. It never decides gate
pass/fail and never approves permission: the released Harness-Gate Core owns
protocol validation, budgets, thresholds, baselines and the final decision.

## Layout

| Path | Contents |
| --- | --- |
| `plugins/typescript-risk/` | TypeScript plugin: original-TypeScript AST complexity, coverage and exact rational CRAP |
| `plugins/rust-measure/` | Rust plugin: AST inventory consumed by the pinned Core function-risk gate |
| `plugins/http-json-contract/` | TypeScript plugin: HTTP/JSON contract and Angular client-drift measurement |
| `plugins/rust-source-risk/` | Python-entry plugin with a Rust AST inventory: Rust source complexity, coverage and CRAP |
| `plugins/rust-native-plugin/`, `plugins/rust-native-driver/` | External-toolchain native plugin: compiler-private MIR driver plus the unpackaged plugin builder (Linux acceptance) |
| `plugins/registry.json` | Plugin registry: directory, language, platforms, entries and shared protocols |
| `protocol/collector-protocol.schema.json` | Generated copy of the Core host contract; Core is the editable source |
| `docs/ownership.json` | Migration provenance, path mapping and the pinned Core contract identity |
| `tools/ci/` | Change classifier, lightweight checks, aggregate and their tests |

## Migration provenance

The initial source snapshot records the Harness-Gate repository, the full source
commit and the path mapping in `docs/ownership.json`. Historical CI logs,
screenshots, manual acceptance reports, build caches, old binaries and Git
history are intentionally not copied.

## CI tiers

`.github/workflows/ci.yml` always starts, classifies the change and ends in one
fixed `Required Quality Aggregate` check. Selection values must be present and
valid; a missing or invalid selection, unknown scope or a classification failure
never passes. Unknown scope runs the conservative full set.

| Change | Routed checks |
| --- | --- |
| Any | Lightweight declaration, link and forbidden-artifact checks (stdlib, no language toolchain) |
| `plugins/<name>/**` | That plugin's language checks and the pinned-Core protocol acceptance |
| A registered shared protocol | Only the plugins that declare that protocol in `plugins/registry.json` |
| Other shared paths (`tools/**`, `.github/**`, root manifests, `docs/ownership.json`, `LICENSE`) | All registered plugins (conservative) |
| Unknown, empty diff or classification failure | Conservative full set, and the aggregate fails closed |

`plugins/registry.json` registers each plugin's directory, language, toolchain
list, supported platforms, install/test/contract/package entries and the shared
protocols it depends on. The classifier turns changed paths into an affected-plugin matrix carrying
each plugin's registered install/test/contract/package entries; toolchains are
selected per language and the commands come from the registry. The plugin job
unconditionally verifies that an executor exists for the selected language and
fails explicitly for anything other than Rust and TypeScript today; a planned
language is opened only in the change that adds its executor and registry entry
in the same round. All plugins share the same
protocol acceptance: startup, I/O format, error handling and compatibility with
the pinned Core release identity in `docs/ownership.json`. Rust plugins also carry the checked-in
`clippy.toml` threshold (cognitive complexity 10) and enable the lint as a
warning. Plugins with `cargo_checks: true` additionally run `cargo fmt` and
`cargo clippy -D warnings`; the native plugin uses its dedicated `build.py`/
rustc path instead, so its declared lint settings are not a claim that the
directly compiled launcher ran Clippy. This round registers Linux acceptance
only; other platforms and release/signing migration are not done yet.

## License

MIT. See [LICENSE](LICENSE).
