# GateProbes

Independent collector plugins for [Harness-Gate](https://github.com/musutrade/Harness-Gate).
GateProbes owns language/tool-specific measurement. It never decides gate
pass/fail and never approves permission: the released Harness-Gate Core owns
protocol validation, budgets, thresholds, baselines and the final decision.

## Layout

| Path | Contents |
| --- | --- |
| `plugins/typescript-risk/` | First migrated plugin: original-TypeScript AST complexity, coverage and exact rational CRAP |
| `protocol/collector-protocol.schema.json` | Generated copy of the Core host contract; Core is the editable source |
| `docs/ownership.json` | Migration provenance, path mapping and the pinned Core contract identity |
| `tools/ci/` | Change classifier, pure-documentation checks and their tests |

## Migration provenance

The initial source snapshot records the Harness-Gate repository, the full source
commit and the path mapping in `docs/ownership.json`. Historical CI logs,
screenshots, manual acceptance reports, build caches, old binaries and Git
history are intentionally not copied.

## CI tiers

`.github/workflows/ci.yml` always starts, classifies the change and ends in one
fixed `Required Quality Aggregate` check. Unknown paths or a classification
failure never pass: unknown scope runs the conservative full set, and a
classification failure fails the aggregate.

| Change | Routed checks |
| --- | --- |
| Pure documentation | Formatting, links and declarations only; no Rust or Node toolchain |
| `plugins/typescript-risk/**` | That plugin's install, unit tests and pinned-Core contract acceptance |
| `protocol/**`, `tools/**`, `.github/**`, root manifests | Expanded set: documentation checks and all plugin checks |
| Unknown | Conservative full set |

`docs/ownership.json`, protocol schemas and test inputs are inputs, not ordinary
documentation. The pure-documentation tier never treats them as docs.

## License

MIT. See [LICENSE](LICENSE).
