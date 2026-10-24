# harness-gate-rust-measure

Development-only AST inventory used by the repository's function-risk gate.
It is never linked into the `harness-gate` product binary.

This tree reports `harness-gate-rust-measure/0.4.0` with rule
`mccabe-rust-3`. Core's current production consumer (merge
`6ec99b8f56477ce1b79a12a16e93f745eee6bb42`) accepts exactly that identity and
rejects the old 0.3.1 identity; there is no fallback. The old candidate
contract remains historical evidence, not the current production route.

## Pinned artifact

`tools/release/package_plugin.py --plugin rust-measure` builds, tests and
clean-installs the pinned package
`harness-gate-rust-measure-0.4.0-linux-amd64.tar.gz`. The package carries the
binary, `plugin.json`, `Cargo.lock`, the license and this README.

Two explicit acceptance routes are retained:

- **Current production**: `production_contract.py` verifies the fixed merged
  Core source in `production-core.json`, the immutable published
  `rust-measure-v0.4.0` binary in `production-release.json`, and the real
  published 0.3.1 binary. It requires the Core production consumer to accept
  the new identity and reject old/unknown/wrong-rule/wrong-target identities.
- **Historical candidate**: `candidate_contract.py` keeps the earlier fixed
  Core source `d76a313...` and its dual-expectation evidence. It is not
  renamed to current production and does not authorize a new release.

CI runs the current-production route first, then the historical candidate
route. `tools/release/package_plugin.py` builds a new artifact and therefore
runs the historical candidate route; it does not pretend a freshly built
binary is the immutable downloaded release. `0.3.1` continues through the
historical `contract.py`. A missing or mismatched fixed input fails closed.

0.4.0 evaluates recursive `cfg` predicates (`test`, `unix`, `windows`,
`target_os`, `not`, `all`, `any`) using the compiler target configuration and
removes item-level `cfg_attr(test, derive(...))` from the production view.
Unsupported predicates, inner attributes and positions fail closed.
