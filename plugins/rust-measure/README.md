# harness-gate-rust-measure

Development-only AST inventory used by the repository's function-risk gate.
It is never linked into the `harness-gate` product binary.

This candidate tree reports `harness-gate-rust-measure/0.4.0` with rule
`mccabe-rust-3`. Core's production pin still expects `0.3.1`; the explicit
0.4.0 consumer candidate is checked separately and the production pin is not
changed by this tree. `tools/quality/source_measure.py` fails closed on an
analyzer, version or rule it does not accept, so a mismatched binary cannot
silently change the measurement series.

## Pinned artifact

`tools/release/package_plugin.py --plugin rust-measure` builds, tests and
clean-installs the pinned package
`harness-gate-rust-measure-0.4.0-linux-amd64.tar.gz`. The package carries the
binary, `plugin.json`, `Cargo.lock`, the license and this README.

Release acceptance is version-routed by `candidate_contract.py`: `0.3.1`
continues through the historical `contract.py`; `0.4.0` uses the fixed Core
candidate source and the fixed published 0.3.1 binary recorded in
`candidate-core.json` / `legacy-release.json`. A missing or mismatched fixed
input fails the contract.

0.4.0 evaluates recursive `cfg` predicates (`test`, `unix`, `windows`,
`target_os`, `not`, `all`, `any`) using the compiler target configuration and
removes item-level `cfg_attr(test, derive(...))` from the production view.
Unsupported predicates, inner attributes and positions fail closed.
