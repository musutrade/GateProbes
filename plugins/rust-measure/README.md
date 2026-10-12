# harness-gate-rust-measure

Development-only AST inventory used by the repository's function-risk gate.
It is never linked into the `harness-gate` product binary.

The only accepted identity is `harness-gate-rust-measure/0.3.1` with rule
`mccabe-rust-3`. `tools/quality/source_measure.py` fails closed on any other
analyzer, version or rule, so a mismatched binary cannot silently change the
measurement series.

## Pinned artifact

`tools/release/package_independent_collectors.py` builds, tests and clean-installs
the pinned package `harness-gate-rust-measure-0.3.1-linux-amd64.tar.gz`, and the
core `v*` release publishes it with an SBOM. The package carries the binary,
`plugin.json`, `Cargo.lock`, the license and this README.

The follow-up core/plugin split change makes core CI consume that released
artifact instead of compiling this directory from source; until then core CI
still builds the measurer from the checked-out source.
