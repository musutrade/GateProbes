# Published rust-source-risk 0.3.0 acceptance

[Immutable release](https://github.com/musutrade/GateProbes/releases/tag/rust-source-risk-v0.3.0),
release ID `423131213`, source `3f6cd00dab33d75ab8c4963629c63edea942a0bb`.
Annotated tag object `1d02f4bd2c7d54fbcc031db87b1b76046846bb0e` points to that source.

| Subject | SHA-256 |
|---|---|
| Linux amd64 archive | `d576b98b6fa1b68cd79ec216c2a9978cfb81f8adec2cc8975c056a4854f5e515` |
| CycloneDX SBOM | `c0c8c544e125424d38459205f727c177d966fb8afbf4c2534f721b09c71577ae` |
| release-inventory.json | `98abfeb0018530c4fcfadebb58eb254492541bf53dfaf1e08ec99ec0823b4bad` |
| Published Core 0.14.1 Linux amd64 | `6b4f36d432266e43e22d82776729d76f04098c5cf63ae2295f508359a37e060c` |

[PR CI 40158219405](https://github.com/musutrade/GateProbes/actions/runs/40158219405),
[main CI 40158667378](https://github.com/musutrade/GateProbes/actions/runs/40158667378)
and [normal release 40159131323](https://github.com/musutrade/GateProbes/actions/runs/40159131323)
succeeded at attempt1, with source/extracted native/preflight suites each running
66 tests and zero skips. That history is distinct from the new recurring public
download consumer job; it does not retroactively claim that job ran in those runs.

After actual publication, all 12 assets and nine package members were downloaded
and verified. Cosign verified the four integrity subjects with exact identity
`https://github.com/musutrade/GateProbes/.github/workflows/collector-release.yml@refs/tags/rust-source-risk-v0.3.0`
and issuer `https://token.actions.githubusercontent.com`. GitHub provenance was
constrained to that tag, source and signer commit. Fresh downloaded-runtime
capture and signed published Core0.14.1 collect/evaluate passed with four records
and five capabilities. All ten reason-specific protocol/evidence negatives failed
as required. Identical real evidence with CRAP2/1 against the isolated1/1 limit
produced transport PASS and final policy FAIL; production limits were unchanged.

[Published pins](../../plugins/rust-source-risk/published_acceptance.json) and the
[runner](../../plugins/rust-source-risk/published_acceptance.py) repeat this as a
separate required regression. They fix release bytes, signatures/provenance,
cosign version/digest, fixture/harness/presets and Core identity. Downloads are
verified before executing runtime bytes. Cached cosign is digest checked; failures
never fall back. New outer public receipts retain inner candidate validator
schema/scope and bind a new bundle/receipt by hash. Immutable package README and
old candidate receipts are packaging history and remain unchanged.

The accepted distribution is Linux x86_64 and a bounded syntactic thiserror/cfg
subset. No Rust name resolution or macro-origin proof, alias/re-export support,
full-project coverage or real-user deployment is claimed. Current/historical
audit/scope inventory succeeds; secrets anyhow and verify anyhow/print/env macros
remain unsupported. Actual Core-project capture rejects repository-wide build.rs
(including a fixture outside the selected crate) and unsupported Cargo config.
A project host still owns trust provisioning, signed requests, explicit subjects
and new-series adoption. Core's own Risk CI uses the distinct rust-measure0.4
analyzer; no production source-risk pin or MIR compatibility row is added. Old0.2
assets/regression, Core policy, thresholds and baselines stay unchanged. GP91 and
GH108 remain open; GH107 remains closed.
