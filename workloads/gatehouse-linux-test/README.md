# GateHouse Linux test workload scope

Tracking: [GateProbes #26](https://github.com/musutrade/GateProbes/issues/26),
[GateHouse #140](https://github.com/musutrade/GateHouse/issues/140).
This is the implementation scope record, not a released or validated workload.

The comparison source is GateHouse
`e65514947e7d4f5e9c65cab91ff3765e102fdb44`, `.github/workflows/ci.yml`.
The Linux Test job at that revision runs four nextest partitions, with two
special tests run separately on the first shard. A local unpartitioned workload
must include those tests rather than copying the CI exclusion expression and
silently losing coverage. The pinned nextest version is `0.9.143` in
`.github/actions/install-ci-tool/tool.sh`. The workflow selects stable Rust;
that floating selector is not a tool identity. Actual executable digests and
versions must be recorded and independently approved for a workload run.

The minimal implementation will reuse ordinary Core flow/runner declarations.
It will not parse project policy, select required checks, evaluate thresholds,
run a Python quality engine, or emit a project PASS. Core owns those decisions.
Measurement/execution outputs and the fixed artifact will remain here, outside
Core. Consumer-side packaging and acceptance must use a fixed Core executable;
no plugin source checkout may be required by Core to build or run its tests.

## Coverage inventory to preserve explicitly

| Source operation | Workload boundary |
| --- | --- |
| All nextest test binaries, including the two separately selected acceptance/export tests | Include in local test command; preserve actual test inventory and receipts |
| Findings-feedback and report-artifact Node tests | Separate command declarations if included; cannot be implied by Rust test success |
| Configured workflow acceptance receipt validation | Preserve actual generated evidence and existing validator; no new evaluator |
| Generated flow/quality schema comparison | Explicit local check if claimed; no commit or push operation |
| Fixed external onboarding acceptance | Fixed external artifact dependency; never implicitly fetch/build plugin source inside Core |
| Checkout, tool installation, cache setup and pinned-data restore | Execution environment preparation, outside quality execution/decision |
| Artifact uploads and GitHub output publication | External consumer work, outside Core completion |

No current fixture or local unit-suite pass claims all rows. Full Linux Test
coverage needs actual commands, tool identities, inventory and retained execution
evidence. Linux test coverage is also distinct from the separate quality/risk
coverage stages in that workflow. No CI jobs will be migrated, removed or triggered
by implementing the workload.

Package publication, fixed artifact SHA, real execution evidence and Core
compatibility acceptance are still pending. Native caches remain controlled by
the execution account; no workload cache key, GC service or volume is introduced.
