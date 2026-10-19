# GateHouse Linux test workload scope

Tracking: [GateProbes #26](https://github.com/musutrade/GateProbes/issues/26),
[GateHouse #140](https://github.com/musutrade/GateHouse/issues/140).
The data-only preset is implemented; independent package/real-Core acceptance
and release are pending. No successful workload run is claimed yet.

The comparison source is GateHouse
`e65514947e7d4f5e9c65cab91ff3765e102fdb44`, `.github/workflows/ci.yml`.
The Linux Test job at that revision runs four nextest partitions, with two
special tests run separately on the first shard. A local unpartitioned workload
must include those tests rather than copying the CI exclusion expression and
silently losing coverage. The pinned nextest version is `0.9.143` in
`.github/actions/install-ci-tool/tool.sh`. The workflow selects stable Rust;
that floating selector is not a tool identity. Actual executable digests and
versions must be recorded and independently approved for a workload run.

The minimal implementation reuses ordinary Core flow declarations.
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

## Fixed package preparation

`products.json` uses the existing `gateprobes-products/v1` catalog, and
`preset/catalog.json` uses Core's existing `harness-preset-catalog/v1`. No new
loader, runtime or protocol is required. The signed package includes the exact
flow, toolchain declaration and this coverage description. The explicit Core
version is compatibility metadata, not a claim of validation before acceptance.

Prepare with an operator-owned Ed25519 key using the existing package manager:

```sh
python3 tools/onboarding/plugin_manager.py prepare \
  --catalog workloads/gatehouse-linux-test/products.json \
  --product gatehouse-linux-test \
  --signing-key /protected/operator.pem --key-id reviewed-operator \
  --output /new/prepared --lock-output /new/workload.lock.json
```

The emitted lock pins exact version, source, manifest digest and signer. Use the
existing `plan`/`apply` commands and Core's explicit trusted-key input to install
that artifact. Copying the prepared package/lock to a separate consumer host
does not require a GateProbes source checkout. Core verifies the signed manifest
and file hashes before using the preset; do not substitute `latest` or repin
modified bytes merely to make acceptance pass.

Preset adoption is explicit: the project owner reviews the resulting workflow
and its required checks/quality policy. Installation alone does not alter those
files. The preset adds no quality policy or collector and cannot stand in for
full-quality verification. Do not overwrite an existing project flow to adopt it.

The host must provide the toolchain in `toolchain.json`, verify protected tool
bytes and configure native Cargo state, pinned test data and any required
acceptance-output environment before invocation. `doctor` prints selected tool
versions but does not enforce the nextest pin or prove host isolation. The
workload does not install tools, fetch source, change caches or create credentials.
Its command runs all Rust nextest tests, including the two special CI tests,
without partition/filter exclusions. Other rows above remain separate coverage.

Package publication, fixed artifact SHA, real execution evidence and Core
compatibility acceptance are still pending. Native caches remain controlled by
the execution account; no workload cache key, GC service or volume is introduced.

## Release distribution and installation trust

The fixed distribution is `gateprobes-gatehouse-linux-test-1.0.0.tar.gz`,
selected by `gatehouse-linux-test-v1.0.0`. Release eligibility, immutable tag,
exact successful main CI, protected `release` environment, inventory/checksums,
Sigstore workflow identity and GitHub provenance reuse the existing
`.github/workflows/collector-release.yml` process. Verify the release inventory,
asset digest and expected repository/workflow identity before extracting or
executing any bundled installer. A checksum downloaded from an unauthenticated
source alone is insufficient.

There are two distinct trust decisions. The repository workflow authenticates
the distribution archive. An operator then reviews the fixed data and uses their
own approved Ed25519 key to prepare a Core installation manifest and lock. Core
continues to verify that operator signature against explicitly trusted keys;
Sigstore provenance is not converted into a Core `plugin.sig`. No operator
private key, disposable acceptance signature or generated install lock is shipped.

After verifying and extracting the release, run the preparation example above
from the extracted top-level directory. The archive includes the declared
workload files, product catalog, existing `tools/onboarding/plugin_manager.py`
and LICENSE, so `--source` may point to that directory without any GateProbes
checkout. Python 3.11+ and OpenSSL are host prerequisites for preparation; the
pinned Rust/nextest tools remain prerequisites for actual workload execution.

The release packager checks extraction and installation/plan compatibility with
the pinned released Core using a disposable key in a temporary directory. This
is package compatibility evidence, not another execution of the real 749-test
workload or proof of either platform's host isolation. A declared release name
here does not imply the tag or its assets have already been published.
