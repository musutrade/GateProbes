# Independent plugin releases

The four collectors below publish through
`.github/workflows/collector-release.yml`. Native Rust continues to use
`native-collector-release.yml`. The relevant Harness-Gate engineering-policy
semantics are unchanged: collectors measure; Core owns protocol validation,
thresholds, requiredness, baseline/ratchet rules and final decisions. Moving
publication does not certify new measurement capabilities or reset a series.

| Plugin | Initial independent tag | Archive |
| --- | --- | --- |
| TypeScript risk | `typescript-risk-v0.1.0-rc.4` | `harness-gate-typescript-collector-0.1.0-rc.4.tgz` |
| HTTP/JSON contract | `http-json-contract-v0.1.0-rc.5` | `harness-gate-http-json-contract-collector-0.1.0-rc.5.tgz` |
| Rust source risk | `rust-source-risk-v0.1.0-rc.7` | `harness-gate-rust-source-risk-0.1.0-rc.7-linux-amd64.tar.gz` |
| Rust measurer | `rust-measure-v0.3.1` | `harness-gate-rust-measure-0.3.1-linux-amd64.tar.gz` |
| GitHub result consumer | `github-check-v1.0.0` | `gateprobes-github-check-1.0.0.tar.gz` |

The GitHub result consumer is not a measurement collector: it maps an
operator-pinned saved Core result to an already provisioned Check and never
recomputes quality. It uses the same release workflow, signed inventory and
eligibility gates as the collectors.

All four collector tags were published as immutable releases on 2026-10-13 from
`f9834a988e9e55ec99b7ebe81fb67a9ca16b2928`, after exact-commit main CI passed.
Independent public download and installation acceptance passed; see the
[Core handoff receipt](https://github.com/musutrade/Harness-Gate/blob/796556875e362d8c5035c53860fc32718052309d/docs/quality/independent-plugin-release-acceptance.json). Source-risk and measurer
archives retain their Linux x86-64 scope; npm packages retain Node 24 and their
existing Linux acceptance. Other operating systems are not newly certified.
Consumers must select an explicit plugin tag. The four workflows pass
`--latest=false`; GitHub currently resolves this repository's latest stable
release to `rust-collector-v0.1.0`, so `/releases/latest` remains not a plugin selector.

## Published acceptance

| Plugin | Successful release run | Public package installation |
| --- | --- | --- |
| TypeScript risk | [38339077287](https://github.com/musutrade/GateProbes/actions/runs/38339077287) | 21 tests and the pinned Core decision contract |
| HTTP/JSON contract | [38338985149](https://github.com/musutrade/GateProbes/actions/runs/38338985149) | 21 tests and the pinned Core collector contract |
| Rust source risk | [38338987066](https://github.com/musutrade/GateProbes/actions/runs/38338987066) | 26 tests without skips and the pinned Core metric contract |
| Rust measurer | [38338989282](https://github.com/musutrade/GateProbes/actions/runs/38338989282) | Extracted analyzer/version/rule identity and Core AST consumer contract |

The 48 downloaded files match the four signed inventories. All 16 integrity
subjects passed exact-tag Sigstore identity and exact-source GitHub provenance
checks. Wrong repository and wrong tag identities were rejected. Fresh public
package installs passed on Linux x86_64 with Node 24.18.0 and Rust 1.97.1 for
source-risk. Runtime dependencies stay inside each Node production install;
withholding TypeScript causes the installed CLI to fail. No plugin or Core
binary was rebuilt for this public-package acceptance. Historical releases and
measurement identities remain intact.

[Core PR #353](https://github.com/musutrade/Harness-Gate/pull/353) removes the
four-plugin packaging dependency after this acceptance. Core's existing
measurer consumption pin remains unchanged; source cleanup and ordinary CI
migration remain separate work.

## Stable identity publications

| Plugin | Stable tag | Release run |
| --- | --- | --- |
| TypeScript risk | `typescript-risk-v0.1.0` | [39241085432](https://github.com/musutrade/GateProbes/actions/runs/39241085432) |
| HTTP/JSON contract | `http-json-contract-v0.1.0` | [39242780489](https://github.com/musutrade/GateProbes/actions/runs/39242780489) |
| Rust source risk | `rust-source-risk-v0.1.0` | [39245030106](https://github.com/musutrade/GateProbes/actions/runs/39245030106) |
| Native collector | `rust-collector-v0.1.0` | [39261930009](https://github.com/musutrade/GateProbes/actions/runs/39261930009) |
| GitHub actions | `github-actions-v1.0.0` | [39236644757](https://github.com/musutrade/GateProbes/actions/runs/39236644757) |
| Operator lifecycle | `operator-lifecycle-v0.1.0` | [39276038756](https://github.com/musutrade/GateProbes/actions/runs/39276038756) |

The four collector promotions kept their predecessor capability/toolchain
semantics and were verified from downloaded artifacts against pinned released
Core v0.6.0. GitHub actions were checked from the extracted archive with 16 Node
tests and byte parity against the migrated actions; this is not a Core binary
compatibility test. Operator lifecycle acceptance used the downloaded binary
with pinned Core v0.6.0 in disposable projects. These verifications preceded the
corresponding Core copy removals. No stable release claims production deployment
or additional platform certification.

## Remaining runtime boundary

All currently registered plugins have published releases. This does not mean
that every externalizable Core implementation has moved: Docker/Podman service
lifecycle remains in Core. The Core #62 design and fake-runtime experiment are
not a released runtime adapter. `operator-lifecycle` manages Git hooks and canary
markers; it does not implement container lifecycle. The Postgres recipe checks
service readiness; its managed-mode result does not certify container creation,
removal or recovery.

The Postgres v0.1.1 archive retains its release-time README. The subsequent
repository README links the completed verification receipt; this documentation
update does not change the released binary or require replacing immutable
assets. Use the [verification receipt](postgres-service-0.1.1-verification.md)
for that later evidence.

## Version and eligibility contract

`plugins/releases.json` maps each plugin to its tag prefix and asset name.
Versions come from that plugin's identity and package/lock manifests. The
adapter rejects missing plugins, malformed or stale tags and disagreement
between these manifests. Plugin versions are independent of the Core version.
The first releases retain the existing collector versions and measurement
identities; previous Core releases remain available and unchanged.

`plugin_release.py verify` calls the unchanged generated Core policy checker
for real tag-to-commit binding, reachability from protected `main`, a successful
`ci.yml` push run for that exact commit and its successful
`Required Quality Aggregate`. It records this evidence before packaging.
Only a plugin tag starts the release workflow. PR/main CI retains its existing
change classification; it does not run a second complete packaging matrix.

## Packaging and acceptance

The packaging job fetches the Core release, Linux binary SHA-256, version and
separate Python consumer/schema source pin specified by
`docs/ownership.json`'s `core_contract`. The consumer source is explicitly pinned independently; the current pin
matches the Core v0.7.1 release source. The binary is identified by its release
tag and digest.
Acceptance executes that released binary and its pinned Python consumers.
It never compiles Core or substitutes a locally built Core executable.
The pinned Core's SBOM generator remains a temporary build input.

Each tag packages one plugin from this repository and verifies the installed
archive: npm packages receive a fresh production-only install, run their
protocol tests from the installed runtime and exercise the pinned Core contract;
installed Node processes have no source dependency search path. Only the copied
test harness receives an absolute Istanbul test-tool import. Runtime dependency
paths must resolve inside the clean consumer, and temporarily removing its
TypeScript dependency must make the installed CLI fail.
Rust source risk runs its suite against the extracted program and checks the
Core metric contract; the measurer checks its extracted identity and the Core
AST consumer. Rust archives include precompiled programs. Rust, LLVM, Python,
Node and other external environments are not bundled or silently installed on
consumer machines. Source-risk measurement series and external toolchain
requirements remain those documented by the plugin.

For a local candidate, use fresh output directories outside the checkout:

```bash
python3 tools/release/pinned_core.py --output /tmp/gateprobes-core-contract
python3 tools/release/package_plugin.py --plugin typescript-risk \
  --core-root /tmp/gateprobes-core-contract --output /tmp/typescript-release-candidate
```

Local packaging requires the declared external tools (Node 24 or Rust 1.97.1
with LLVM tools and Rust documentation, plus Python). It is a candidate check;
the workflow still performs its own eligibility, packaging and signing gates.
Routine lightweight tests use only the Python standard library. Full packaging
runs only for a selected tag and has a 35-minute job limit; native publication
continues on its existing platform workflow.

## Integrity and installation

Each release includes exactly its package, CycloneDX SBOM, release inventory,
checksum manifest, and their Sigstore signatures/certificates. The package-only
inventory adapter uses the shared inventory schema and regular-file/hash
validation. All checksum, signature, attestation, upload-set and final inventory
verification operations use the unchanged generated Core inventory tool.
Additional or missing files block publication.

The signing identity is the exact tag ref:

```text
https://github.com/musutrade/GateProbes/.github/workflows/collector-release.yml@refs/tags/<plugin-tag>
```

Verify the inventory with this identity and GitHub's OIDC issuer
`https://token.actions.githubusercontent.com`, then use its explicit subject
list to verify every Sigstore signature, checksum and GitHub provenance
attestation. Provenance must name
`musutrade/GateProbes/.github/workflows/collector-release.yml`. A checksum alone
does not establish publisher identity. After verification, install a `.tgz`
with `npm install --ignore-scripts` or extract the Rust archive into a fresh
directory and follow that plugin's README. Never use the Core workflow identity
to accept a newly published GateProbes artifact.

Publication requires the `release` environment, uses short-lived GitHub OIDC
credentials and refuses any existing release tag. Fixes require a new plugin
version/tag; existing releases are never overwritten. Core's legacy packaging
job can be removed only after these four signed releases and their actual
installation acceptance have succeeded.

On 2026-10-13, GateProbes enabled immutable releases for future publication and
the active `release-tags` ruleset (ID `24964258`). It forbids updates and deletion
of all five collector tag prefixes, with no bypass actors. Historical RC8 retains
its original `immutable=false` state; this migration does not rewrite it. The
workflow also refetches tag/main references and repeats exact-commit eligibility
immediately before publication, with the release target bound to `GITHUB_SHA`.


## Postgres release line (2026-10-14)

`postgres-service-v0.1.1` is published as an immutable release with archive
`gateprobes-postgres-0.1.1-linux-amd64.tar.gz`. Independent public verification
passed all 12 files and four integrity subjects; the exact public pair passes
47 real service/doctor/verify records and all three installed presets. See the
[final receipt](postgres-service-0.1.1-verification.md).
It uses the same eligibility, installed package acceptance, complete signed
inventory, exact-tag Sigstore/provenance and immutable publication gates.
Core v0.4.9 is incompatible with `service_checks`. The independently verified
[Core v0.5.0](core-0.5.0-verification.json) is now pinned; packaging checks the
actual released binary's schema and fails for incompatible Core. Ordinary CI does not substitute candidate Core or skip this contract.
Local candidate installed acceptance is separate. See the [plugin guide](../plugins/postgres-service/README.md).

On 2026-10-14 the active release-tags ruleset was extended to
`refs/tags/postgres-service-v*`. Existing matches, update/deletion prohibitions
and the empty bypass list were preserved. The new plugin follows the same
immutable release flow.

The `postgres-service-v0.1.0` tag remains unchanged at
`a5e321ec67de2fad04fd8bdc45bbf8cb564439cb`. Its [release run](https://github.com/musutrade/GateProbes/actions/runs/38545979584)
passed eligibility and installed package acceptance, then failed before publication:
checkout had a peeled local tag and `git fetch --tags` rejected the annotated
remote object as clobbering that ref. No 0.1.0 release was published. The new
publication refresh fetches the exact remote tag to a separate ref and checks its
commit before the unchanged exact-main eligibility check. A mismatched remote
commit still blocks. Existing tags/assets are never force-updated. Version 0.1.1
contains this workflow correction; Postgres check semantics and Core pin are unchanged.

Native installation is owned here; use the [fixed, verified standalone entry](native-installation.md) for install/upgrade/rollback. The Core installer has retired plugin execution.

## Onboarding preset distribution

`onboarding-presets-v1.0.0` packages both existing rust-minimal and python-minimal products, installer, and acceptance CLI. Published through the normal release gates as run [39225207743](https://github.com/musutrade/GateProbes/actions/runs/39225207743); the downloaded bundle ran the 29-step onboarding acceptance against fixed released Core v0.6.0. Linux x86_64 is the acceptance platform; declarations for other targets are not new certification. Distribution provenance and operator installation signing remain separate.

## GitHub platform actions

`github-actions-v1.0.0` moved the advisory findings-feedback and optional report-artifact upload implementations and tests to GateProbes; published as run [39236644757](https://github.com/musutrade/GateProbes/actions/runs/39236644757) and verified from the downloaded archive. Both retain explicit opt-in transport; neither participates in Core quality decisions. Use a full reviewed source commit for Actions references or a verified fixed archive. The duplicated Core copies were removed after that verified download acceptance.

## Core 0.7.1 compatibility update in progress

The active Core contract pins the four downloaded v0.7.1 assets from
`26734c7055870c1c9c4014bf75039d55b8c91ad8`. Onboarding presets 1.0.2 is already
published and has downloaded-Core Linux acceptance. Linux workload 1.0.1 and
GitHub Check 1.0.1 are new compatibility candidates; their manifests do not
constitute publication or multi-platform acceptance. Existing release artifacts
and their historical Core evidence remain unchanged. Native Docker runtime
remains unregistered and unreleased; fake-socket checks are not daemon acceptance.

### Native Docker build reproducibility and Core acceptance

The musl repair compares archive and SBOM bytes from Ubuntu 22.04 and 24.04.
Ubuntu 22.04 performs build-only reproducibility checks; Ubuntu 24.04 also runs
strict extracted-package acceptance against downloaded Core 0.7.1. That Core
binary emits a weak `GLIBC_2.39` loader warning on Ubuntu 22.04, so this matrix
does not certify Core compatibility there. Successful acceptance still requires
empty stderr. The release packaging entry always runs Core acceptance; the
build-only function is not a release acceptance substitute. The pre-version-bump repair passed cross-runner equality in CI run
39535862193; each new artifact version must pass that comparison again. The published
`docker-runtime-v0.1.0` assets remain immutable.

## Published runtime importer and Podman lifecycle (2026-10-24)

`runtime-importer-v0.7.0` is published with an exact Core 0.14.1 pin and declared
Core 0.13.0/0.14.1 compatibility; downloaded-archive acceptance passed against
both published Core binaries. See the
[importer 0.7.0 receipt](releases/runtime-importer-0.7.0-acceptance.md).

`podman-lifecycle-v0.3.0` is published and independently verified, but its
immutable packaged manifest still declares Core 0.13.0 and packaging-time
candidate wording. That wording is packaging history, not a current unpublished
fact; the receipt records the verified interoperability without editing the
artifact or Core's installation gate. See the
[adapter status receipt](releases/podman-lifecycle-0.3.0-status.md).

Both entries cover Linux x86_64 rootless Podman 5.7.0 normal lifecycle only; no
daemon restart, additional platforms or fleet migration is certified.

## Published Rust source-risk 0.3.0 (2026-10-25)

`rust-source-risk-v0.3.0` is immutable and independently downloaded-byte verified;
see the [public receipt](releases/rust-source-risk-0.3.0-acceptance.md). Its packaged
candidate wording is immutable preparation history, not current unpublished status.
The separate published03 consumer gate fixes public bytes and crypto identities,
then runs fresh four-record signed Core0.14.1 acceptance, ten specific negatives
and a real policy failure. The original published0.2 regression and new-build
candidate gate remain independent. This does not upgrade Core's distinct
rust-measure0.4 analyzer, provision a real project's trust/series, reopen #107 or
certify full Core-project capture. Linux x86_64 only; documented config/build.rs
and unsupported-macro boundaries remain.
