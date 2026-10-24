# runtime-importer 0.7.0 publication and acceptance

Published 2026-10-24 as an immutable independent release. This receipt binds the
published archive, the exact Core pin, the declared compatibility and the real
engine acceptance. It does not change any earlier importer or adapter artifact.

## Release identity

- [Release runtime-importer-v0.7.0](https://github.com/musutrade/GateProbes/releases/tag/runtime-importer-v0.7.0)
- PR [#86](https://github.com/musutrade/GateProbes/pull/86), head `43d67eda199c00c372b80c6bd7f2ab50330e3534`, merged as `5f2b171977edab0e724a0c65367719d113904c14`
- Annotated tag object `e754ac47e1d4bfbfc6f123a9614b6ba0983aab39`, target exactly the merge above
- PR CI `40081467431`, main CI `40081763069`, release `40082285885`: attempt 1, success
- Inventory source: `musutrade/GateProbes` at `5f2b171977edab0e724a0c65367719d113904c14`

## Published artifacts

| Subject | SHA-256 |
| --- | --- |
| `gateprobes-runtime-importer-0.7.0.tar.gz` | `591fd260f914a252b1bb93d3e52df9eb0f75f207fa2c5f38dc324e9401563129` |
| `gateprobes-runtime-importer-0.7.0.tar.gz.sbom.cdx.json` | `be223867b4208017cf8c587d148920fe4b16d59635e32f21b3bbdecf8ba61ce4` |
| `SHA256SUMS` | `f22b66ef40ccf72354ea05d3b2d9991ec5e68e8f96a9eea537c8696253d3923c` |
| `release-inventory.json` | `1be7c37208456fd90aab269ed448206d06601960d03d7d29728b95b088fbb181` |

The archive and SBOM digests equal the locally accepted candidate. All four
subjects passed `cosign verify-blob` with certificate identity
`https://github.com/musutrade/GateProbes/.github/workflows/collector-release.yml@refs/tags/runtime-importer-v0.7.0`
and issuer `https://token.actions.githubusercontent.com`, and all four passed
`gh attestation verify` with signer workflow
`musutrade/GateProbes/.github/workflows/collector-release.yml`.

## Declared identity

- Manifest version `0.7.0`, authority `offline-installation-only`
- `core_versions`: `0.13.0`, `0.14.1`
- Core pin `plugins/runtime-importer/core-pin-podman.json`: release `v0.14.1`, source `c22a12e25a5ea6f617d4afb9dd4e2410dc14f267`, binary `harness-gate-linux-amd64`, SHA-256 `6b4f36d432266e43e22d82776729d76f04098c5cf63ae2295f508359a37e060c`
- Runtime pin `tools/runtime_import/release-pin-podman.json`: unchanged `podman-lifecycle-v0.3.0` archive `044a1e9d…`, executable `efca5ba3…`
- The installer writes the unchanged `gate-runtime/lifecycle-installation-v1` descriptor for `podman-lifecycle` `0.3.0`

The installer itself validates adapter members, pinned digests and the mutation
manifest. It never reads or executes Core; Core version and digest are checked by
the packaging and acceptance harness before publication.

## Downloaded acceptance

The downloaded release archive was extracted and exercised directly.

- Installer acceptance (`accept_importer_podman07.py`): 8 cases pass, including
  descriptor mode 0400, executable mode 0500, no operator state, refused capture
  profile, and the fixed 0.5/0.6 historical pins.
- Real rootless Podman 5.7.0 normal lifecycle with the published
  `podman-lifecycle 0.3.0` assets, one fresh Core-owned container per run:

| Core | Origin | SHA-256 | Container | Result |
| --- | --- | --- | --- | --- |
| 0.14.1 | Downloaded published Core | `6b4f36d432266e43e22d82776729d76f04098c5cf63ae2295f508359a37e060c` | `gatehouse-bce274130786f633eb86616cedf517bc` | released, exact post-remove absence |
| 0.13.0 | Downloaded published Core | `1800325ea2f541dd9b011c03dc93c3dac341e839ece6289ebe778275dcaacf75` | `gatehouse-370ca404c153943220038f82ecdc36f8` | released, exact post-remove absence |

Both runs created, started, health-checked, exercised over HTTP, stopped and
removed only their own container. The independent absence check returned exactly
1 and each service record records the released reservation with a post-remove
tombstone.

## Boundaries

- Linux x86_64, rootless Podman 5.7.0, normal lifecycle only. No daemon restart,
  additional platforms, OS containment or fleet migration is certified.
- Historical importer 0.1 through 0.6 artifacts, pins and tags are unchanged; the
  0.6 archive still verifies with its own acceptance script.
- `podman-lifecycle 0.3.0` is an immutable published artifact whose manifest still
  declares Core `0.13.0` and its packaging-time candidate wording. That wording is
  packaging history, not a statement that the adapter is currently unpublished;
  see the [adapter status receipt](podman-lifecycle-0.3.0-status.md).
- This receipt is a public acceptance declaration. It does not replace Core's
  exact installation-descriptor gate, does not modify any published manifest, and
  does not add a new Core, version range or digest allowlist.
