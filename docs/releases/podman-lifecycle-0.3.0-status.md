# podman-lifecycle 0.3.0 published status

Published 2026-10-24 (the release itself predates this note) as an immutable
independent artifact. This note records the current status and the exact
boundary between the published bytes and later acceptance evidence.

## Release identity

- [Release podman-lifecycle-v0.3.0](https://github.com/musutrade/GateProbes/releases/tag/podman-lifecycle-v0.3.0)
- Source commit `c802fffaee9fdbea1ce9d4642ac14cb998882b20`
- Archive `gateprobes-podman-lifecycle-0.3.0-linux-amd64.tar.gz`, SHA-256 `044a1e9d6d7be82ca8e83b8f810ce6c266825a793d77f418d14efd13a69d69a0`
- SBOM SHA-256 `f66dbe03e8c7b1f8cc20f93b1ad3857ec908b6f4158073965a2b515a64bbf262`
- Inventory SHA-256 `8713afa1cb1fa52509d36541ffc8d0098a6defc00f2ba1bc4e5beb8793a5bc4b`
- `SHA256SUMS` SHA-256 `389c309ec6deb477815e25c6919616f17cbcbdfd27acfc9c27dba76a902bf12c`
- Adapter executable `gateprobes-podman-lifecycle`, SHA-256 `efca5ba3b8e8bbbf0d7cce0efdce12b3f58fba190e01ba790bac81650c972d9d`, mode 0500 after installation

All four integrity subjects pass `cosign verify-blob` with certificate identity
`https://github.com/musutrade/GateProbes/.github/workflows/collector-release.yml@refs/tags/podman-lifecycle-v0.3.0`
and issuer `https://token.actions.githubusercontent.com`, and pass
`gh attestation verify` with signer workflow
`musutrade/GateProbes/.github/workflows/collector-release.yml`.

## Immutable manifest boundary

The published `plugins/podman-lifecycle/plugin.json` inside the archive still
declares:

- `core_versions`: `["0.13.0"]`
- `status`: `development-candidate`
- limitations text written at packaging time, including "package archive,
  signature, registry and downloaded-Core acceptance remain unpublished"

Those fields are immutable packaging history. They are **not** a current statement
that the adapter is unpublished, and this note does not claim they were edited.
Changing them would require a new adapter version and new tag; no such release is
made here.

## Verified current interoperability

The published bytes are consumed through the published runtime importer, which
pins this exact archive, SBOM, inventory and executable digest and writes the
unchanged `gate-runtime/lifecycle-installation-v1` descriptor
(`product` `podman-lifecycle`, `version` `0.3.0`).

`runtime-importer 0.7.0` was verified with this adapter on two published Core
binaries:

- Core `0.14.1` (`6b4f36d4…`): real rootless Podman 5.7.0 lifecycle pass,
  service released, exact post-remove absence
- Core `0.13.0` (`1800325e…`): real rootless Podman 5.7.0 lifecycle pass,
  service released, exact post-remove absence

See the [importer 0.7.0 receipt](runtime-importer-0.7.0-acceptance.md) for the
exact runs, containers and digests.

## Boundaries

- The current support statement is a public acceptance declaration, not a Core
  installation gate. Core still accepts exactly the installation descriptor
  `(podman-lifecycle, 0.3.0)` with its digest and protected-path checks.
- No new Core, global digest allowlist, version range or policy change is
  introduced to work around the archived wording.
- Acceptance covers Linux x86_64 rootless Podman 5.7.0 normal lifecycle only.
  No daemon restart, additional platforms or fleet migration is certified.
- No historical tag, asset, signature or archive was modified.
