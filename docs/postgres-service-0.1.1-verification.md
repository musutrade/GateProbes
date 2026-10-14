# Postgres externalization: public acceptance

Accepted 2026-10-14 for GateHouse #24. **PASS** for the independently downloaded Core v0.5.0 and GateProbes Postgres v0.1.1 pair on Linux x86_64.

Postgres URL isolation, health, recipes, ecosystem preparation and legacy migration are owned by GateProbes. Core retains generic required checks, bounded execution, service lifecycle and final blocking. Old policies require explicit migration; frozen historical inputs and earlier failure records remain available. See the [consumer inventory and pre-release notes](https://github.com/musutrade/GateHouse/blob/main/docs/quality/postgres-externalization.md), [Core public receipt](https://github.com/musutrade/GateHouse/blob/main/docs/releases/0.5.0-public-verification.md) and [upgrade guide](https://github.com/musutrade/GateHouse/blob/main/docs/releases/0.5.0.zh-CN.md). This final receipt supersedes pending-delivery statements in the dated pre-release notes.

- [Core v0.5.0](https://github.com/musutrade/GateHouse/releases/tag/v0.5.0): exact main CI and release passed; all 21 assets and seven exact-tag Sigstore/provenance subjects independently verified. Public binary and registry installations pass generic verification with complete evidence.
- [Plugin v0.1.1](https://github.com/musutrade/GateProbes/releases/tag/postgres-service-v0.1.1): [exact main CI](https://github.com/musutrade/GateProbes/actions/runs/38547630782) and [signed release](https://github.com/musutrade/GateProbes/actions/runs/38548206084) passed. All12 public files and four integrity subjects verified against complete inventory, API digests, checksums, exact-tag certificate identity and exact source/signer commit. Release is immutable.
- The hosted 47-record installed contract and downloaded public binary have identical plugin/Core digests. The public pair also passes 47 records with a TCP-ready isolated Postgres server and real pg_isready. A closed target port blocks doctor, dependent step and verify while the same server remains ready on 5432. Missing/tampered/incompatible/timed-out/crashed/failed checks block; migration, upgrade rebinding, privacy and offline import assertions pass.
- The installed package generates a separate catalog; all three presets pass configuration and execution/quality parity. Original steps, collectors/policies and full/ci membership are preserved. The temporary container is removed. No image, toolchain or system dependency was installed by acceptance.

The original 0.1.0 tag and failed publication run are retained: its package passed, but annotated tag refetch failed before release creation. The corrected 0.1.1 workflow fetches the remote tag into a separate ref, requires its commit to match, then repeats unchanged release eligibility. Positive and changed-remote regressions execute the actual workflow block. No immutable tag or old release was rewritten.

Engineering Policy thresholds, required gates, baseline/debt/ratchet, measurement series and release authority are unchanged. Real health acceptance means server readiness; it does not establish authentication or SQL success. The suite uses controlled fixtures for negative/managed scenarios. Other platform plugin runtime acceptance is not claimed.

## Machine receipt

```json
{
  "schema": "gatehouse-postgres-public-acceptance/v1",
  "date": "2026-10-14",
  "status": "pass",
  "issue": "musutrade/GateHouse#24",
  "core": {
    "tag": "v0.5.0",
    "source": "b178d3fe4f35018cd000dd291b324ff13ecc1c76",
    "binary_sha256": "198597ff623ce006d6f19261a352ca7a6d82a7c58af7bbba75de3c4076cd26a7",
    "main_ci": 38538172051,
    "release_run": 38542930583
  },
  "plugin": {
    "status": "pass",
    "repository": "musutrade/GateProbes",
    "tag": "postgres-service-v0.1.1",
    "commit": "b1cc618e17a56dd6c220c29852e79769d0db7723",
    "certificate_identity": "https://github.com/musutrade/GateProbes/.github/workflows/collector-release.yml@refs/tags/postgres-service-v0.1.1",
    "release": "https://github.com/musutrade/GateProbes/releases/tag/postgres-service-v0.1.1",
    "published_at": "2026-10-14T10:16:51Z",
    "files": 12,
    "signed_attested_subjects": [
      "SHA256SUMS",
      "gateprobes-postgres-0.1.1-linux-amd64.tar.gz",
      "gateprobes-postgres-0.1.1-linux-amd64.tar.gz.sbom.cdx.json",
      "release-inventory.json"
    ],
    "assets": [
      {
        "kind": "package",
        "name": "gateprobes-postgres-0.1.1-linux-amd64.tar.gz",
        "sha256": "98223cbc76f0af650f55e7f699dec5f169d1b269a1d2fb12c1b8dae83cf14133",
        "size_bytes": 664723
      },
      {
        "kind": "sbom",
        "name": "gateprobes-postgres-0.1.1-linux-amd64.tar.gz.sbom.cdx.json",
        "sha256": "27264700f2e29d185884079be303f1b28d1eef58a5387dd90494966de30de823",
        "size_bytes": 22354
      }
    ],
    "scope": "exact inventory, API digests, checksums, exact-tag Sigstore and exact-source/signer GitHub attestations"
  },
  "plugin_main_ci": 38547630782,
  "plugin_release_run": 38548206084,
  "installed_plugin_sha256": "1607ca46a5910957c00f987fd8cc5f9e42331c02ae195386b166957845145237",
  "hosted_installed_contract": {
    "passed": 47,
    "same_public_plugin_bytes": true,
    "same_public_core_bytes": true
  },
  "real_contract": {
    "status": "pass",
    "plugin_sha256": "1607ca46a5910957c00f987fd8cc5f9e42331c02ae195386b166957845145237",
    "core_sha256": "198597ff623ce006d6f19261a352ca7a6d82a7c58af7bbba75de3c4076cd26a7",
    "health": "real pg_isready with explicit host/port; TCP-ready isolated Docker server",
    "cases": [
      {
        "case": "isolated-and-healthy",
        "command": "doctor",
        "expected": "pass"
      },
      {
        "case": "isolated-and-healthy",
        "command": "service-step",
        "expected": "pass"
      },
      {
        "case": "isolated-and-healthy",
        "command": "verify",
        "expected": "pass"
      },
      {
        "case": "production-name",
        "command": "doctor",
        "expected": "block"
      },
      {
        "case": "production-name",
        "command": "service-step",
        "expected": "block"
      },
      {
        "case": "production-name",
        "command": "verify",
        "expected": "block"
      },
      {
        "case": "remote-without-opt-in",
        "command": "doctor",
        "expected": "block"
      },
      {
        "case": "remote-without-opt-in",
        "command": "service-step",
        "expected": "block"
      },
      {
        "case": "remote-without-opt-in",
        "command": "verify",
        "expected": "block"
      },
      {
        "case": "query-override",
        "command": "doctor",
        "expected": "block"
      },
      {
        "case": "query-override",
        "command": "service-step",
        "expected": "block"
      },
      {
        "case": "query-override",
        "command": "verify",
        "expected": "block"
      },
      {
        "case": "wrong-scheme",
        "command": "doctor",
        "expected": "block"
      },
      {
        "case": "wrong-scheme",
        "command": "service-step",
        "expected": "block"
      },
      {
        "case": "wrong-scheme",
        "command": "verify",
        "expected": "block"
      },
      {
        "case": "closed-target-port",
        "command": "doctor",
        "expected": "block"
      },
      {
        "case": "closed-target-port",
        "command": "service-step",
        "expected": "block"
      },
      {
        "case": "closed-target-port",
        "command": "verify",
        "expected": "block"
      },
      {
        "case": "production-target-conflict",
        "command": "doctor",
        "expected": "block"
      },
      {
        "case": "production-target-conflict",
        "command": "service-step",
        "expected": "block"
      },
      {
        "case": "production-target-conflict",
        "command": "verify",
        "expected": "block"
      },
      {
        "case": "health-failure",
        "command": "doctor",
        "expected": "block"
      },
      {
        "case": "health-failure",
        "command": "service-step",
        "expected": "block"
      },
      {
        "case": "health-failure",
        "command": "verify",
        "expected": "block"
      },
      {
        "case": "health-tool-missing",
        "command": "doctor",
        "expected": "block"
      },
      {
        "case": "health-tool-missing",
        "command": "service-step",
        "expected": "block"
      },
      {
        "case": "health-tool-missing",
        "command": "verify",
        "expected": "block"
      },
      {
        "case": "timeout",
        "command": "doctor",
        "expected": "block"
      },
      {
        "case": "timeout",
        "command": "service-step",
        "expected": "block"
      },
      {
        "case": "timeout",
        "command": "verify",
        "expected": "block"
      },
      {
        "case": "plugin-missing",
        "command": "doctor",
        "expected": "block"
      },
      {
        "case": "plugin-missing",
        "command": "service-step",
        "expected": "block"
      },
      {
        "case": "plugin-missing",
        "command": "verify",
        "expected": "block"
      },
      {
        "case": "artifact-tampered",
        "command": "doctor",
        "expected": "block"
      },
      {
        "case": "artifact-tampered",
        "command": "service-step",
        "expected": "block"
      },
      {
        "case": "artifact-tampered",
        "command": "verify",
        "expected": "block"
      },
      {
        "case": "explicit-upgrade-rebind",
        "command": "doctor",
        "expected": "pass"
      },
      {
        "case": "explicit-upgrade-rebind",
        "command": "service-step",
        "expected": "pass"
      },
      {
        "case": "explicit-upgrade-rebind",
        "command": "verify",
        "expected": "pass"
      },
      {
        "case": "result-version-mismatch",
        "command": "doctor",
        "expected": "block"
      },
      {
        "case": "result-version-mismatch",
        "command": "service-step",
        "expected": "block"
      },
      {
        "case": "result-version-mismatch",
        "command": "verify",
        "expected": "block"
      },
      {
        "case": "protocol-incompatible",
        "command": "doctor",
        "expected": "block"
      },
      {
        "case": "protocol-incompatible",
        "command": "service-step",
        "expected": "block"
      },
      {
        "case": "protocol-incompatible",
        "command": "verify",
        "expected": "block"
      },
      {
        "case": "v1-migration",
        "command": "config-check",
        "expected": "pass"
      },
      {
        "case": "migrated-offline-import",
        "command": "config-import",
        "expected": "pass"
      }
    ],
    "image_id": "sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea",
    "routing": "closed target port blocks while the same server accepts TCP on 5432"
  },
  "installed_presets": {
    "passed": [
      "rust-api",
      "angular-only",
      "angular-rust-postgres"
    ],
    "preserved": "all original execution steps, quality collectors/policies, full/ci membership and generated policy files"
  },
  "sbom": {
    "format": "CycloneDX",
    "spec": "1.5",
    "components": 62
  },
  "temporary_test_containers_remaining": 0,
  "failed_publication_retained": {
    "tag": "postgres-service-v0.1.0",
    "source": "a5e321ec67de2fad04fd8bdc45bbf8cb564439cb",
    "run": 38545979584,
    "published": false,
    "reason": "annotated remote tag collided with peeled checkout tag before publication",
    "resolution": "separate remote verification ref with required commit equality; new0.1.1 version; no old tag/assets overwritten"
  },
  "policy": "Engineering Policy, thresholds, requiredness, baseline/debt/ratchet, metric series and release authority unchanged",
  "scope": "Linux x86_64 public installation; real pg_isready/server readiness, not authentication/SQL certification; controlled negative/managed fixtures remain part of the47-record suite"
}
```
