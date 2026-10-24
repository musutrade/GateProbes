# Rust measurer 0.4.0 current-production contract

This is a local GateProbes candidate. It adds an explicit current-production
acceptance route without changing the immutable `rust-measure-v0.4.0` release
or its assets, and without republishing or bumping the plugin version.

## Fixed identities

Current Core production consumer:

- Repository: `musutrade/GateHouse`
- Merge/source: `6ec99b8f56477ce1b79a12a16e93f745eee6bb42`
- Required files and SHA-256 values: `plugins/rust-measure/production-core.json`
- Acceptance entry:
  `tools/quality/tests/rust_measure_candidate_acceptance.py`

Published measurer:

- Tag: `rust-measure-v0.4.0`
- Source: `d47afd65254f310f3f34c2bb548773eb9f31b121`
- Archive SHA-256: `d3015acd152dfcc8ac53ee1aa653454aa51244a94ca97645bccf6cd2db6bf126`
- Binary SHA-256: `8770863b6e051f42428babac48fb04e58a688b29a32ae233a8cb1faf7b2ac0f2`
- SBOM SHA-256: `024377cad47b1f184277912db03d58151d7efc64bb290fb711f907469d567bb6`
- Inventory SHA-256: `3a5aafa2baa3ea41fa5be59ecd5521621779be1b0d035c445e619b3f57d755e3`
- Pin: `plugins/rust-measure/production-release.json`

The production route downloads and verifies the release archive, extracts it
safely, checks the binary digest and `plugin.json` identity, fetches the fixed
Core files, checks every pinned hash, and runs the fixed Core acceptance with
the downloaded 0.4.0 binary and the immutable real 0.3.1 binary.

## Semantics

- Production Core accepts only `harness-gate-rust-measure/0.4.0` with rule
  `mccabe-rust-3`.
- The real 0.3.1 binary, unknown version, wrong rule and wrong target echo are
  rejected.
- The acceptance requires exact symbols `included`, `nested`, `plain` and exact
  excluded span `[[3, 1, 4, 17]]`.
- No old/new fallback, environment switch or CLI bypass exists.

## Routing and history

- `production_contract.py`: current production route. It is the first command
  in the rust-measure registry contract used by CI, so current CI always checks
  the current Core production consumer against the downloaded release.
- `candidate_contract.py`: historical candidate route. It keeps the fixed Core
  source `d76a3130a13a565643f5b9fda8f5a5f2b7d28453` and the earlier dual
  expectation evidence. It is not renamed to current production and does not
  authorize a new release.
- `tools/release/package_plugin.py` builds a fresh artifact, so it continues to
  run the historical candidate route. It does not claim the fresh binary is the
  immutable downloaded release. A post-release/current-production check uses
  the downloaded binary instead.
- `contract.py` remains the historical 0.3.1 old-consumer contract.
- No tag, asset, historical pin or published evidence is rewritten.

## Negative/failure coverage

The production helper and tests fail on:

- missing or mismatched fixed Core files;
- missing or mismatched released binary;
- missing manifest or mismatched analyzer/version/rule;
- invalid release pin, asset, source commit or certificate identity;
- incomplete/tampered Core acceptance output, including missing
  `legacy_rejected`, mutated spans, or fewer than four invalid-identity
  rejections.

The actual production acceptance also exercises real 0.3.1, unknown version,
wrong rule and wrong target echo.

## Boundaries

- No push/PR/tag/release in this batch.
- No new measurer version and no republishing of `rust-measure-v0.4.0`.
- No collector 0.2.0 compatibility row; `tested: []` remains deny-by-default.
- thiserror/#107 remains a separate limitation; #108/#91 are not closed here.
