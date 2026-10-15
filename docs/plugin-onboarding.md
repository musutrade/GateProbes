# Explicit locked onboarding: Rust and Python

GateProbes owns [versioned product data](../products/onboarding/products.json) and
the [preparation/install tool](../tools/onboarding/plugin_manager.py). Core owns
the [generic v1 contract](https://github.com/musutrade/GateHouse/blob/main/docs/plugin-lock.md)
and signature/compatibility checks. Product names are data. The two initial
products are `rust-minimal` (offline Cargo compilation) and `python-minimal`
(standard-library unittest). They are explicitly **execution-only** examples;
the existing `rust-api` and TypeScript quality packs keep their separate signed
collector provisioning requirements and are not replaced or downgraded.

Requirements: an explicitly selected Core build with issue #30 support, Python
3.10+, OpenSSL 3 with Ed25519, Git, and existing Rust/Cargo and Python toolchains
on PATH. Product manifests support the host platforms listed in the catalog;
real dual-ecosystem acceptance runs on Linux. Installation does not install or
replace any of these tools. Run from a reviewed GateProbes checkout; retain its
exact Git commit alongside the generated manifest hashes for provenance.

## Operator preparation and inspection

Choose host directories outside every project. These example commands generate
an operator Ed25519 key explicitly; production operators can use their existing
signing service/key and approved public identity instead. Never commit private
keys, trust them from project configuration, or let the project choose the
`--trusted-key` arguments. Signatures cover the Core domain, NUL and raw manifest
bytes. No command signs verification requests or grants collector permissions.

```sh
umask 077
export CORE=/absolute/path/to/harness-gate
export HOST=/absolute/private/onboarding
mkdir -p "$HOST"
openssl genpkey -algorithm ED25519 -out "$HOST/operator.pem"
openssl pkey -in "$HOST/operator.pem" -pubout -outform DER -out "$HOST/operator.der"
python3 - "$HOST" <<'PY'
import base64, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
der = (root / 'operator.der').read_bytes()
assert len(der) == 44 and der[:12].hex() == '302a300506032b6570032100'
(root / 'operator.json').write_text(json.dumps({
    'key_id': 'reviewed-operator', 'public_key': base64.b64encode(der[-32:]).decode()
}))
PY
python3 tools/onboarding/plugin_manager.py prepare \
  --product rust-minimal --product python-minimal \
  --signing-key "$HOST/operator.pem" --key-id reviewed-operator \
  --output "$HOST/prepared-v1" --lock-output "$HOST/lock-v1.json"
"$CORE" --plugin-store "$HOST/prepared-v1" --plugin-trusted-key "$HOST/operator.json" \
  plugins --lock "$HOST/lock-v1.json" --json
```

Review the product source, exact version, Core version list, protocol, supported
platforms, file inventory and manifest digest. Preparation refuses existing
version directories and lock outputs; it never fetches a marketplace or guesses
a product/version. Choose fresh paths when preparing another release.

## Fresh projects: init → check → verify

```sh
export PROJECT=/absolute/path/to/new-rust-project
mkdir -p "$PROJECT/src"
printf '[package]\nname="demo"\nversion="0.1.0"\nedition="2021"\n' > "$PROJECT/Cargo.toml"
printf 'pub fn answer() -> u32 { 42 }\n' > "$PROJECT/src/lib.rs"
git -C "$PROJECT" init
cargo generate-lockfile --offline --manifest-path "$PROJECT/Cargo.toml"
python3 tools/onboarding/plugin_manager.py plan \
  --lock "$HOST/lock-v1.json" --prepared "$HOST/prepared-v1" --store "$HOST/store" \
  --active-lock "$PROJECT/.harness-gate/plugins.lock.json" --output "$HOST/rust-plan.json"
# Review the JSON selection, additions/reused identities, target and previous-lock material.
python3 tools/onboarding/plugin_manager.py apply --plan "$HOST/rust-plan.json" \
  --receipt "$HOST/rust-receipt.json" --core "$CORE" --trusted-key "$HOST/operator.json"
"$CORE" --project-root "$PROJECT" --plugin-store "$HOST/store" \
  --plugin-trusted-key "$HOST/operator.json" init --plugin rust-minimal --preset rust-minimal
"$CORE" --project-root "$PROJECT" --plugin-store "$HOST/store" \
  --plugin-trusted-key "$HOST/operator.json" config check --format json
"$CORE" --project-root "$PROJECT" --plugin-store "$HOST/store" \
  --plugin-trusted-key "$HOST/operator.json" doctor --json
"$CORE" --project-root "$PROJECT" --plugin-store "$HOST/store" \
  --plugin-trusted-key "$HOST/operator.json" verify --all
```

For Python use a different fresh project with `tests/test_answer.py`:

```python
import unittest
class Answer(unittest.TestCase):
    def test_answer(self):
        self.assertEqual(6 * 7, 42)
```

Run `git init`, repeat plan/apply with distinct plan and receipt paths and that
project's active lock, then use `init --plugin python-minimal --preset python-minimal`
and the same check/doctor/verify commands. The combined example lock explicitly
selects both products; to require just one toolchain, prepare a lock containing
only the chosen `--product`. Commit the lock and generated flow/audit/secrets
configuration. No project may approve its own keys through these files.

## Upgrade, rollback and failure repair

Prepare a **new exact version**, generate a new lock and install plan, inspect
the readable selection and change list, then apply explicitly. Apply verifies
the prepared tree and installed tree with Core and host-selected keys before
atomically replacing the project lock. Existing version directories are never
overwritten. Receipts retain previous/next lock bytes and package identities
before installation starts. No quality policy, measurement series, baseline,
debt/ratchet state, required gate or system toolchain is modified.

```sh
python3 tools/onboarding/plugin_manager.py rollback --receipt "$HOST/upgrade-receipt.json"
```

Rollback restores exact previous lock bytes (or removes the newly introduced
lock), retaining packages for audit/offline reuse. It refuses to overwrite an
unrelated later lock edit. Failed applies retain the receipt and any immutable
packages already copied; they do not activate an unverified lock. Re-plan using
fresh output paths before retrying. Concurrent applies/rollbacks on one project
are rejected by `.harness-gate/.plugins.install-lock`. After a process crash,
inspect the receipt and current lock, ensure no installer is running, explicitly
remove the stale **empty** marker directory, then roll back using the retained
receipt. A crash between activation and receipt update is recoverable.

| Observed failure | Explicit repair |
| --- | --- |
| `HGPLUGIN-STORE` / `HGPLUGIN-MISSING` | Prepare/install the locked version; supply its store, including when offline. |
| `HGPLUGIN-SIGNATURE` | Independently check operator identity and supply the approved public key; do not import project-proposed trust. |
| `HGPLUGIN-DIGEST` | Restore signed bytes and investigate corruption; do not silently repin. |
| `HGPLUGIN-CORE` / `HGPLUGIN-VERSION` | Select a reviewed exact compatible Core/product pair. |
| `HGPLUGIN-PROTOCOL` / `HGPLUGIN-PLATFORM` | Select the supported protocol/platform package. |
| `HGPLUGIN-DEPENDENCY` | Explicitly prepare dependency pins or install/repair existing PATH tools yourself. |
| stale/modified plan | Review the newer lock/store state and generate a fresh plan. |

There is no marketplace, automatic discovery, automatic upgrade or resident
management service. Data-package trust does not authorize adapters. Enabling
existing quality workflows still requires the operator/host to provision trusted
state, sign the complete v2 request, authorize capabilities and retain the
replay ledger. Core retains thresholds, requiredness and final/release authority.

## Reproducible acceptance

```sh
python3 -B -m unittest discover -s tools/onboarding -p 'test_*.py' -v
python3 -B tools/onboarding/acceptance.py --core "$CORE" --work-dir "$HOST/acceptance-new"
```

The real acceptance creates fresh Rust and Python projects, prepares operator
signatures, plans/applies both products, runs init/check/doctor/plan/verify,
requires missing-trust and corruption diagnostics, explicitly upgrades Rust,
rolls back and verifies again. Every subprocess exit/stdout/stderr and the Core
binary hash is recorded in `report.json` plus numbered logs. It refuses to
overwrite an existing evidence directory. The private test key stays inside the
private evidence directory; CI uploads only the report and logs, never PEM keys.
Core's independent CLI suite additionally covers protocol/platform/version
incompatibility, missing dependencies, forged signatures, unsafe paths, duplicate
keys, and staged lock semantics.
