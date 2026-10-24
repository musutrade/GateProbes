#!/usr/bin/env python3
"""Current production Core consumer acceptance for the released 0.4.0 measurer.

The historical d76a candidate contract remains in candidate_contract.py. This
entry point is the current-production route: it verifies the fixed merged Core
consumer source and the immutable published measurer binary, then requires the
Core production consumer to accept 0.4.0 and reject the real 0.3.1/unknown/
wrong-rule/wrong-target identities. It never falls back to the old identity.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/release"))
import rust_measure_candidate as legacy
import rust_measure_production as production

HERE = Path(__file__).resolve().parent
EXPECTED_SYMBOLS = ["included", "nested", "plain"]
EXPECTED_EXCLUDED = [[3, 1, 4, 17]]


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        raise SystemExit(f"command failed ({result.returncode}): {' '.join(command)}\n"
                         f"{result.stdout}{result.stderr}")
    return result


def plugin_version(plugin_dir: Path) -> str:
    manifest = json.loads((plugin_dir / "plugin.json").read_text())
    version = manifest.get("version")
    if not isinstance(version, str):
        raise SystemExit("measurer plugin.json has no version")
    return version


def check_acceptance(value: dict) -> None:
    if value.get("consumer", {}).get("version") != "0.4.0":
        raise SystemExit(f"production acceptance consumer mismatch: {value.get('consumer')}")
    if value.get("series", {}).get("analyzer") != "harness-gate-rust-measure/0.4.0":
        raise SystemExit(f"production acceptance series mismatch: {value.get('series')}")
    if value.get("symbols") != EXPECTED_SYMBOLS:
        raise SystemExit(f"production acceptance symbols mismatch: {value.get('symbols')}")
    if value.get("excluded") != EXPECTED_EXCLUDED:
        raise SystemExit(f"production acceptance excluded mismatch: {value.get('excluded')}")
    for key in ("legacy_rejected", "mutated_span_rejected"):
        if value.get(key) is not True:
            raise SystemExit(f"production acceptance negative missing: {key}")
    if value.get("invalid_identities_rejected") != 4:
        raise SystemExit("production acceptance did not reject all four invalid identities")


def production_contract(binary: Path, core_root: Path, release_pin: dict,
                        legacy_binary: Path, legacy_pin: dict) -> dict:
    production.verify_release_binary(binary, release_pin)
    legacy.verify_legacy(legacy_binary, legacy_pin)
    acceptance = core_root / production.load_core_pin()["acceptance"]
    result = run([sys.executable, str(acceptance), "--binary", str(binary),
                  "--legacy-binary", str(legacy_binary)])
    value = json.loads(result.stdout)
    check_acceptance(value)
    return {"version": "0.4.0", "route": "production",
            "core_source_commit": production.load_core_pin()["source_commit"],
            "release": release_pin["release"],
            "acceptance": value}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path,
                        help="downloaded released 0.4.0 binary; omit to download it")
    parser.add_argument("--plugin-dir", type=Path, default=HERE)
    parser.add_argument("--legacy-binary", type=Path,
                        help="real 0.3.1 binary; omit to download the immutable release")
    args = parser.parse_args()
    if plugin_version(args.plugin_dir.resolve()) != "0.4.0":
        raise SystemExit("production route requires measurer version 0.4.0")
    core_pin, release_pin = production.load_core_pin(), production.load_release_pin()
    legacy_pin = legacy.load_legacy_pin()
    temporary = None
    try:
        if args.binary is None:
            temporary = tempfile.TemporaryDirectory(prefix="rust-measure-040-production-")
            prepared = Path(temporary.name) / "production"
            contract = production.prepare(prepared)
            binary = Path(contract["binary"])
            core_root = Path(contract["core_root"])
        else:
            binary = args.binary.resolve()
            production.verify_release_binary(binary, release_pin)
            temporary = tempfile.TemporaryDirectory(prefix="rust-measure-040-production-core-")
            core_root = Path(temporary.name) / "core"
            production.prepare_core(core_root, core_pin)
        if args.legacy_binary is None:
            if temporary is None:
                temporary = tempfile.TemporaryDirectory(prefix="rust-measure-040-legacy-")
            legacy_binary = legacy.prepare_legacy(Path(temporary.name) / "legacy", legacy_pin)
        else:
            legacy_binary = args.legacy_binary.resolve()
        print(json.dumps(production_contract(binary, core_root, release_pin,
                                             legacy_binary, legacy_pin), sort_keys=True))
        return 0
    finally:
        if temporary is not None:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
