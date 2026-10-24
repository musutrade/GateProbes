#!/usr/bin/env python3
"""Version-routed measurer acceptance for the fixed 0.4.0 consumer candidate."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/release"))
import rust_measure_candidate as candidate

HERE = Path(__file__).resolve().parent


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


def old_contract(binary: Path, core_root: Path) -> str:
    result = run([sys.executable, str(HERE / "contract.py"), "--binary", str(binary),
                  "--core-root", str(core_root)])
    return result.stdout.strip()


def candidate_contract(binary: Path, core_root: Path, prepared: Path | None,
                       legacy_binary: Path | None) -> dict:
    core_pin, legacy_pin = candidate.load_core_pin(), candidate.load_legacy_pin()
    temporary = None
    try:
        if prepared is None:
            temporary = tempfile.TemporaryDirectory(prefix="rust-measure-040-contract-")
            prepared = Path(temporary.name) / "candidate"
            contract = candidate.prepare(prepared)
        else:
            prepared = prepared.resolve()
            contract = json.loads((prepared / "contract.json").read_text())
            if contract.get("core") != core_pin or contract.get("legacy") != legacy_pin:
                raise SystemExit("candidate contract does not match fixed pins")
            candidate.verify_core(Path(contract["core_root"]), core_pin)
        if legacy_binary is None:
            legacy_binary = Path(contract["legacy_binary"])
        if legacy_binary is None:
            raise SystemExit("legacy 0.3.1 binary is required for the 0.4.0 contract")
        legacy_binary = legacy_binary.resolve()
        candidate.verify_legacy(legacy_binary, legacy_pin)
        # Historical old-Core path remains valid for the old binary.
        old = old_contract(legacy_binary, core_root)
        # The merged Core candidate acceptance covers both consumer directions.
        acceptance = Path(contract["core_root"]) / core_pin["acceptance"]
        result = run([sys.executable, str(acceptance), "--binary", str(binary),
                      "--legacy-binary", str(legacy_binary)])
        return {"version": "0.4.0", "route": "candidate", "old_contract": old,
                "candidate_acceptance": json.loads(result.stdout),
                "core_source_commit": core_pin["source_commit"],
                "legacy_release": legacy_pin["release"]}
    finally:
        if temporary is not None:
            temporary.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--plugin-dir", type=Path, default=HERE)
    parser.add_argument("--core-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path)
    parser.add_argument("--legacy-binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"measurer binary missing: {binary}")
    version = plugin_version(args.plugin_dir.resolve())
    route = candidate.route_version(version)
    if route == "legacy":
        print(json.dumps({"version": version, "route": "legacy",
                          "contract": old_contract(binary, args.core_root.resolve())}, sort_keys=True))
        return 0
    print(json.dumps(candidate_contract(binary, args.core_root.resolve(), args.candidate_root,
                                         args.legacy_binary), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
