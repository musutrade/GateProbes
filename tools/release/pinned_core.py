#!/usr/bin/env python3
"""Fetch and verify the fixed released Core used for plugin acceptance."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
MODULES = ("collector_runner", "harness_evidence", "project_model", "quality_evidence",
           "source_measure", "function_risk", "production_coverage", "complexity_analyzer", "quality_common")
SCHEMAS = ("capability-requirements", "harness-evidence", "policy-exceptions", "policy",
           "project-model", "subject-mappings")


def contract(root: Path = ROOT) -> dict:
    value = json.loads((root / "docs/ownership.json").read_text())["core_contract"]
    if not re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]):
        raise ValueError("Core modules require a full source commit")
    if value["repository"] != "musutrade/GateHouse":
        raise ValueError("unexpected Core repository")
    if value["release"] != "v" + value["version"]:
        raise ValueError("Core release/version mismatch")
    pinned = value["platforms"]["linux"]
    if pinned["binary"] != "harness-gate-linux-amd64" or not re.fullmatch(r"[0-9a-f]{64}", pinned["sha256"]):
        raise ValueError("invalid Linux Core binary contract")
    return value


def fetch(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=60) as response:
        payload = response.read()
    if not payload:
        raise ValueError(f"empty pinned Core input: {url}")
    destination.write_bytes(payload)


def verify(directory: Path, root: Path = ROOT) -> dict:
    value = contract(root)
    pinned = value["platforms"]["linux"]
    binary = directory / "bin" / pinned["binary"]
    if hashlib.sha256(binary.read_bytes()).hexdigest() != pinned["sha256"]:
        raise ValueError("pinned Core binary digest mismatch")
    actual = subprocess.run([str(binary), "--version"], text=True, capture_output=True, check=True).stdout.strip()
    if actual != "harness-gate " + value["version"]:
        raise ValueError("pinned Core binary version mismatch")
    return value


def prepare(directory: Path) -> None:
    value = contract()
    directory.mkdir(parents=True, exist_ok=False)
    pinned = value["platforms"]["linux"]
    binary = directory / "bin" / pinned["binary"]
    fetch(f"https://github.com/{value['repository']}/releases/download/{value['release']}/{pinned['binary']}", binary)
    binary.chmod(0o755)
    verify(directory)
    base = f"https://raw.githubusercontent.com/{value['repository']}/{value['source_commit']}"
    files = [f"tools/quality/{name}.py" for name in MODULES]
    files += [f"tools/quality/schema/{name}.schema.json" for name in SCHEMAS]
    files += ["schema/collector-protocol.schema.json", "tools/release/generate-sbom.py"]
    for path in files:
        fetch(f"{base}/{path}", directory / path)
    (directory / "contract.json").write_text(json.dumps(value, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    prepare(parser.parse_args().output.resolve())
