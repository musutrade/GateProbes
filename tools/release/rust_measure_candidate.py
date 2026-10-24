#!/usr/bin/env python3
"""Fetch and verify the fixed 0.4.0 Core consumer and the legacy 0.3.1 binary."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
CORE_PIN = ROOT / "plugins/rust-measure/candidate-core.json"
LEGACY_PIN = ROOT / "plugins/rust-measure/legacy-release.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_core_pin(path: Path = CORE_PIN) -> dict:
    value = json.loads(path.read_text())
    if value.get("schema") != "rust-measure-candidate-core/v1":
        raise ValueError("unknown candidate Core pin schema")
    if value.get("repository") != "musutrade/GateHouse":
        raise ValueError("unexpected candidate Core repository")
    if not re.fullmatch(r"[0-9a-f]{40}", value.get("source_commit", "")):
        raise ValueError("invalid candidate Core source commit")
    files = value.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("empty candidate Core file pin")
    for name, expected in files.items():
        if not isinstance(name, str) or not name.startswith("tools/quality/") or ".." in Path(name).parts:
            raise ValueError("invalid candidate Core file path")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("invalid candidate Core file hash")
    if value.get("acceptance") not in files:
        raise ValueError("candidate acceptance script is not pinned")
    return value


def load_legacy_pin(path: Path = LEGACY_PIN) -> dict:
    value = json.loads(path.read_text())
    if value.get("schema") != "rust-measure-legacy-release-pin/v1":
        raise ValueError("unknown legacy measurer pin schema")
    for key in ("repository", "release", "asset", "sha256", "binary_sha256",
                "version", "analyzer", "rule", "source_commit", "workflow",
                "certificate_identity"):
        if not isinstance(value.get(key), str) or not value[key]:
            raise ValueError(f"invalid legacy measurer pin {key}")
    for key in ("sha256", "binary_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", value[key]):
            raise ValueError(f"invalid legacy measurer pin {key}")
    if not re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]):
        raise ValueError("invalid legacy measurer source commit")
    if value["asset"] != f"harness-gate-rust-measure-{value['version']}-linux-amd64.tar.gz":
        raise ValueError("legacy measurer asset/version mismatch")
    return value


def fetch(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=60) as response:
        payload = response.read()
    if not payload:
        raise ValueError(f"empty input: {url}")
    destination.write_bytes(payload)


def verify_core(directory: Path, pin: dict) -> None:
    for name, expected in pin["files"].items():
        path = directory / name
        if not path.is_file():
            raise ValueError(f"missing candidate Core file: {name}")
        if digest(path) != expected:
            raise ValueError(f"candidate Core file digest mismatch: {name}")


def prepare_core(directory: Path, pin: dict) -> None:
    directory.mkdir(parents=True, exist_ok=False)
    base = f"https://raw.githubusercontent.com/{pin['repository']}/{pin['source_commit']}"
    for name in pin["files"]:
        fetch(f"{base}/{name}", directory / name)
    verify_core(directory, pin)


def verify_legacy(binary: Path, pin: dict) -> None:
    if not binary.is_file():
        raise ValueError(f"missing legacy measurer binary: {binary}")
    if digest(binary) != pin["binary_sha256"]:
        raise ValueError("legacy measurer binary digest mismatch")
    manifest = json.loads((binary.parent / "plugin.json").read_text())
    actual = (manifest.get("analyzer"), manifest.get("version"), manifest.get("rule"))
    expected = (pin["analyzer"], pin["version"], pin["rule"])
    if actual != expected:
        raise ValueError(f"legacy measurer identity mismatch: {actual} != {expected}")


def prepare_legacy(directory: Path, pin: dict) -> Path:
    directory.mkdir(parents=True, exist_ok=False)
    archive = directory / pin["asset"]
    fetch(f"https://github.com/{pin['repository']}/releases/download/{pin['release']}/{pin['asset']}", archive)
    if digest(archive) != pin["sha256"]:
        raise ValueError("legacy measurer archive digest mismatch")
    with tarfile.open(archive) as source:
        members = list(source)
        if not members:
            raise ValueError("empty legacy measurer archive")
        roots = {Path(member.name).parts[0] for member in members if Path(member.name).parts}
        if len(roots) != 1:
            raise ValueError("legacy measurer archive has multiple roots")
        for member in members:
            parts = Path(member.name).parts
            if member.name.startswith("/") or ".." in parts or "\\" in member.name or not (member.isfile() or member.isdir()):
                raise ValueError(f"unsafe legacy measurer archive member: {member.name}")
        source.extractall(directory, filter="data")
    root = directory / roots.pop()
    binary = root / "harness-gate-rust-measure"
    verify_legacy(binary, pin)
    return binary


def prepare(output: Path) -> dict:
    core_pin, legacy_pin = load_core_pin(), load_legacy_pin()
    output.mkdir(parents=True, exist_ok=False)
    core = output / "core"
    prepare_core(core, core_pin)
    legacy = prepare_legacy(output / "legacy", legacy_pin)
    contract = {"core": core_pin, "legacy": legacy_pin, "core_root": str(core),
                "legacy_binary": str(legacy)}
    (output / "contract.json").write_text(json.dumps(contract, indent=2) + "\n")
    return contract


def route_version(version: str) -> str:
    if version == "0.3.1":
        return "legacy"
    if version == "0.4.0":
        return "candidate"
    raise ValueError(f"unsupported rust-measure version route: {version}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output.resolve()), indent=2))
