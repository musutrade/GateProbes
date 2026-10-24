#!/usr/bin/env python3
"""Fetch and verify the current production Core consumer and released measurer."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
CORE_PIN = ROOT / "plugins/rust-measure/production-core.json"
RELEASE_PIN = ROOT / "plugins/rust-measure/production-release.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_core_pin(path: Path = CORE_PIN) -> dict:
    value = json.loads(path.read_text())
    if value.get("schema") != "rust-measure-production-core/v1":
        raise ValueError("unknown production Core pin schema")
    if value.get("repository") != "musutrade/GateHouse":
        raise ValueError("unexpected production Core repository")
    if not re.fullmatch(r"[0-9a-f]{40}", value.get("source_commit", "")):
        raise ValueError("invalid production Core source commit")
    files = value.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("empty production Core file pin")
    for name, expected in files.items():
        if (not isinstance(name, str) or not name.startswith("tools/quality/")
                or ".." in Path(name).parts):
            raise ValueError("invalid production Core file path")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("invalid production Core file hash")
    if value.get("acceptance") not in files:
        raise ValueError("production acceptance script is not pinned")
    return value


def load_release_pin(path: Path = RELEASE_PIN) -> dict:
    value = json.loads(path.read_text())
    if value.get("schema") != "rust-measure-production-release-pin/v1":
        raise ValueError("unknown production measurer pin schema")
    for key in ("repository", "release", "asset", "sha256", "sbom_sha256",
                "inventory_sha256", "binary_sha256", "source_commit", "version",
                "analyzer", "rule", "workflow", "certificate_identity"):
        if not isinstance(value.get(key), str) or not value[key]:
            raise ValueError(f"invalid production measurer pin {key}")
    for key in ("sha256", "sbom_sha256", "inventory_sha256", "binary_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", value[key]):
            raise ValueError(f"invalid production measurer pin {key}")
    if not re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]):
        raise ValueError("invalid production measurer source commit")
    if value["asset"] != f"harness-gate-rust-measure-{value['version']}-linux-amd64.tar.gz":
        raise ValueError("production measurer asset/version mismatch")
    if value["certificate_identity"] != (
            f"https://github.com/{value['repository']}/{value['workflow']}"
            f"@refs/tags/{value['release']}"):
        raise ValueError("production measurer certificate identity mismatch")
    return value


def fetch(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    last_error = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                payload = response.read()
            if not payload:
                raise ValueError(f"empty input: {url}")
            destination.write_bytes(payload)
            return
        except (urllib.error.URLError, TimeoutError) as error:
            last_error = error
            if attempt < 2:
                time.sleep(attempt + 1)
    raise last_error


def verify_core(directory: Path, pin: dict) -> None:
    for name, expected in pin["files"].items():
        path = directory / name
        if not path.is_file():
            raise ValueError(f"missing production Core file: {name}")
        if digest(path) != expected:
            raise ValueError(f"production Core file digest mismatch: {name}")


def prepare_core(directory: Path, pin: dict) -> None:
    directory.mkdir(parents=True, exist_ok=False)
    base = f"https://raw.githubusercontent.com/{pin['repository']}/{pin['source_commit']}"
    for name in pin["files"]:
        fetch(f"{base}/{name}", directory / name)
    verify_core(directory, pin)


def verify_release_binary(binary: Path, pin: dict) -> None:
    if not binary.is_file():
        raise ValueError(f"missing released measurer binary: {binary}")
    if digest(binary) != pin["binary_sha256"]:
        raise ValueError("released measurer binary digest mismatch")
    manifest_path = binary.parent / "plugin.json"
    if not manifest_path.is_file():
        raise ValueError(f"missing released measurer manifest: {manifest_path}")
    manifest = json.loads(manifest_path.read_text())
    actual = (manifest.get("analyzer"), manifest.get("version"), manifest.get("rule"))
    expected = (pin["analyzer"], pin["version"], pin["rule"])
    if actual != expected:
        raise ValueError(f"released measurer identity mismatch: {actual} != {expected}")


def prepare_release(directory: Path, pin: dict) -> Path:
    directory.mkdir(parents=True, exist_ok=False)
    archive = directory / pin["asset"]
    fetch(f"https://github.com/{pin['repository']}/releases/download/{pin['release']}/{pin['asset']}",
          archive)
    if digest(archive) != pin["sha256"]:
        raise ValueError("released measurer archive digest mismatch")
    with tarfile.open(archive) as source:
        members = list(source)
        if not members:
            raise ValueError("empty released measurer archive")
        roots = {Path(member.name).parts[0] for member in members if Path(member.name).parts}
        if len(roots) != 1:
            raise ValueError("released measurer archive has multiple roots")
        for member in members:
            parts = Path(member.name).parts
            if (member.name.startswith("/") or ".." in parts or "\\" in member.name
                    or not (member.isfile() or member.isdir())):
                raise ValueError(f"unsafe released measurer archive member: {member.name}")
        source.extractall(directory, filter="data")
    root = directory / roots.pop()
    binary = root / "harness-gate-rust-measure"
    verify_release_binary(binary, pin)
    return binary


def prepare(output: Path) -> dict:
    core_pin, release_pin = load_core_pin(), load_release_pin()
    output.mkdir(parents=True, exist_ok=False)
    core = output / "core"
    prepare_core(core, core_pin)
    binary = prepare_release(output / "release", release_pin)
    contract = {"core": core_pin, "release": release_pin, "core_root": str(core),
                "binary": str(binary)}
    (output / "contract.json").write_text(json.dumps(contract, indent=2) + "\n")
    return contract


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output.resolve()), indent=2))
