"""Publish existing onboarding products as one independently verifiable bundle."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import tomllib

import package_workload
import plugin_release

PRODUCT = "onboarding-presets"
CATALOG = "products/onboarding/products.json"


def members(root: Path, version: str) -> dict[str, bytes]:
    read = lambda name: package_workload.checked_file(root, name)
    catalog = json.loads(read(CATALOG))
    if catalog.get("schema") != "gateprobes-products/v1":
        raise ValueError("invalid onboarding product catalog")
    products = catalog["products"]
    if set(products) != {"rust-minimal", "python-minimal"}:
        raise ValueError("unexpected onboarding products")
    names = [CATALOG, "tools/onboarding/plugin_manager.py", "tools/onboarding/acceptance.py",
             "plugins/onboarding-presets/plugin.json", "plugins/onboarding-presets/README.md", "LICENSE"]
    for name, product in products.items():
        if product["version"] != version:
            raise ValueError("onboarding distribution/product versions differ")
        ecosystem = name.removesuffix("-minimal")
        expected = [f"products/onboarding/presets/{ecosystem}/catalog.json",
                    f"products/onboarding/presets/{ecosystem}/flow.toml"]
        if product["files"] != expected:
            raise ValueError("unexpected onboarding product members")
        names.extend(expected)
    if len(names) != len(set(names)):
        raise ValueError("duplicate onboarding members")
    files = {name: read(name) for name in names}
    for name, data in files.items():
        if name.endswith(".json"):
            json.loads(data)
        elif name.endswith(".toml"):
            tomllib.loads(data.decode())
    return files


def package(root: Path, output: Path, core: Path) -> None:
    identity = plugin_release.resolve(PRODUCT, root)
    files = members(root, identity["version"])
    archive = output / identity["archive"]
    prefix = archive.name.removesuffix(".tar.gz")
    with archive.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as stream:
            for name, data in sorted(files.items()):
                member = tarfile.TarInfo(f"{prefix}/{name}")
                member.size, member.mode, member.mtime = len(data), 0o644, 0
                stream.addfile(member, io.BytesIO(data))
    with tempfile.TemporaryDirectory(prefix="onboarding-package-") as temporary:
        work = Path(temporary)
        with tarfile.open(archive) as stream:
            stream.extractall(work, filter="data")
        installed = work / prefix
        if members(installed, identity["version"]) != files:
            raise ValueError("onboarding archive differs from reviewed bytes")
        subprocess.run([sys.executable, str(installed / "tools/onboarding/acceptance.py"),
                        "--core", str(core.resolve()), "--work-dir", str(work / "acceptance")],
                       cwd=installed, check=True)
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": PRODUCT,
                                       "version": identity["version"]}},
            "components": [{"type": "file", "name": name,
                            "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(data).hexdigest()}]}
                           for name, data in sorted(files.items())]}
    (output / (archive.name + ".sbom.cdx.json")).write_text(json.dumps(sbom, indent=2) + "\n")
