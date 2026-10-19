"""Deterministic external consumer package, accepted against the released Core."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

import package_workload
import plugin_release

PRODUCT = "github-check"


def package(root: Path, output: Path, core: Path) -> None:
    identity = plugin_release.resolve(PRODUCT, root)
    files = {name: package_workload.checked_file(root, f"plugins/{PRODUCT}/{name}")
             for name in ("github_check.py", "README.md", "plugin.json", "LICENSE")}
    manifest = json.loads(files["plugin.json"])
    if (manifest.get("schema") != "gateprobes-result-consumer/v1"
            or manifest.get("name") != PRODUCT
            or manifest.get("entry") != "github_check.py"
            or manifest.get("authority") != "result-mapping-only"):
        raise ValueError("invalid result consumer identity")
    archive = output / identity["archive"]
    prefix = archive.name.removesuffix(".tar.gz")
    with archive.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as stream:
            for name, data in sorted(files.items()):
                member = tarfile.TarInfo(f"{prefix}/{name}")
                member.size, member.mode, member.mtime = len(data), 0o644, 0
                stream.addfile(member, io.BytesIO(data))
    with tempfile.TemporaryDirectory(prefix="consumer-package-") as temporary:
        work = Path(temporary)
        with tarfile.open(archive) as stream:
            stream.extractall(work, filter="data")
        installed = work / prefix
        if {p.name: p.read_bytes() for p in installed.iterdir()} != files:
            raise ValueError("consumer extraction differs from reviewed bytes")
        env = {k: v for k, v in os.environ.items()
               if k not in ("GH_TOKEN", "GITHUB_TOKEN", "GATEHOUSE_CHECK_TOKEN")}
        env.update(GATEHOUSE_CORE=str(core.resolve()),
                   GATEPROBES_CONSUMER=str(installed / "github_check.py"))
        subprocess.run([str(core.resolve()), "--version"], check=True, env=env)
        # Test code and fixtures are local to GateProbes; the tested consumer is
        # extracted from the archive and the Core is a verified released binary.
        subprocess.run([sys.executable, str(root / "plugins/github-check/accept.py")],
                       cwd=work, env=env, check=True)
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": PRODUCT,
                                       "version": identity["version"]}},
            "components": [{"type": "file", "name": name,
                            "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(data).hexdigest()}]}
                           for name, data in sorted(files.items())]}
    (output / (archive.name + ".sbom.cdx.json")).write_text(json.dumps(sbom, indent=2) + "\n")
