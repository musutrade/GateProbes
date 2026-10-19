"""Deterministic platform action package; tests use fake API and local files."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

import package_workload
import plugin_release

PRODUCT = "github-actions"


def package(root: Path, output: Path) -> None:
    identity = plugin_release.resolve(PRODUCT, root)
    names = ["plugin.json", "README.md", "LICENSE",
             "actions/findings-feedback/action.yml", "actions/findings-feedback/feedback.cjs",
             "actions/findings-feedback/feedback.test.cjs", "actions/report-artifact/action.yml",
             "actions/report-artifact/prepare.cjs", "actions/report-artifact/prepare.test.cjs"]
    files = {name: package_workload.checked_file(root, f"plugins/{PRODUCT}/{name}") for name in names}
    manifest = json.loads(files["plugin.json"])
    if (manifest.get("schema") != "gateprobes-platform-actions/v1"
            or manifest.get("name") != PRODUCT
            or manifest.get("authority") != "advisory-feedback-and-artifact-transport-only"):
        raise ValueError("invalid platform action identity")
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
        extracted = {p.relative_to(installed).as_posix(): p.read_bytes()
                     for p in installed.rglob("*") if p.is_file()}
        if extracted != files:
            raise ValueError("action extraction differs from reviewed bytes")
        env = {k: v for k, v in os.environ.items()
               if k not in ("GH_TOKEN", "GITHUB_TOKEN", "GATEHOUSE_CHECK_TOKEN",
                            "FEEDBACK_TOKEN", "ACTIONS_RUNTIME_TOKEN")}
        subprocess.run(["node", "--test", "actions/findings-feedback/feedback.test.cjs",
                        "actions/report-artifact/prepare.test.cjs"],
                       cwd=installed, env=env, check=True)
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": PRODUCT,
                                       "version": identity["version"]}},
            "components": [{"type": "file", "name": name,
                            "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(data).hexdigest()}]}
                           for name, data in sorted(files.items())]}
    (output / (archive.name + ".sbom.cdx.json")).write_text(json.dumps(sbom, indent=2) + "\n")
