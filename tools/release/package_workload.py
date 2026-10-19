"""Fixed data-only workload distribution; installation trust stays operator-owned.

The existing protected release workflow attests/signs this archive via OIDC.
No operator key, test signature, or generated installation lock is distributed.
"""
from __future__ import annotations

import base64
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

import plugin_release

PRODUCT = "gatehouse-linux-test"
CATALOG = f"workloads/{PRODUCT}/products.json"


def checked_file(root: Path, name: str) -> bytes:
    path = Path(name)
    if path.is_absolute() or not path.parts or any(p in (".", "..") for p in path.parts):
        raise ValueError("unsafe workload member")
    target = root
    for part in path.parts:
        target /= part
        if target.is_symlink():
            raise ValueError("workload member is a symlink")
    if not target.is_file():
        raise ValueError("workload member is not a file")
    return target.read_bytes()


def members(root: Path) -> dict[str, bytes]:
    catalog = json.loads(checked_file(root, CATALOG))
    if catalog.get("schema") != "gateprobes-products/v1":
        raise ValueError("unknown product catalog")
    product = catalog["products"][PRODUCT]
    names = product["files"]
    if not isinstance(names, list) or len(set(names)) != len(names):
        raise ValueError("duplicate workload members")
    prefix = f"workloads/{PRODUCT}/"
    if any(not name.startswith(prefix) for name in names):
        raise ValueError("workload data must stay inside its product directory")
    files = {name: checked_file(root, name) for name in names}
    for name in (CATALOG, "tools/onboarding/plugin_manager.py", "LICENSE"):
        if name in files:
            raise ValueError("duplicate distribution member")
        files[name] = checked_file(root, name)
    # Validate shipped declarations, without evaluating project quality policy.
    json.loads(files[prefix + "preset/catalog.json"])
    json.loads(files[prefix + "toolchain.json"])
    tomllib.loads(files[prefix + "preset/flow.toml"].decode())
    return files


def run(args: list, cwd: Path) -> bytes:
    result = subprocess.run([str(a) for a in args], cwd=cwd, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return result.stdout


def accept(installed: Path, work: Path, core: Path) -> None:
    """Use only archive members and the fixed Core; test keys never leave work."""
    private, public = work / "test.pem", work / "test-key.json"
    run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", private], work)
    der = run(["openssl", "pkey", "-in", private, "-pubout", "-outform", "DER"], work)
    if len(der) != 44 or not der.startswith(bytes.fromhex("302a300506032b6570032100")):
        raise ValueError("unexpected Ed25519 public key encoding")
    public.write_text(json.dumps({"key_id": "package-acceptance-only",
                                 "public_key": base64.b64encode(der[-32:]).decode()}))
    tool = [sys.executable, installed / "tools/onboarding/plugin_manager.py"]
    prepared, lock = work / "prepared", work / "lock.json"
    run([*tool, "prepare", "--source", installed, "--catalog", CATALOG,
         "--product", PRODUCT, "--signing-key", private, "--key-id", "package-acceptance-only",
         "--output", prepared, "--lock-output", lock], work)
    project, store = work / "project", work / "store"
    project.mkdir()
    plan = work / "plan.json"
    run([*tool, "plan", "--lock", lock, "--active-lock", project / ".harness-gate/plugins.lock.json",
         "--store", store, "--prepared", prepared, "--output", plan], work)
    run([*tool, "apply", "--plan", plan, "--receipt", work / "receipt.json",
         "--core", core, "--trusted-key", public], work)
    command = [core, "--project-root", project, "--plugin-store", store,
               "--plugin-trusted-key", public]
    run([*command, "init", "--plugin", PRODUCT, "--preset", PRODUCT], work)
    run([*command, "config", "check", "--format", "json"], work)
    # This is package compatibility, not a new full Rust workload execution.
    selected = json.loads(run([*command, "verify", "--plan", "--json", "--all"], work))
    if "linux.rust-tests" not in selected.get("plan", {}).get("execution_order", []):
        raise ValueError("installed workload step missing from Core plan")


def package(root: Path, output: Path, core: Path) -> None:
    identity = plugin_release.resolve(PRODUCT, root)
    files = members(root)
    name = identity["archive"].removesuffix(".tar.gz")
    archive = output / identity["archive"]
    # Stable ordering, permissions, timestamps and gzip header bind data bytes.
    with archive.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as stream:
            for path, data in sorted(files.items()):
                entry = tarfile.TarInfo(f"{name}/{path}")
                entry.size, entry.mode, entry.mtime = len(data), 0o644, 0
                stream.addfile(entry, io.BytesIO(data))
    with tempfile.TemporaryDirectory(prefix="workload-package-") as tmp:
        work = Path(tmp)
        with tarfile.open(archive) as stream:
            stream.extractall(work / "unpacked", filter="data")
        installed = work / "unpacked" / name
        if members(installed) != files:
            raise ValueError("workload archive differs from reviewed input bytes")
        accept(installed, work, core.resolve())
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": PRODUCT,
                                       "version": identity["version"]}},
            "components": [{"type": "file", "name": path,
                            "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(data).hexdigest()}]}
                           for path, data in sorted(files.items())]}
    (output / (archive.name + ".sbom.cdx.json")).write_text(json.dumps(sbom, indent=2) + "\n")
