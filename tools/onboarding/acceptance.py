#!/usr/bin/env python3
"""Real two-ecosystem onboarding against an explicitly selected candidate Core."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    core = args.core.resolve(strict=True)
    work = args.work_dir.absolute()
    work.mkdir(mode=0o700, parents=True)  # No overwriting prior acceptance evidence.
    work = work.resolve()
    counter = 0
    steps = []

    def run(command, *, cwd=None, expected=None):
        nonlocal counter
        counter += 1
        result = subprocess.run([str(v) for v in command], cwd=cwd, capture_output=True,
                                env={**os.environ, "HARNESS_GATE_PRESETS_DIR": ""})
        (work / f"{counter:02d}.stdout.log").write_bytes(result.stdout)
        (work / f"{counter:02d}.stderr.log").write_bytes(result.stderr)
        text = (result.stdout + result.stderr).decode(errors="replace")
        if (expected is None and result.returncode != 0) or (expected is not None and (result.returncode == 0 or expected not in text)):
            raise RuntimeError(f"step {counter} failed ({expected}): {command}\n{text}")
        steps.append({"step": counter, "command": [str(v) for v in command], "exit": result.returncode,
                      "expected_diagnostic": expected})
        return result.stdout

    private, public = work / "operator.pem", work / "operator.json"
    run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", private])
    der = run(["openssl", "pkey", "-in", private, "-pubout", "-outform", "DER"])
    if not der.startswith(bytes.fromhex("302a300506032b6570032100")) or len(der) != 44:
        raise RuntimeError("unexpected Ed25519 public key encoding")
    public.write_text(json.dumps({"key_id": "acceptance-operator", "public_key": base64.b64encode(der[-32:]).decode()}))
    tool = [sys.executable, ROOT / "tools/onboarding/plugin_manager.py"]
    prepared, lock, store = work / "prepared-v1", work / "lock-v1.json", work / "installed"
    run([*tool, "prepare", "--product", "rust-minimal", "--product", "python-minimal", "--signing-key", private,
         "--key-id", "acceptance-operator", "--output", prepared, "--lock-output", lock])
    config_before = {}
    for ecosystem in ("rust", "python"):
        project = work / (ecosystem + "-project")
        project.mkdir()
        if ecosystem == "rust":
            (project / "src").mkdir()
            (project / "src/lib.rs").write_text("pub fn answer() -> u32 { 42 }\n")
            (project / "Cargo.toml").write_text('[package]\nname = "onboarding-fixture"\nversion = "0.1.0"\nedition = "2021"\n')
            run(["cargo", "generate-lockfile", "--offline"], cwd=project)
        else:
            (project / "tests").mkdir()
            (project / "tests/test_answer.py").write_text('import unittest\nclass Answer(unittest.TestCase):\n    def test_answer(self):\n        self.assertEqual(6 * 7, 42)\n')
        run(["git", "init"], cwd=project)
        plan, receipt = work / (ecosystem + "-install.json"), work / (ecosystem + "-receipt.json")
        run([*tool, "plan", "--lock", lock, "--active-lock", project / ".harness-gate/plugins.lock.json",
             "--store", store, "--prepared", prepared, "--output", plan])
        run([*tool, "apply", "--plan", plan, "--receipt", receipt, "--core", core, "--trusted-key", public])
        command = [core, "--project-root", project, "--plugin-store", store, "--plugin-trusted-key", public]
        run([*command, "init", "--plugin", ecosystem + "-minimal", "--preset", ecosystem + "-minimal"])
        run([*command, "config", "check", "--format", "json"])
        run([*command, "doctor", "--json"])
        run([*command, "verify", "--plan", "--json", "--all"])
        run([*command, "verify", "--all"])
        if (project / ".harness-gate/quality.toml").exists():
            raise RuntimeError("minimal execution-only preset silently adopted quality policy")
        config_before[ecosystem] = (project / ".harness-gate/flow.toml").read_bytes()
        run([core, "--project-root", project, "--plugin-store", store, "config", "check", "--format", "json"], expected="HGPLUGIN-SIGNATURE")
    # Corruption is diagnosed, never silently repaired or repinned.
    product_version = json.loads((ROOT / "products/onboarding/products.json").read_text())["products"]["rust-minimal"]["version"]
    artifact = store / f"rust-minimal/{product_version}/products/onboarding/presets/rust/flow.toml"
    original = artifact.read_bytes()
    artifact.write_bytes(b"corrupt")
    rust = work / "rust-project"
    command = [core, "--project-root", rust, "--plugin-store", store, "--plugin-trusted-key", public]
    run([*command, "config", "check", "--format", "json"], expected="HGPLUGIN-DIGEST")
    artifact.write_bytes(original)
    # An upgrade changes only explicit locked artifact selection; configuration,
    # baseline, policy and installed system toolchains remain operator-owned.
    source = work / "source-v2"
    shutil.copytree(ROOT / "products/onboarding", source / "products/onboarding")
    catalog = source / "products/onboarding/products.json"
    value = json.loads(catalog.read_text())
    major, minor, patch = (int(part) for part in product_version.split("."))
    value["products"]["rust-minimal"]["version"] = f"{major}.{minor}.{patch + 1}"
    catalog.write_text(json.dumps(value))
    prepared2, lock2 = work / "prepared-v2", work / "lock-v2.json"
    run([*tool, "prepare", "--source", source, "--product", "rust-minimal", "--product", "python-minimal",
         "--signing-key", private, "--key-id", "acceptance-operator", "--output", prepared2, "--lock-output", lock2])
    upgrade, receipt = work / "upgrade.json", work / "upgrade-receipt.json"
    run([*tool, "plan", "--lock", lock2, "--active-lock", rust / ".harness-gate/plugins.lock.json", "--store", store,
         "--prepared", prepared2, "--output", upgrade])
    run([*tool, "apply", "--plan", upgrade, "--receipt", receipt, "--core", core, "--trusted-key", public])
    run([*command, "config", "check"])
    run([*tool, "rollback", "--receipt", receipt])
    if (rust / ".harness-gate/plugins.lock.json").read_bytes() != lock.read_bytes():
        raise RuntimeError("rollback did not restore exact v1 lock bytes")
    if (rust / ".harness-gate/flow.toml").read_bytes() != config_before["rust"]:
        raise RuntimeError("install/upgrade changed project policy")
    run([*command, "verify", "--all"])
    report = {"schema": "gateprobes-onboarding-acceptance/v1", "passed": True, "ecosystems": ["rust", "python"],
              "core_sha256": hashlib.sha256(core.read_bytes()).hexdigest(), "steps": steps}
    (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: {len(steps)} real steps, Rust/Python init -> check -> verify, upgrade/rollback, trust/corruption diagnostics")


if __name__ == "__main__":
    main()
