#!/usr/bin/env python3
"""Pinned current-consumer acceptance for the published rust-source-risk 0.2.0.

This is an acceptance harness, not a production trust provisioner. It verifies
the immutable release archive, the published Core binary, a fresh capture bundle,
the complete signed Core collect path and the separate evaluate path. Every
negative case must fail for its expected reason; a bare nonzero exit is not
accepted as evidence.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
from pathlib import Path


class AcceptanceError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_digest(path: Path) -> str:
    return digest(path.read_bytes())


def write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def read_json(path: Path):
    return json.loads(path.read_text())


def verify_release_inventory(path: Path, pins: dict) -> dict:
    release = pins["release"]
    require(file_digest(path) == release["inventory_sha256"],
            "release inventory digest mismatch")
    inventory = read_json(path)
    require(inventory.get("tag") == release["tag"], "release tag mismatch")
    source = inventory.get("source", {})
    require(source.get("repository") == "https://github.com/musutrade/GateProbes",
            "release source repository mismatch")
    require(source.get("commit") == release["source_commit"],
            "release source commit mismatch")
    assets = {asset.get("name"): asset for asset in inventory.get("assets", [])}
    asset = assets.get(release["archive"])
    require(asset is not None, "release archive missing from inventory")
    require(asset.get("sha256") == release["archive_sha256"],
            "release archive digest mismatch in inventory")
    return inventory


def verify_archive(path: Path, pins: dict, destination: Path) -> Path:
    release = pins["release"]
    require(path.is_file(), f"release archive missing: {path}")
    require(file_digest(path) == release["archive_sha256"],
            "release archive digest mismatch")
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            name = Path(member.name)
            require(not name.is_absolute() and ".." not in name.parts,
                    f"unsafe archive member: {member.name}")
            require(member.isfile() or member.isdir(),
                    f"non-regular archive member: {member.name}")
        archive.extractall(destination, filter="data")
    entries = list(destination.iterdir())
    require(len(entries) == 1 and entries[0].is_dir(),
            "archive must contain one top-level directory")
    plugin = entries[0]
    actual = {}
    for candidate in plugin.rglob("*"):
        require(not candidate.is_symlink(), f"archive symlink: {candidate}")
        if candidate.is_file():
            actual[candidate.relative_to(plugin).as_posix()] = file_digest(candidate)
    expected = release["members"]
    require(actual == expected,
            f"archive member inventory mismatch: {sorted(set(actual) ^ set(expected))}")
    return plugin


def verify_core(path: Path, pins: dict) -> dict:
    require(path.is_absolute(), "Core path must be absolute")
    require(path.is_file(), f"Core binary missing: {path}")
    require(file_digest(path) == pins["core"]["sha256"],
            "Core binary digest mismatch")
    result = subprocess.run([str(path), "--version"], text=True,
                            capture_output=True, check=False)
    require(result.returncode == 0,
            f"Core version probe failed: {result.stderr.strip()}")
    actual = result.stdout.strip()
    require(actual == pins["core"]["version"],
            f"Core version mismatch: {actual!r} != {pins['core']['version']!r}")
    return {"path": str(path), "sha256": file_digest(path), "version": actual}


def verify_toolchain(pins: dict) -> dict:
    tools = pins["tools"]
    rustc = subprocess.run(["rustc", "--version"], text=True,
                           capture_output=True, check=False)
    require(rustc.returncode == 0, "rustc is unavailable")
    require(tools["rustc"] in rustc.stdout,
            f"rustc version mismatch: {rustc.stdout.strip()}")
    coverage = subprocess.run(["cargo", "llvm-cov", "--version"], text=True,
                              capture_output=True, check=False)
    require(coverage.returncode == 0, "cargo-llvm-cov is unavailable")
    require(coverage.stdout.strip().startswith("cargo-llvm-cov " + tools["cargo_llvm_cov"]),
            f"cargo-llvm-cov version mismatch: {coverage.stdout.strip()}")
    python = platform.python_version()
    require(python.startswith(tools["python"] + "."),
            f"Python version mismatch: {python}")
    return {"rustc": rustc.stdout.strip(),
            "cargo_llvm_cov": coverage.stdout.strip(),
            "python": python}


def verify_cargo_environment(root: Path) -> dict:
    cargo_home = os.environ.get("CARGO_HOME")
    require(cargo_home, "CARGO_HOME must be a clean temporary directory")
    cargo_path = Path(cargo_home).resolve()
    require(cargo_path.is_dir(), f"CARGO_HOME is not a directory: {cargo_path}")
    require(not cargo_path.is_relative_to(root),
            "CARGO_HOME must be outside the measured workspace")
    forbidden = {
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET",
        "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTDOC", "CARGO_BUILD_RUSTDOCFLAGS", "RUSTC",
        "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTUP_TOOLCHAIN",
    }
    overrides = sorted(name for name in forbidden if os.environ.get(name))
    require(not overrides, f"unsupported capture environment overrides: {overrides}")
    return {"CARGO_HOME": str(cargo_path), "overrides": []}


def verify_bundle(bundle_path: Path, pins: dict) -> tuple[dict, dict, Path]:
    bundle = read_json(bundle_path)
    require(bundle.get("schema") is None or bundle.get("schema") == "rust-source-capture-bundle/v1",
            "unexpected capture bundle schema")
    request = bundle["request"]
    series = bundle["series"]
    root = Path(request["workspace_root"]).resolve(strict=True)
    require(root.parent == bundle_path.resolve().parent,
            "capture workspace must be a sibling of the bundle")
    require((root / ".local-capture-snapshot").read_text() ==
            "backend-source-only rehearsal\n",
            "capture snapshot marker mismatch")
    require(not (root / ".git").exists(), "capture workspace must not be a checkout")
    receipt = request["parameters"]["receipt"]
    require(receipt.get("schema") == "rust-source-capture/v1",
            "capture receipt schema mismatch")
    require(receipt.get("context") == request.get("context"),
            "capture receipt context mismatch")
    require(request["context"]["target"] == pins["fixture"]["target"],
            "capture target mismatch")
    for name, expected in pins["fixture"]["sources"].items():
        require(receipt["sources"].get(name) == expected,
                f"fixture source digest mismatch: {name}")
    for name, expected in pins["fixture"]["inputs"].items():
        require(receipt["inputs"].get(name) == expected,
                f"fixture input digest mismatch: {name}")
    for name, expected in pins["fixture"]["pipeline_files"].items():
        require(receipt["pipeline"]["files"].get(name) == expected,
                f"fixture pipeline digest mismatch: {name}")
    release = pins["release"]
    require(request["collector"] == {"name": release["name"], "version": release["version"]},
            "collector identity mismatch")
    require(series["collector"] == request["collector"],
            "series collector identity mismatch")
    require(series["target"] == request["context"]["target"],
            "series target mismatch")
    require(series["runtime"]["version"] == platform.python_version(),
            "series runtime does not match the acceptance Python")
    require(request["requested_capabilities"] and
            len(set(request["requested_capabilities"])) == len(request["requested_capabilities"]),
            "duplicate or empty requested capabilities")
    artifact_root = Path(request["output_root"]).resolve()
    require(artifact_root == root / "evidence",
            "artifact root must be the capture evidence directory")
    require(artifact_root.is_dir(), "artifact root is missing")
    require(not any(artifact_root.iterdir()),
            "artifact root must be empty for a fresh acceptance")
    require(Path(receipt["raw_root"]).is_absolute() and Path(receipt["raw_root"]).is_dir(),
            "capture raw root is missing")
    return bundle, request, root


NEGATIVE_LAYERS = {
    "stale-context": "collect",
    "expired": "collect",
    "tampered-signature": "collect",
    "replay": "collect",
    "tampered-artifact": "evaluate",
    "wrong-target": "evaluate",
    "wrong-version": "evaluate",
    "wrong-source": "evaluate",
    "missing-metric": "evaluate",
    "missing-evidence": "evaluate",
}

EVALUATE_REASONS = {
    "wrong-target": "noncanonical measurement series identity",
    "wrong-version": "collector version mismatch",
    "wrong-source": "source identity mismatch",
    "missing-metric": "capability/evidence mismatch: risk.crap",
    "missing-evidence": "missing or ambiguous subject metric evidence",
}


def policy_with_limit(policy: dict, metric: str, limit: dict) -> dict:
    updated = copy.deepcopy(policy)
    for rule in updated["rules"]:
        if rule["metric"] == metric:
            rule["limit"] = limit
    return updated


def check_negative(label: str, layer: str, returncode: int, stderr: str,
                   expected_reason: str, report=None) -> dict:
    require(NEGATIVE_LAYERS[label] == layer,
            f"{label}: layer mismatch {layer!r}")
    require(returncode != 0, f"{label} unexpectedly succeeded")
    reasons = report_reasons(report) if report is not None else [stderr]
    require(any(expected_reason in reason for reason in reasons),
            f"{label}: expected {expected_reason!r}, got {reasons!r}")
    return {
        "case": label, "layer": layer, "exit": returncode,
        "expected_reason": expected_reason,
        "observed_reason": next(reason for reason in reasons
                                if expected_reason in reason),
        "passed": True,
    }


def report_reasons(value) -> list[str]:
    reasons = []

    def visit(item):
        if isinstance(item, dict):
            reason = item.get("reason")
            if isinstance(reason, str):
                reasons.append(reason)
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return reasons


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--release-inventory", type=Path, required=True)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--presets-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pins", type=Path,
                        default=Path(__file__).with_name("core_acceptance.json"))
    args = parser.parse_args()

    pins = read_json(args.pins)
    require(pins.get("schema") == "rust-source-risk-core-acceptance/v1",
            "unexpected acceptance pins schema")
    require(args.presets_dir.is_dir() and (args.presets_dir / "catalog.json").is_file(),
            f"presets catalog missing: {args.presets_dir}")
    require(shutil.which("openssl"), "openssl is unavailable")

    verify_release_inventory(args.release_inventory, pins)
    unpack = Path(tempfile.mkdtemp(prefix="source-risk-unpack-"))
    plugin = verify_archive(args.archive, pins, unpack)
    core_info = verify_core(args.core, pins)
    toolchain = verify_toolchain(pins)
    bundle, measurement, root = verify_bundle(args.bundle, pins)
    cargo_environment = verify_cargo_environment(root)

    host = Path(tempfile.mkdtemp(prefix="host-", dir=root.parent))
    replay = host / "replay"
    replay.mkdir(mode=0o700)
    require(not replay.resolve().is_relative_to(root),
            "replay state must be outside the measured workspace")
    python = Path(sys.executable).resolve()

    def run(label: str, command: list, env=None):
        result = subprocess.run([str(item) for item in command],
                                capture_output=True, text=True, env=env)
        (host / (label + ".stdout")).write_text(result.stdout)
        (host / (label + ".stderr")).write_text(result.stderr)
        return result

    if not (root / ".harness-gate/flow.toml").exists():
        initialized = run("init", [
            core_info["path"], "--project-root", root, "init", "--preset", "rust-api",
            "--presets-dir", args.presets_dir,
        ])
        require(initialized.returncode == 0, initialized.stderr)

    config = root / ".harness-gate"
    flow_name = tomllib.loads((config / "flow.toml").read_text())["project"]["name"]
    request_path = config / "backend-request.json"
    write(request_path, {})
    groups = {"functions": measurement["parameters"]["subjects"]}
    metric_groups = [
        ("functions", "coverage.line"),
        ("functions", "coverage.region"),
        ("functions", "risk.crap"),
    ]
    declared = f'''version = 1
[project]
id = "codexsymphony"
name = {json.dumps(flow_name)}
[components.backend]
flow_components = ["app"]
source_roots = ["apps/server/src"]
artifact_root = "evidence"
'''
    for group in groups:
        declared += f'''[subjects.{group}]
component = "backend"
kind = "{group}"
selection = {{kind = "explicit", paths = {json.dumps(sorted({s["path"] for s in groups[group]}))}}}
'''
    declared += '''[collectors.backend]
protocol = "harness-collector-request/v1"
request = ".harness-gate/backend-request.json"
'''
    rules = []
    for group, metric in [(g, m) for g in groups
                          for m in measurement["requested_capabilities"]]:
        declared += f'''[[collectors.backend.produces]]
target = {{kind = "subject", id = "{group}"}}
capability = "{metric}"
series = "{bundle["series"]["id"]}"
'''
    for group, metric in metric_groups:
        name = group + "." + metric
        rules.append({
            "id": name,
            "scope": {"kind": "subject", "subject": group},
            "metric": metric,
            "operator": "le" if metric == "risk.crap" else "ge",
            "limit": {"type": "rational", "numerator": 10, "denominator": 1}
            if metric == "risk.crap" else {"type": "ratio", "covered": 80, "total": 100},
            "required": True,
            "on_violation": "fail",
            "remediation_classes": ["improve_tests"],
        })
        declared += f'''[policies."{name}"]
policy_file = ".harness-gate/backend-policy.json"
rule = "{name}"
expectation = {{target = {{kind = "subject", id = "{group}"}}, capability = "{metric}", series = "{bundle["series"]["id"]}"}}
'''
    declared += f'''[profiles.full]
assurance = "complete"
collectors = ["backend"]
policies = {json.dumps([r["id"] for r in rules])}
[profiles.hook]
assurance = "partial"
collectors = []
policies = []
[baseline]
required = false
provider = {{kind = "none"}}
[reporting]
output = "target/quality"
formats = ["human", "json"]
'''
    (config / "quality.toml").write_text(declared)
    write(config / "backend-policy.json", {"schema": "harness-policy/v1", "rules": rules})
    component = {
        "id": "backend", "path": "apps/server/src", "metadata": {},
        "targets": [{"id": measurement["context"]["target"],
                     "boundaries": ["production"], "metadata": {}}],
        "source_boundaries": [{"id": "production", "path": "apps/server/src",
                               "role": "production", "metadata": {}}],
    }
    state = {
        "schema": "quality-trusted-state/v1", "profile": "full",
        "expected": measurement["context"], "components": {"backend": component},
        "subjects": groups,
        "subject_kinds": {name: "function/v1" if name == "functions" else "file/v1"
                          for name in groups},
        "relationship_kinds": {}, "series": {"backend": bundle["series"]},
        "artifact_root": "evidence", "artifacts": {},
        "selection": {"changed_subject": sorted(groups), "critical_subject": []},
        "mappings": None, "exceptions": [],
    }
    state_path = host / "state.json"

    def pin():
        state["config_files"] = {
            ".harness-gate/" + name: file_digest(config / name)
            for name in ("flow.toml", "quality.toml", "backend-policy.json",
                         "backend-request.json")
        }
        write(state_path, state)

    pin()
    compiled_path = host / "compiled.json"
    compiled_run = run("compile", [
        core_info["path"], "quality", "compile", "--repository-root", root,
        "--state", state_path, "--output", compiled_path,
    ])
    require(compiled_run.returncode == 0, compiled_run.stderr)
    compiled = read_json(compiled_path)
    payload = {
        "schema": "quality-collector-binding/v1",
        "config_files": {p: d for p, d in state["config_files"].items()
                         if p != ".harness-gate/backend-request.json"},
        "series": state["series"], "profile": "full",
    }
    payload.update({key: compiled[key] for key in
                    ("project", "policy", "expected", "selection", "mappings",
                     "exceptions")})
    config_digest = digest(canonical(payload).encode())
    claims = sorted([
        {"subject": subject["id"], "capability": metric,
         "series": bundle["series"]["id"]}
        for group in groups
        for metric in measurement["requested_capabilities"]
        for subject in groups[group]
    ], key=lambda value: (value["subject"], value["capability"], value["series"]))
    inner = {
        "schema": "harness-project-collector-request/v1",
        "project": measurement["project"],
        "collector": measurement["collector"],
        "context": measurement["context"],
        "workspace_root": str(root),
        "output_root": measurement["output_root"],
        "selection": compiled["selection"],
        "bindings": claims,
    }
    binding_path = host / "binding.json"
    write(binding_path, {
        "schema": "rust-source-project-binding/v1",
        "input": inner, "config_digest": config_digest,
        "request": measurement,
    })
    runtime = {
        str(plugin / name): file_digest(plugin / name)
        for name in ("plugin.py", "measure.py", "inventory", "ast/Cargo.lock",
                     "capture.py")
    }
    runtime[str(python)] = file_digest(python)
    launcher = host / "collector"
    launcher.write_text(
        "#!/usr/bin/python3\nimport os, sys, hashlib\nfrom pathlib import Path\n"
        + "pins = " + repr(runtime) + "\n"
        + "for name, expected in pins.items():\n"
        + "    assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == expected, 'runtime changed'\n"
        + f"os.execv({str(python)!r}, [{str(python)!r}, {str(plugin / 'plugin.py')!r}, *sys.argv[1:]])\n"
    )
    launcher.chmod(0o700)
    key = host / "private.pem"
    prior = os.umask(0o077)
    try:
        keygen = run("keygen", ["openssl", "genpkey", "-algorithm", "ED25519",
                                "-out", key])
        require(keygen.returncode == 0, keygen.stderr)
    finally:
        os.umask(prior)
    public = host / "public.der"
    public_run = run("public", ["openssl", "pkey", "-in", key, "-pubout",
                                "-outform", "DER", "-out", public])
    require(public_run.returncode == 0, public_run.stderr)
    keys = host / "trusted-keys.json"
    write(keys, [{"key_id": "local-backend-only",
                  "public_key": base64.b64encode(public.read_bytes()[12:]).decode()}])
    now = int(time.time() * 1000)
    request = {
        "protocol_version": 2, "result_schema_version": "1",
        "adapter": measurement["collector"] | {
            "executable": str(launcher),
            "source_digest": file_digest(launcher),
            "signature": {"algorithm": "ed25519", "key_id": "local-backend-only",
                          "value": ""},
        },
        "invocation_id": measurement["context"]["run"], "step_id": "backend",
        "timeout_ms": 120000, "config_digest": config_digest,
        "artifact_root": inner["output_root"], "nonce": os.urandom(16).hex(),
        "issued_at_ms": now, "expires_at_ms": now + 300000,
        "args": ["project", "--binding", str(binding_path),
                 "--binding-sha256", file_digest(binding_path)],
        "environment": {},
        "capabilities": {"network": [], "resources": [], "environment": []},
        "input": inner,
    }

    def sign(value, label):
        signed = {
            "domain": "harness-gate/adapter-request/v2", "protocol_version": 2,
            "result_schema_version": "1",
            "adapter": {k: value["adapter"][k]
                        for k in ("name", "version", "executable", "source_digest")},
        }
        signed["adapter"]["signature"] = {"algorithm": "ed25519",
                                          "key_id": "local-backend-only"}
        for name in ("invocation_id", "step_id", "timeout_ms", "config_digest",
                     "artifact_root", "nonce", "issued_at_ms", "expires_at_ms",
                     "args", "environment", "capabilities", "input"):
            signed[name] = (json.loads(canonical(value[name]))
                            if name in ("environment", "input") else value[name])
        sign_input = host / (label + "-sign-input.json")
        sign_input.write_text(json.dumps(signed, separators=(",", ":"),
                                         ensure_ascii=False))
        signature = host / (label + "-signature.bin")
        result = run(label + "-sign", ["openssl", "pkeyutl", "-sign", "-rawin",
                                       "-inkey", key, "-in", sign_input,
                                       "-out", signature])
        require(result.returncode == 0, result.stderr)
        value["adapter"]["signature"]["value"] = base64.b64encode(
            signature.read_bytes()).decode()

    expired = copy.deepcopy(request)
    expired.update(nonce=os.urandom(16).hex(), issued_at_ms=now - 120000,
                   expires_at_ms=now - 60000)
    sign(expired, "expired")
    sign(request, "valid")
    key.unlink()
    require(not key.exists(), "ephemeral private key was not removed")

    collect_command = [
        core_info["path"], "--replay-state-dir", str(replay), "quality", "collect",
        "--repository-root", root, "--state", state_path,
        "--trusted-keys", keys, "--output", host / "collection.json",
    ]

    def collect(label: str, value):
        write(request_path, value)
        pin()
        return run(label, collect_command)

    negatives = []

    def record_negative(label: str, layer: str, result, expected_reason: str,
                        report=None):
        negatives.append(check_negative(
            label, layer, result.returncode, result.stderr, expected_reason,
            report))

    stale = copy.deepcopy(request)
    stale["input"]["context"]["commit"] = "f" * 40
    stale_result = collect("stale-context", stale)
    record_negative("stale-context", "collect", stale_result,
                    "collector roots/selection/capability request mismatch")
    expired_result = collect("expired", expired)
    record_negative("expired", "collect", expired_result,
                    "adapter request has expired")
    broken = copy.deepcopy(request)
    broken["nonce"] += "-tampered"
    rejected = collect("tampered-signature", broken)
    record_negative("tampered-signature", "collect", rejected,
                    "adapter signature verification failed")

    collected = collect("collect", request)
    require(collected.returncode == 0, collected.stderr)
    collection = read_json(host / "collection.json")
    write(host / "accepted-collection.json", collection)
    write(host / "evidence.json", collection["evidence"])
    for name in ("project", "policy", "expected"):
        write(host / (name + ".json"), compiled[name])
    artifact_root = Path(inner["output_root"])

    def evaluate(label: str, evidence, policy_path: Path | None = None,
                 output_name: str | None = None):
        evidence_path = host / (label + "-evidence.json")
        write(evidence_path, evidence)
        policy = policy_path or host / "policy.json"
        report_path = host / (output_name or (label + "-report.json"))
        command = [
            core_info["path"], "quality", "evaluate", "--source-root", root,
            "--artifact-root", artifact_root, "--output", report_path,
            "--project", host / "project.json", "--policy", policy,
            "--expected", host / "expected.json", "--evidence", evidence_path,
        ]
        result = run(label, command)
        report = read_json(report_path) if report_path.exists() else None
        return result, report

    assessed, report = evaluate("evaluate", collection["evidence"])
    require(assessed.returncode == 0, assessed.stderr)
    require(report["aggregate"]["state"] == "pass",
            f"accepted evaluation did not pass: {report['aggregate']}")

    evidence_root = artifact_root
    retained = evidence_root.with_name("accepted-evidence")
    evidence_root.rename(retained)
    evidence_root.mkdir()
    replay_result = collect("replay", request)
    record_negative("replay", "collect", replay_result,
                    "adapter request nonce has already been used")
    evidence_root.rmdir()
    retained.rename(evidence_root)

    artifact_path = evidence_root / collection["evidence"][0]["artifacts"][0]["path"]
    require(artifact_path.resolve().is_relative_to(evidence_root),
            "artifact escapes the output root")
    original = artifact_path.read_bytes()
    try:
        artifact_path.write_bytes(original + b" ")
        tampered, tampered_report = evaluate("tampered-artifact",
                                             collection["evidence"])
        record_negative("tampered-artifact", "evaluate", tampered,
                        "artifact/source digest mismatch", tampered_report)
    finally:
        artifact_path.write_bytes(original)

    def mutated_evidence(label: str, mutate):
        evidence = copy.deepcopy(collection["evidence"])
        mutate(evidence)
        result, mutated_report = evaluate(label, evidence)
        record_negative(label, "evaluate", result,
                        EVALUATE_REASONS[label], mutated_report)

    mutated_evidence("wrong-target",
                     lambda ev: ev[0]["series"].__setitem__(
                         "target", "aarch64-unknown-linux-gnu"))
    mutated_evidence("wrong-version",
                     lambda ev: ev[0]["collector"].__setitem__("version", "0.1.0"))
    mutated_evidence("wrong-source",
                     lambda ev: ev[0]["source"].__setitem__("sha256", "0" * 64))
    mutated_evidence("missing-metric",
                     lambda ev: ev[0].__setitem__(
                         "metrics", [m for m in ev[0]["metrics"]
                                     if m["name"] != "risk.crap"]))
    mutated_evidence("missing-evidence", lambda ev: ev.clear())

    policy_fail = policy_with_limit(
        compiled["policy"], "risk.crap",
        {"type": "rational", "numerator": 1, "denominator": 1})
    policy_fail_path = host / "policy-fail.json"
    write(policy_fail_path, policy_fail)
    policy_result, policy_report = evaluate(
        "policy-fail", collection["evidence"], policy_fail_path,
        "policy-fail-report.json")
    require(policy_result.returncode != 0,
            "real measurement policy failure unexpectedly passed")
    require(policy_report["aggregate"]["state"] == "fail",
            f"policy failure aggregate mismatch: {policy_report['aggregate']}")
    policy_reasons = report_reasons(policy_report)
    require(any("policy limit violated" in reason for reason in policy_reasons),
            f"policy failure reason mismatch: {policy_reasons!r}")

    receipt = {
        "schema": "rust-source-risk-core-acceptance/v1",
        "status": "pass",
        "scope": "current-consumer-regression",
        "release": {
            "tag": pins["release"]["tag"],
            "source_commit": pins["release"]["source_commit"],
            "archive": pins["release"]["archive"],
            "archive_sha256": pins["release"]["archive_sha256"],
            "inventory_sha256": pins["release"]["inventory_sha256"],
            "members": pins["release"]["members"],
        },
        "core": core_info,
        "toolchain": toolchain,
        "cargo_environment": cargo_environment,
        "host": str(host),
        "replay_state": str(replay),
        "signing_key": "ephemeral Ed25519 generated in host and removed before collect",
        "fixture": {
            "bundle": str(args.bundle.resolve()),
            "bundle_sha256": file_digest(args.bundle),
            "workspace": str(root),
            "commit": measurement["context"]["commit"],
            "target": measurement["context"]["target"],
            "sources": measurement["parameters"]["receipt"]["sources"],
            "inputs": measurement["parameters"]["receipt"]["inputs"],
            "pipeline": measurement["parameters"]["receipt"]["pipeline"],
        },
        "positive": {
            "transport": "PASS",
            "collect_exit": 0,
            "evaluate_exit": assessed.returncode,
            "aggregate": report["aggregate"]["state"],
            "series": bundle["series"]["id"],
            "evidence_records": len(collection["evidence"]),
            "metrics": collection["evidence"][0]["metrics"],
            "capabilities": collection["evidence"][0]["capabilities"],
        },
        "negatives": negatives,
        "policy_fail": {
            "transport": "PASS",
            "evaluate_exit": policy_result.returncode,
            "aggregate": policy_report["aggregate"]["state"],
            "expected_reason": "policy limit violated",
            "observed_reason": next(reason for reason in policy_reasons
                                    if "policy limit violated" in reason),
            "fixture_policy": "CRAP limit 1/1, unrelated to production policy",
        },
        "checks": {
            "release_inventory": "verified",
            "archive": "verified",
            "archive_members": "verified",
            "core_binary": "verified",
            "toolchain": "verified",
            "fresh_capture": "verified",
            "empty_artifact_root": "verified",
            "ephemeral_key_removed": "verified",
            "replay_state_outside_workspace": "verified",
        },
        "limitations": [
            "acceptance harness, not production trust provisioning",
            "Linux x86_64 only",
            "thiserror macro attributes remain unsupported",
            "current 0.2.0 consumer regression; not a new candidate artifact",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write(args.output, receipt)
    copy_root = args.output.parent / "host"
    if copy_root.exists():
        shutil.rmtree(copy_root)
    shutil.copytree(host, copy_root)
    print(json.dumps(receipt, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AcceptanceError as error:
        print(f"ACCEPTANCE FAILED: {error}", file=sys.stderr)
        raise SystemExit(1)
