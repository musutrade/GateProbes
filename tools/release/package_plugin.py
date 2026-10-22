#!/usr/bin/env python3
"""Build and accept one GateProbes package against the pinned released Core.

Packaging migrated from Harness-Gate; measurement and policy semantics are unchanged.
"""
from __future__ import annotations

import argparse
import json
import importlib.util
import os
import re
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

import pinned_core
import readiness_core
import lifecycle_core
import package_lifecycle
import plugin_release
import package_workload
import package_consumer
import package_actions
import package_operator
import package_onboarding
import package_runtime
import package_importer
import importer_core
import importer_core_v3

ROOT = Path(__file__).resolve().parents[2]


def run(*args: str, cwd: Path = ROOT, env=None, echo=True, combine=False) -> str:
    result = subprocess.run(args, cwd=cwd, env=env, check=False, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT if combine else None)
    if echo or result.returncode:
        print(result.stdout, end="", flush=True)
    result.check_returncode()
    return result.stdout


def node_test_environment(source: Path, stage: str) -> dict:
    env = dict(os.environ, NODE_PATH="")
    if env.get("HARNESS_GATE_TYPESCRIPT_ACCEPTANCE"):
        env["HARNESS_GATE_TYPESCRIPT_ACCEPTANCE"] = str(
            Path(env["HARNESS_GATE_TYPESCRIPT_ACCEPTANCE"]) / stage)
    return env


def copy_node_tests(source: Path, installed: Path, tests: list[str]) -> None:
    for filename in tests:
        text = (source / filename).read_text()
        if source.name == "typescript-risk":
            dependency = 'require("istanbul-lib-instrument")'
            if text.count(dependency) != 1:
                raise RuntimeError("cannot locate the isolated Istanbul test-tool import")
            # Only the copied test harness receives this absolute test-tool
            # import. Runtime dependencies cannot fall back to source modules.
            tool = str(source / "node_modules/istanbul-lib-instrument")
            text = text.replace(dependency, "require(" + json.dumps(tool) + ")")
        (installed / filename).write_text(text)


def verify_node_dependencies(installed: Path, consumer: Path, env: dict) -> None:
    script = ("const fs=require('node:fs'),path=require('node:path');"
              "const req=require('node:module').createRequire(path.resolve('package.json'));"
              "const p=req('./package.json');const root=fs.realpathSync(process.argv[1])+path.sep;"
              "for(const name of Object.keys(p.dependencies||{})){"
              "const resolved=fs.realpathSync(req.resolve(name));"
              "if(!resolved.startsWith(root))throw Error('runtime dependency escaped install: '+name);}")
    run("node", "-e", script, str(consumer / "node_modules"), cwd=installed, env=env)


def reject_missing_typescript(executable: Path, consumer: Path, env: dict) -> None:
    """Prove these collectors cannot use a development/global fallback."""
    dependency = consumer / "node_modules/typescript"
    withheld = consumer / "withheld-typescript"
    dependency.rename(withheld)
    try:
        result = subprocess.run([str(executable), "--version"], cwd=consumer, env=env,
                                text=True, capture_output=True, check=False)
        print(result.stdout + result.stderr, end="", flush=True)
        if result.returncode == 0 or "Cannot find module 'typescript'" not in result.stderr:
            raise RuntimeError("installed collector did not reject its missing TypeScript dependency")
        print("missing runtime TypeScript dependency: correctly rejected", flush=True)
    finally:
        withheld.rename(dependency)


def measurer_archive_name(version: str) -> str:
    return "harness-gate-rust-measure-" + version + "-linux-amd64.tar.gz"


def measurer_identity(source: Path) -> dict:
    manifest = tomllib.loads((source / "Cargo.toml").read_text())
    identity = json.loads((source / "plugin.json").read_text())
    if manifest["package"]["name"] != identity["name"]:
        raise RuntimeError("measurer plugin identity name mismatch")
    if manifest["package"]["version"] != identity["version"]:
        raise RuntimeError("measurer plugin identity version mismatch")
    return identity


def check_measurer_identity(binary: Path, source: Path, identity: dict) -> None:
    result = subprocess.run([str(binary), str(source), "--target-cfg"],
                            input=json.dumps({"target": "packaged", "cfg": []}),
                            capture_output=True, text=True, check=True)
    report = json.loads(result.stdout)
    if (report.get("analyzer"), report.get("version"), report.get("rule")) != (
            identity["analyzer"], identity["version"], identity["rule"]):
        raise RuntimeError("packaged measurer identity mismatch")


def rust_measure_package(output: Path, core: Path) -> None:
    source = ROOT / "plugins/rust-measure"
    manifest = source / "Cargo.toml"
    identity = measurer_identity(source)
    version = identity["version"]
    with tempfile.TemporaryDirectory(prefix="rust-measure-package-") as tmp:
        stage = Path(tmp)
        env = dict(os.environ, CARGO_TARGET_DIR=str(stage / "target"))
        run("cargo", "test", "--locked", "--manifest-path", str(manifest), env=env)
        run("cargo", "build", "--locked", "--release", "--manifest-path", str(manifest), env=env)
        binary = stage / "target/release" / identity["executable"]
        name = "harness-gate-rust-measure-" + version + "-linux-amd64"
        package = stage / name
        package.mkdir()
        for filename in ("plugin.json", "Cargo.toml", "Cargo.lock", "README.md"):
            shutil.copy2(source / filename, package / filename)
        shutil.copy2(ROOT / "LICENSE", package / "LICENSE")
        shutil.copy2(binary, package / identity["executable"])
        smoke = stage / "smoke.rs"
        smoke.write_text("fn packaged_measure(x: bool) { if x {} }\n")
        check_measurer_identity(package / identity["executable"], smoke, identity)
        archive = output / measurer_archive_name(version)
        with tarfile.open(archive, "w:gz") as stream:
            stream.add(package, arcname=name)
        # Extracting the archive catches omitted files before publication.
        consumer = stage / "consumer"
        consumer.mkdir()
        with tarfile.open(archive) as stream:
            stream.extractall(consumer, filter="data")
        installed = consumer / name
        for filename in ("plugin.json", "Cargo.toml", "Cargo.lock", "README.md",
                         "LICENSE", identity["executable"]):
            if not (installed / filename).is_file():
                raise RuntimeError("incomplete measurer archive: " + filename)
        check_measurer_identity(installed / identity["executable"], smoke, identity)
        run("python3", str(source / "contract.py"), "--binary", str(installed / identity["executable"]),
            "--core-root", str(core / "tools/quality"), cwd=consumer)
        metadata = stage / "cargo-metadata.json"
        metadata.write_text(run("cargo", "metadata", "--locked", "--format-version", "1",
                                "--manifest-path", str(manifest), env=env, echo=False))
        run("python3", str(core / "tools/release/generate-sbom.py"), "--metadata", str(metadata),
            "--lockfile", str(source / "Cargo.lock"),
            "--output", str(output / (measurer_archive_name(version) + ".sbom.cdx.json")))


def require_service_contract(core_binary: Path) -> None:
    """Probe the already verified Core artifact; never compile a substitute."""
    with tempfile.TemporaryDirectory(prefix="postgres-core-schema-") as tmp:
        directory = Path(tmp)
        run(str(core_binary), "--project-root", str(directory), "schema", "export",
            "--output", "flow.schema.json", cwd=directory)
        schema = json.loads((directory / "flow.schema.json").read_text())
        if "service_checks" not in schema.get("properties", {}):
            raise RuntimeError("pinned released Core lacks gate-service-check/v1; "
                               "publish and explicitly pin a compatible Core before packaging Postgres")


def stage_postgres(binary: Path, source: Path, package: Path) -> None:
    package.mkdir()
    identity = measurer_identity(source)
    for filename in ("plugin.json", "Cargo.toml", "Cargo.lock", "README.md", "LICENSE",
                     "prepare-preset.py"):
        shutil.copy2(source / filename, package / filename)
    shutil.copy2(binary, package / identity["executable"])
    shutil.copy2(ROOT / "protocol/service-check.schema.json", package / "service-check.schema.json")
    shutil.copytree(ROOT / "presets", package / "presets")


def accept_postgres_archive(archive: Path, source: Path, consumer: Path,
                            core_binary: Path, report: Path) -> None:
    consumer.mkdir()
    with tarfile.open(archive) as stream:
        stream.extractall(consumer, filter="data")
    installed = consumer / archive.name.removesuffix(".tar.gz")
    identity = measurer_identity(source)
    required = ("plugin.json", "Cargo.toml", "Cargo.lock", "README.md", "LICENSE",
                "prepare-preset.py", "service-check.schema.json", "presets/catalog.json",
                identity["executable"])
    for filename in required:
        if not (installed / filename).is_file():
            raise RuntimeError("incomplete Postgres archive: " + filename)
    if run(str(installed / identity["executable"]), "--version", cwd=consumer).strip() != (
            identity["name"] + " " + identity["version"]):
        raise RuntimeError("installed Postgres identity mismatch")
    run("python3", str(source / "contract.py"), "--binary", str(installed / identity["executable"]),
        "--core-binary", str(core_binary), "--output", str(report), cwd=consumer)
    # Installed setup resources must preserve the original execution/quality gates.
    catalog = consumer / "prepared-presets"
    run("python3", str(installed / "prepare-preset.py"), "--binary",
        str(installed / identity["executable"]), "--output", str(catalog), cwd=consumer)
    project = consumer / "project"
    project.mkdir()
    run(str(core_binary), "--project-root", str(project), "--presets-dir", str(catalog),
        "init", "--preset", "angular-rust-postgres", cwd=consumer)
    run(str(core_binary), "--project-root", str(project), "config", "check", cwd=consumer)
    spec = importlib.util.spec_from_file_location("preset_accept", ROOT / "tools/presets/accept.py")
    parity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parity)
    declaration = json.loads((catalog / "catalog.json").read_text())
    parity.verify_generated(catalog, declaration,
                            declaration["presets"]["angular-rust-postgres"], project)


def postgres_package(output: Path, core: Path, core_binary: Path) -> None:
    require_service_contract(core_binary)
    source = ROOT / "plugins/postgres-service"
    identity = measurer_identity(source)
    name = "gateprobes-postgres-" + identity["version"] + "-linux-amd64"
    with tempfile.TemporaryDirectory(prefix="postgres-package-") as tmp:
        stage = Path(tmp)
        manifest = source / "Cargo.toml"
        env = dict(os.environ, CARGO_TARGET_DIR=str(stage / "target"))
        run("cargo", "test", "--locked", "--manifest-path", str(manifest), env=env)
        run("cargo", "build", "--locked", "--release", "--manifest-path", str(manifest), env=env)
        stage_postgres(stage / "target/release" / identity["executable"], source, stage / name)
        archive = output / (name + ".tar.gz")
        with tarfile.open(archive, "w:gz") as stream:
            stream.add(stage / name, arcname=name)
        evidence = Path(os.environ.get("HARNESS_GATE_POSTGRES_ACCEPTANCE", str(stage / "acceptance")))
        evidence.mkdir(parents=True, exist_ok=True)
        accept_postgres_archive(archive, source, stage / "consumer", core_binary,
                                evidence / "installed-contract.json")
        metadata = stage / "cargo-metadata.json"
        metadata.write_text(run("cargo", "metadata", "--locked", "--format-version", "1",
                                "--manifest-path", str(manifest), env=env, echo=False))
        sbom = core / "tools/release/generate-sbom.py"
        if not sbom.is_file():
            # Ordinary CI fetches this same pinned source resource at the root.
            sbom = core / "generate-sbom.py"
        run("python3", str(sbom), "--metadata", str(metadata), "--lockfile", str(source / "Cargo.lock"),
            "--output", str(output / (archive.name + ".sbom.cdx.json")))


def node_package(directory: str, output: Path, core: Path) -> None:
    # npm's dependency tree is a packaging input, never a checkout artifact.
    with tempfile.TemporaryDirectory(prefix="node-package-") as tmp:
        source = Path(tmp) / directory
        shutil.copytree(ROOT / "plugins" / directory, source,
                        ignore=shutil.ignore_patterns("node_modules", "*.tgz", "__pycache__"))
        package_node_source(source, output, core)


def package_node_source(source: Path, output: Path, core: Path) -> None:
    directory = source.name
    run("npm", "ci", "--ignore-scripts", cwd=source)
    run("npm", "test", cwd=source)
    if directory == "typescript-risk":
        run("npm", "run", "test:core", cwd=source, env=node_test_environment(source, "source"))
    packed = json.loads(run("npm", "pack", "--ignore-scripts", "--json",
                            "--pack-destination", str(output), cwd=source))
    archive = output / packed[0]["filename"]
    accept_node_archive(source, archive, core, output)


def accept_node_archive(source: Path, archive: Path, core: Path, output: Path) -> None:
    directory = source.name
    package = json.loads((source / "package.json").read_text())
    # A fresh install catches omitted runtime modules and shrinkwrap errors.
    with tempfile.TemporaryDirectory(prefix="collector-consumer-") as tmp:
        consumer = Path(tmp)
        (consumer / "package.json").write_text(json.dumps({
            "name": "harness-gate-collector-runtime", "version": package["version"],
            "private": True,
        }))
        run("npm", "install", "--ignore-scripts", "--omit=dev", "--prefix", tmp,
            str(archive))
        executable = consumer / "node_modules/.bin" / next(iter(package["bin"]))
        env = node_test_environment(source, "installed")
        version = run(str(executable), "--version", env=env)
        if version.strip() != next(iter(package["bin"])) + " " + package["version"]:
            raise RuntimeError("installed collector version mismatch")
        # Run the source test harness against the actual installed runtime files.
        installed = consumer / "node_modules" / package["name"]
        tests = (["test.cjs", "test-core.cjs"] if directory == "typescript-risk"
                 else ["test.cjs", "business.test.cjs"])
        verify_node_dependencies(installed, consumer, env)
        reject_missing_typescript(executable, consumer, env)
        copy_node_tests(source, installed, tests)
        run("node", "--test", *tests, cwd=installed, env=env)
        if directory == "http-json-contract":
            run("python3", str(source / "contract.py"), "--cli", str(installed / "cli.cjs"),
                "--plugin", str(installed), "--core-root", str(core / "tools/quality"), cwd=consumer, env=env)
        # Generate the actual installed runtime dependency inventory.
        sbom = run("npm", "sbom", "--sbom-format=cyclonedx", "--omit=dev",
                   cwd=consumer, echo=False)
        json.loads(sbom)
        (output / (archive.name + ".sbom.cdx.json")).write_text(sbom)


def rust_package(output: Path, core: Path) -> None:
    source = ROOT / "plugins/rust-source-risk"
    manifest = source / "ast/Cargo.toml"
    identity = json.loads((source / "plugin.json").read_text())
    with tempfile.TemporaryDirectory(prefix="rust-source-package-") as tmp:
        stage = Path(tmp)
        env = dict(os.environ, CARGO_TARGET_DIR=str(stage / "target"))
        run("cargo", "test", "--locked", "--manifest-path", str(manifest), env=env)
        run("cargo", "build", "--locked", "--release", "--manifest-path", str(manifest), env=env)
        inventory = stage / "target/release/harness-gate-rust-source-inventory"
        env["RUST_SOURCE_INVENTORY"] = str(inventory)
        # Existing tests also exercise the default sibling executable path.
        # Keep build/test products outside the checked-in plugin source.
        test_source = stage / "source-tests"
        shutil.copytree(source, test_source, ignore=shutil.ignore_patterns(
            "target", "inventory", "__pycache__", "*.tar.gz"))
        shutil.copy2(inventory, test_source / "inventory")
        run("python3", "-m", "unittest", "discover", "-s", str(test_source),
            "-p", "test_*.py", "-v", env=env)
        name = "harness-gate-rust-source-risk-" + identity["version"] + "-linux-amd64"
        package = stage / name
        package.mkdir()
        for filename in ("plugin.py", "measure.py", "capture.py", "plugin.json", "LICENSE", "README.md"):
            shutil.copy2(source / filename, package / filename)
        shutil.copy2(inventory, package / "inventory")
        (package / "ast").mkdir()
        shutil.copy2(source / "ast/Cargo.lock", package / "ast/Cargo.lock")
        run("python3", str(package / "plugin.py"), "--help", cwd=stage)
        metadata = stage / "cargo-metadata.json"
        metadata.write_text(run("cargo", "metadata", "--locked", "--format-version", "1",
                                "--manifest-path", str(manifest), env=env, echo=False))
        spec = importlib.util.spec_from_file_location(
            "locked_notices", ROOT / "plugins/rust-native-plugin/locked_notices.py")
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        lock = {(p["name"], p["version"], p.get("source")): p for p in
                tomllib.loads((source / "ast/Cargo.lock").read_text())["package"]}
        notices = []
        for dependency in json.loads(metadata.read_text())["packages"]:
            if dependency["source"]:
                texts, _ = verifier.registry_notices(dependency, lock)
                notices.extend(f'{dependency["name"]} {dependency["version"]} / {file}\n{text}'
                               for file, text in sorted(texts.items()))
        sysroot = Path(run("rustc", "--print", "sysroot").strip())
        notices.append((sysroot / "share/doc/rust/COPYRIGHT-library.html").read_text())
        (package / "THIRD_PARTY_NOTICES.txt").write_text("\n\n".join(notices))
        smoke = stage / "smoke.rs"
        smoke.write_text("fn published_inventory(x: bool) { if x {} }\n")
        rows = json.loads(run(str(package / "inventory"), str(smoke), cwd=stage))
        if len(rows) != 1 or rows[0]["complexity"] != 2:
            raise RuntimeError("packaged inventory smoke test failed")
        with tarfile.open(output / (name + ".tar.gz"), "w:gz") as archive:
            archive.add(package, arcname=name)
        accept_rust_archive(output / (name + ".tar.gz"), source, stage / "consumer", core)
        run("python3", str(core / "tools/release/generate-sbom.py"), "--metadata", str(metadata),
            "--lockfile", str(source / "ast/Cargo.lock"),
            "--output", str(output / (name + ".tar.gz.sbom.cdx.json")))


def accept_rust_archive(archive: Path, source: Path, consumer: Path, core: Path) -> None:
    """Exercise the extracted archive; source-tree tests alone miss omitted files."""
    consumer.mkdir()
    with tarfile.open(archive) as stream:
        stream.extractall(consumer, filter="data")
    installed = consumer / archive.name.removesuffix(".tar.gz")
    required = ("plugin.py", "measure.py", "capture.py", "plugin.json", "inventory",
                "ast/Cargo.lock", "LICENSE", "THIRD_PARTY_NOTICES.txt")
    for name in required:
        if not (installed / name).is_file():
            raise RuntimeError("incomplete Rust collector archive: " + name)
    for test in source.glob("test_*.py"):
        shutil.copy2(test, installed / test.name)
    shutil.copytree(source / "fixtures", installed / "fixtures")
    output = run("python3", "-m", "unittest", "discover", "-s", str(installed),
                 "-p", "test_*.py", "-v", cwd=consumer, combine=True, env=dict(
                     os.environ, PYTHONPATH="", RUST_SOURCE_INVENTORY=str(installed / "inventory")))
    if "skipped=" in output or not re.search(r"Ran [1-9][0-9]* tests", output):
        raise RuntimeError("extracted Rust collector acceptance skipped tests")
    run("python3", str(source / "contract.py"), "--plugin", str(installed),
        "--core-root", str(core / "tools/quality"), cwd=consumer)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin", choices=tuple(plugin_release.releases()), required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--core-root", required=True, type=Path)
    args = parser.parse_args()
    row = plugin_release.resolve(args.plugin)
    core = args.core_root.resolve()
    if args.plugin == "docker-lifecycle":
        lifecycle_core.verify(core)
        package_lifecycle.validate(ROOT)
        output = args.output.resolve()
        output.mkdir(parents=True, exist_ok=False)
        package_lifecycle.package(ROOT, output, core)
        expected = {row["archive"], row["archive"] + ".sbom.cdx.json"}
        if {path.name for path in output.iterdir()} != expected:
            raise RuntimeError("lifecycle packaged assets differ")
        return
    if args.plugin == "docker-readiness":
        readiness_core.verify(core)
        output = args.output.resolve()
        output.mkdir(parents=True, exist_ok=False)
        package_runtime.package(ROOT, output, core, "docker-readiness")
        expected = {row["archive"], row["archive"] + ".sbom.cdx.json"}
        if {path.name for path in output.iterdir()} != expected:
            raise RuntimeError("readiness packaged assets differ")
        return
    if args.plugin == "runtime-importer":
        if row['version'] == '0.2.0':
            importer_core_v3.verify(core)
        else:
            importer_core.verify(core)
        output = args.output.resolve()
        output.mkdir(parents=True, exist_ok=False)
        assets = core / "runtime-assets"
        package_importer.package(ROOT, output, core, assets)
        expected = {row["archive"], row["archive"] + ".sbom.cdx.json"}
        if {path.name for path in output.iterdir()} != expected:
            raise RuntimeError("importer packaged assets differ")
        return
    contract = pinned_core.verify(core)
    os.environ["HARNESS_GATE_BINARY"] = str(core / "bin" / contract["platforms"]["linux"]["binary"])
    os.environ["HARNESS_GATE_EXPECTED_VERSION"] = contract["version"]
    os.environ["PYTHONPATH"] = str(core / "tools/quality")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    if args.plugin == "docker-runtime":
        package_runtime.package(ROOT, output, core)
    elif args.plugin == "gatehouse-linux-test":
        package_workload.package(ROOT, output, Path(os.environ["HARNESS_GATE_BINARY"]))
    elif args.plugin == "onboarding-presets":
        package_onboarding.package(ROOT, output, Path(os.environ["HARNESS_GATE_BINARY"]))
    elif args.plugin == "operator-lifecycle":
        package_operator.package(ROOT, output, core)
    elif args.plugin == "github-actions":
        package_actions.package(ROOT, output)
    elif args.plugin == "github-check":
        package_consumer.package(ROOT, output, Path(os.environ["HARNESS_GATE_BINARY"]))
    elif args.plugin in ("typescript-risk", "http-json-contract"):
        node_package(args.plugin, output, core)
    elif args.plugin == "rust-source-risk":
        rust_package(output, core)
    elif args.plugin == "postgres-service":
        postgres_package(output, core, Path(os.environ["HARNESS_GATE_BINARY"]))
    else:
        rust_measure_package(output, core)
    expected = {row["archive"], row["archive"] + ".sbom.cdx.json"}
    if {path.name for path in output.iterdir()} != expected:
        raise RuntimeError("packaged assets differ from plugin release configuration")


if __name__ == "__main__":
    main()
