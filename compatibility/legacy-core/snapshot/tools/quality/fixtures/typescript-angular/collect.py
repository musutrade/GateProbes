#!/usr/bin/env python3
"""Collect native fixture artifacts. This is not a Harness Gate adapter."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import shutil
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[3]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def inventory(root):
    return {str(p.relative_to(root)): {"sha256": digest(p), "bytes": p.stat().st_size}
            for p in sorted(root.rglob("*")) if p.is_file()}


class Collection:
    def __init__(self, output):
        if output.is_relative_to(ROOT):
            raise ValueError("Output must be outside the fixture source tree")
        self.output = output
        # Refuse reuse: a failed retry must never inherit a successful manifest.
        output.mkdir(parents=True, exist_ok=False)
        self.env = dict(os.environ, CI="true", NG_CLI_ANALYTICS="false",
                        npm_config_cache=str(output / "npm-cache"),
                        CARGO_TARGET_DIR=str(output / "cargo-target"))
        self.manifest = {"schema": "angular-native-fixture/v1", "status": "failed",
                         "scope": "native artifacts only; no adapter certification",
                         "platform": platform.platform(), "commands": [],
                         "environment": {key: self.env[key] for key in
                                         ("CI", "NG_CLI_ANALYTICS", "npm_config_cache",
                                          "CARGO_TARGET_DIR")}}
        self.save()

    def save(self):
        write_json(self.output / "manifest.json", self.manifest)

    def run(self, argv, cwd=ROOT):
        number = len(self.manifest["commands"])
        log = self.output / f"command-{number:02}.log"
        record = {"argv": argv, "cwd": str(cwd.relative_to(REPO)),
                  "log": log.name, "exit_status": None}
        self.manifest["commands"].append(record)
        self.save()
        try:
            with log.open("wb") as stream:
                result = subprocess.run(argv, cwd=cwd, env=self.env, stdout=stream,
                                        stderr=subprocess.STDOUT, timeout=600, check=False)
            record["exit_status"] = result.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            record["error"] = str(error)
            raise
        finally:
            self.save()
        if result.returncode:
            raise RuntimeError(f"command failed ({result.returncode}): {argv}; see {log}")
        return log.read_text()

    def collect(self):
        app = ROOT / "app"
        provider = ROOT / "provider"
        self.manifest["revision"] = self.run(["git", "rev-parse", "HEAD"]).strip()
        self.manifest["working_tree"] = self.run(["git", "status", "--porcelain"]).strip()
        self.manifest["target"] = "reference-app / Rust quote provider"
        self.manifest["runtime"] = {}
        for tool in ("node", "npm", "rustc", "cargo", "python3"):
            self.manifest["runtime"][tool] = self.run([tool, "--version"]).strip()
        package = json.loads((app / "package.json").read_text())
        for tool in ("node", "npm"):
            actual = self.manifest["runtime"][tool].removeprefix("v")
            if actual != package["engines"][tool]:
                raise RuntimeError(f"Expected {tool} {package['engines'][tool]}, got {actual}")
        toolchain = json.loads((ROOT / "toolchain.json").read_text())
        for tool in ("rustc", "cargo"):
            if self.manifest["runtime"][tool] != toolchain[tool]:
                raise RuntimeError(f"Unexpected {tool} runtime; see toolchain.json")
        lock = digest(app / "package-lock.json")
        installs = []
        for index in range(2):
            self.run(["npm", "ci", "--no-audit", "--no-fund"], app)
            installed = app / "node_modules/.package-lock.json"
            shutil.copy2(installed, self.output / f"installed-{index}.json")
            installs.append(digest(installed))
            if digest(app / "package-lock.json") != lock:
                raise RuntimeError("Locked install changed the committed lockfile")
        if installs[0] != installs[1]:
            raise RuntimeError("Repeated locked installs differ")
        self.manifest["locked_install"] = {"runs": 2, "lock_sha256": lock,
                                          "installed_inventory_sha256": installs[0]}
        self.run(["npm", "ls", "--depth=0", "--json"], app)
        generated = inventory(app / "src/app/generated")
        self.run(["npm", "run", "generate:client"], app)
        if not generated or generated != inventory(app / "src/app/generated"):
            raise RuntimeError("Generated client drift; regenerate and review before collection")
        self.run(["cargo", "test", "--locked"], provider)
        self.run(["cargo", "build", "--locked"], provider)
        # Clear outputs before measurement so successful no-op tools cannot reuse them.
        for path in (app / "dist", app / "coverage", app / ".angular"):
            if path.exists():
                shutil.rmtree(path)
        self.run(["npm", "exec", "--", "ng", "build", "--configuration", "production"], app)
        executable = Path(self.env["CARGO_TARGET_DIR"]) / "debug/angular-reference-provider"
        server_record = {"argv": [str(executable)], "cwd": str(provider.relative_to(REPO)),
                         "exit_status": None, "shutdown": "collector terminates after tests"}
        self.manifest["provider"] = server_record
        with (self.output / "provider.stderr.log").open("wb") as stderr:
            server = subprocess.Popen([str(executable)], cwd=provider, env=self.env,
                                      stdout=subprocess.PIPE, stderr=stderr)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(server.stdout, selectors.EVENT_READ)
                    if not selector.select(timeout=10):
                        raise RuntimeError("Provider did not announce its address")
                url = server.stdout.readline().decode().strip()
                (self.output / "provider.stdout.log").write_text(url + "\n")
                self.env["REFERENCE_PROVIDER_URL"] = url
                self.manifest["test_environment"] = {"REFERENCE_PROVIDER_URL": url}
                with urllib.request.urlopen(url + "/openapi.json", timeout=10) as response:
                    served = response.read()
                (self.output / "served-openapi.json").write_bytes(served)
                if served != (provider / "openapi.json").read_bytes():
                    raise RuntimeError("Served OpenAPI differs from generator input")
                self.run(["npm", "exec", "--", "ng", "test", "--watch=false", "--coverage"], app)
                if server.poll() is not None:
                    raise RuntimeError("Provider exited during collection")
            finally:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
                server.stdout.close()
                server_record["exit_status"] = server.returncode
                self.save()
        validate_outputs(app)
        shutil.copytree(app / "dist", self.output / "build")
        shutil.copytree(app / "coverage", self.output / "coverage")
        virtual_files = [p for p in (app / ".angular").rglob("*")
                         if p.is_file() and p.suffix in {".js", ".map"}]
        if not any(p.suffix == ".map" for p in virtual_files):
            raise RuntimeError("Emitted test source maps missing")
        for path in virtual_files:
            destination = self.output / "test-build" / path.relative_to(app / ".angular")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
        # Preserve original bytes, configuration and the collection implementation.
        for path in ROOT.rglob("*"):
            relative = path.relative_to(ROOT)
            if any(part in {"node_modules", ".angular", "dist", "coverage", "target",
                            "evidence", "__pycache__"} for part in relative.parts):
                continue
            if path.is_file():
                destination = self.output / "sources" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, destination)
        self.manifest["configuration_digests"] = {
            str(p.relative_to(ROOT)): digest(p) for p in
            [app / "package.json", app / "package-lock.json", app / "angular.json",
             app / "tsconfig.json", app / "tsconfig.app.json", app / "tsconfig.spec.json",
             app / "vitest.config.ts", ROOT / "toolchain.json",
             app / ".npmrc", app / ".node-version", provider / "Cargo.toml",
             provider / "Cargo.lock", provider / "openapi.json"]}
        # Tool caches and executables are not measurement artifacts.
        for name in ("npm-cache", "cargo-target"):
            shutil.rmtree(self.output / name)
        self.manifest["artifacts"] = {k: v for k, v in inventory(self.output).items()
                                      if k != "manifest.json"}
        self.manifest["status"] = "complete"
        self.save()


def validate_outputs(app):
    maps = list((app / "dist").rglob("*.js.map"))
    if not maps or not any((app / "dist").rglob("index.html")):
        raise RuntimeError("Build output or source maps missing")
    for path in maps:
        data = json.loads(path.read_text())
        if not data.get("sources") or not data.get("sourcesContent") or not data.get("mappings"):
            raise RuntimeError(f"Incomplete source map: {path}")
    reports = list((app / "coverage").rglob("coverage-final.json"))
    if len(reports) != 1:
        raise RuntimeError("Expected one raw Istanbul coverage report")
    coverage = json.loads(reports[0].read_text())
    pricing = [v for k, v in coverage.items() if k.endswith("/pricing.ts")]
    if len(pricing) != 1:
        raise RuntimeError("Pricing source absent or ambiguous in native coverage")
    counters = [n for values in pricing[0]["b"].values() for n in values]
    if not counters or not any(n == 0 for n in counters) or not any(n > 0 for n in counters):
        raise RuntimeError("Expected both tested and untested native branch counters")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    collection = Collection(args.output.resolve())
    try:
        collection.collect()
    except Exception as error:
        collection.manifest["error"] = str(error)
        collection.save()
        print(error, file=sys.stderr)
        return 1
    print(collection.output / "manifest.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
