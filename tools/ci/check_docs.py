#!/usr/bin/env python3
"""Pure-documentation checks: links, declarations and forbidden artifacts.

Uses only the Python standard library, no Rust or Node toolchain and no
network. Executable examples and plugin behavior belong to the plugin tier.
`docs/ownership.json`, protocol schemas and test inputs are inputs: they are
validated here and never treated as ordinary documentation.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRECTORY_NAMES = {".git", "node_modules", "target"}
FORBIDDEN_DIRECTORY_NAMES = {"node_modules", "target", "dist"}
FORBIDDEN_FILE_SUFFIXES = (".tgz", ".tar.gz", ".tar")
LINK = re.compile(r"\]\(([^)\s]+)")
FULL_SHA = re.compile(r"[0-9a-f]{40}")
FULL_DIGEST = re.compile(r"[0-9a-f]{64}")


def walk(root: Path):
    for current, directories, files in os.walk(root):
        directories[:] = sorted(d for d in directories if d not in SKIP_DIRECTORY_NAMES)
        for name in sorted(files):
            yield Path(current) / name


def link_failures(root: Path) -> list[str]:
    failures = []
    for document in walk(root):
        if document.suffix != ".md":
            continue
        text = document.read_text(errors="replace")
        for target in LINK.findall(text):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path = target.split("#", 1)[0]
            if not (document.parent / path).exists():
                failures.append(f"{document.relative_to(root).as_posix()}: broken link {target}")
    return failures


def ownership_failures(root: Path) -> list[str]:
    path = root / "docs" / "ownership.json"
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        return [f"docs/ownership.json: {error}"]
    failures = []
    if value.get("schema") != "gateprobes-ownership/v1":
        failures.append("docs/ownership.json: unknown schema")
    if not FULL_SHA.fullmatch(str(value.get("source_commit", ""))):
        failures.append("docs/ownership.json: source_commit must be a full 40-hex SHA")
    if not value.get("path_map"):
        failures.append("docs/ownership.json: empty path_map")
    contract = value.get("core_contract", {})
    if not FULL_DIGEST.fullmatch(str(contract.get("sha256", ""))):
        failures.append("docs/ownership.json: core_contract.sha256 must be a full digest")
    for field in ("release", "binary", "version"):
        if not contract.get(field):
            failures.append(f"docs/ownership.json: core_contract.{field} is required")
    return failures


def artifact_failures(root: Path) -> list[str]:
    failures = []
    for current, directories, _ in os.walk(root):
        directories[:] = sorted(directories)
        for name in list(directories):
            if name in FORBIDDEN_DIRECTORY_NAMES:
                failures.append((Path(current) / name).relative_to(root).as_posix())
                directories.remove(name)
    for path in walk(root):
        if path.name.endswith(FORBIDDEN_FILE_SUFFIXES):
            failures.append(path.relative_to(root).as_posix())
    return sorted(set(failures))


def plugin_declaration_failures(root: Path) -> list[str]:
    failures = []
    try:
        declared = set(json.loads((root / "docs" / "ownership.json").read_text()).get("plugins", {}))
    except (OSError, json.JSONDecodeError):
        return ["docs/ownership.json: unreadable plugin declarations"]
    for directory in sorted((root / "plugins").iterdir()):
        if not directory.is_dir():
            continue
        if directory.name not in declared:
            failures.append(f"plugins/{directory.name}: not declared in docs/ownership.json")
        manifest = directory / "plugin.json"
        if not manifest.is_file():
            failures.append(f"plugins/{directory.name}: missing plugin.json")
            continue
        try:
            value = json.loads(manifest.read_text())
        except json.JSONDecodeError as error:
            failures.append(f"plugins/{directory.name}/plugin.json: {error}")
            continue
        for field in ("name", "version", "executable"):
            if not value.get(field):
                failures.append(f"plugins/{directory.name}/plugin.json: missing {field}")
    return failures


def registry_failures(root: Path) -> list[str]:
    path = root / "plugins" / "registry.json"
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        return [f"plugins/registry.json: {error}"]
    failures = []
    if value.get("schema") != "gateprobes-plugin-registry/v1":
        failures.append("plugins/registry.json: unknown schema")
    languages = value.get("languages")
    if not isinstance(languages, list) or not languages:
        failures.append("plugins/registry.json: no languages")
        languages = []
    plugins = value.get("plugins")
    if not isinstance(plugins, dict) or not plugins:
        failures.append("plugins/registry.json: no plugins")
        plugins = {}
    for name, row in sorted(plugins.items()):
        if not isinstance(row, dict) or row.get("language") not in languages:
            failures.append(f"plugins/registry.json: {name} has an unknown language")
            continue
        if not (root / str(row.get("path", ""))).is_dir():
            failures.append(f"plugins/registry.json: {name} path is missing")
        entries = row.get("entries", {})
        for key in ("install", "test", "contract", "package"):
            if not entries.get(key):
                failures.append(f"plugins/registry.json: {name} is missing the {key} entry")
        for protocol in row.get("protocols", []):
            if not (root / protocol).is_file():
                failures.append(f"plugins/registry.json: {name} protocol is missing: {protocol}")
    for directory in sorted((root / "plugins").iterdir()):
        if directory.is_dir() and directory.name not in plugins:
            failures.append(f"plugins/{directory.name}: not registered in plugins/registry.json")
    return failures


def check(root: Path = ROOT) -> list[str]:
    return (link_failures(root) + ownership_failures(root)
            + artifact_failures(root) + plugin_declaration_failures(root)
            + registry_failures(root))


def main() -> int:
    failures = check()
    if failures:
        print("documentation checks failed:", file=sys.stderr)
        for failure in failures:
            print("  " + failure, file=sys.stderr)
        return 1
    print("documentation checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
