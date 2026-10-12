#!/usr/bin/env python3
"""Classify changed paths into affected plugins and CI tiers.

The workflow always starts and always ends in one fixed aggregate. Renames
classify both the source and target path, so moving plugin source into `docs/`
still runs the plugin checks. Unknown paths, an empty change set or an
unresolvable diff resolve to the conservative full set; a classifier error fails
the classify job so the aggregate fails.

Plugin metadata comes from `plugins/registry.json`: path, language, platforms,
test/package/contract entries and the shared protocols a plugin depends on. New
languages only need a registry entry and their language workflow; this module
never assumes a build method.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REGISTRY = Path("plugins/registry.json")
DOC_SUFFIXES = (".md", ".txt")
ROOT_DOCUMENTS = {
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
}
INPUT_PATHS = {"docs/ownership.json"}
SHARED_PREFIXES = ("tools/", "protocol/", ".github/")
SHARED_FILES = {"LICENSE", "package.json", ".gitignore"}


def load_registry(root: Path) -> dict:
    value = json.loads((root / REGISTRY).read_text())
    if value.get("schema") != "gateprobes-plugin-registry/v1":
        raise ValueError("unknown plugin registry schema")
    languages = value.get("languages")
    if not isinstance(languages, list) or not languages:
        raise ValueError("plugin registry must declare languages")
    plugins = value.get("plugins")
    if not isinstance(plugins, dict) or not plugins:
        raise ValueError("plugin registry must declare plugins")
    for name, row in plugins.items():
        if not isinstance(row, dict) or row.get("language") not in languages:
            raise ValueError(f"plugin {name}: unknown language")
        path = row.get("path")
        if not isinstance(path, str) or not path.startswith("plugins/"):
            raise ValueError(f"plugin {name}: invalid path")
        entries = row.get("entries", {})
        for key in ("install", "test", "contract", "package"):
            if not entries.get(key):
                raise ValueError(f"plugin {name}: missing {key} entry")
        toolchains = row.get("toolchains", [])
        if not isinstance(toolchains, list) or not toolchains:
            raise ValueError(f"plugin {name}: missing toolchains")
        for toolchain in toolchains:
            if toolchain not in languages:
                raise ValueError(f"plugin {name}: unknown toolchain {toolchain}")
        if "rust" in toolchains:
            for key in ("rust_toolchain", "rust_components"):
                if not row.get(key):
                    raise ValueError(f"plugin {name}: missing {key}")
        if row.get("language") == "rust" and not isinstance(row.get("cargo_checks"), bool):
            raise ValueError(f"plugin {name}: cargo_checks must be a boolean")
        for protocol in row.get("protocols", []):
            if not isinstance(protocol, str) or not protocol:
                raise ValueError(f"plugin {name}: invalid protocol")
    return value


def parse_name_status(output: str) -> list[str]:
    """Return both sides of renames and the path of every other change."""
    paths = []
    for line in output.splitlines():
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 2 and parts[1]:
            paths.append(parts[1])
        if len(parts) >= 3 and parts[2]:
            paths.append(parts[2])
    return paths


def changed_paths(base: str, head: str) -> list[str]:
    output = subprocess.check_output(
        ["git", "diff", "--name-status", "--find-renames", base, head],
        text=True,
        stderr=subprocess.PIPE,
    )
    return parse_name_status(output)


def is_document(path: str) -> bool:
    return path in ROOT_DOCUMENTS or (path.startswith("docs/") and path.endswith(DOC_SUFFIXES))


def is_shared(path: str) -> bool:
    return path in INPUT_PATHS or path in SHARED_FILES or path.startswith(SHARED_PREFIXES)


def classify(paths: list[str], registry: dict) -> dict:
    plugins = registry["plugins"]
    by_prefix = {row["path"].rstrip("/") + "/": name for name, row in plugins.items()}
    protocols: dict[str, set[str]] = {}
    for name, row in plugins.items():
        for protocol in row.get("protocols", []):
            protocols.setdefault(protocol, set()).add(name)
    classes = {"docs": False, "plugin": False, "shared": False, "unknown": False}
    affected: set[str] = set()
    for path in paths:
        match = next((name for prefix, name in by_prefix.items() if path.startswith(prefix)), None)
        if match is not None:
            classes["plugin"] = True
            affected.add(match)
        elif is_shared(path):
            classes["shared"] = True
        elif is_document(path):
            classes["docs"] = True
        else:
            classes["unknown"] = True

    if classes["shared"]:
        unregistered = [path for path in paths if is_shared(path) and path not in protocols]
        if unregistered:
            affected.update(plugins)
        else:
            for path in paths:
                affected.update(protocols.get(path, ()))
    if classes["unknown"] or not paths:
        classes["unknown"] = True
        affected.update(plugins)

    matrix = {
        "include": [
            {"plugin": name, "language": plugins[name]["language"], "path": plugins[name]["path"],
             "toolchains": plugins[name]["toolchains"],
             "entries": {key: plugins[name]["entries"][key]
                         for key in ("install", "test", "contract", "package")},
             **{key: plugins[name][key] for key in
                ("rust_toolchain", "rust_components", "cargo_checks", "merges_schemas")
                if key in plugins[name]}}
            for name in sorted(affected)
        ]
    }
    selection = {"run_light": True, "run_plugins": bool(affected)}
    return {"classes": classes, "plugins": sorted(affected), "matrix": matrix, "selection": selection}


def render(result: dict, paths: list[str]) -> dict:
    selection = result["selection"]
    summary = json.dumps({
        "files": len(paths),
        "classes": result["classes"],
        "affected": result["plugins"],
        "languages": sorted({row["language"] for row in result["matrix"]["include"]}),
        "run": {"light": selection["run_light"], "plugins": selection["run_plugins"]},
    }, sort_keys=True, separators=(",", ":"))
    return {
        "docs": str(result["classes"]["docs"]).lower(),
        "plugin": str(result["classes"]["plugin"]).lower(),
        "shared": str(result["classes"]["shared"]).lower(),
        "unknown": str(result["classes"]["unknown"]).lower(),
        "run_light": str(selection["run_light"]).lower(),
        "run_plugins": str(selection["run_plugins"]).lower(),
        "plugins": ",".join(result["plugins"]),
        "matrix": json.dumps(result["matrix"], separators=(",", ":")),
        "summary": summary,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--paths", type=Path, help="classify exactly these newline-separated paths")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    registry = load_registry(args.root)
    if args.paths is not None:
        paths = [line.strip() for line in args.paths.read_text().splitlines() if line.strip()]
    elif not args.base or not args.head or set(args.base) == {"0"}:
        paths = []
    else:
        paths = changed_paths(args.base, args.head)

    result = render(classify(paths, registry), paths)
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(result["summary"])
    if args.github_output:
        with args.github_output.open("a") as handle:
            for key, value in result.items():
                handle.write(f"{key}={value}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
