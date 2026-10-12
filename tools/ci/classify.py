#!/usr/bin/env python3
"""Classify changed paths into CI tiers and select the subtasks to run.

The workflow always starts and always ends in one fixed aggregate. Unknown
paths, an empty change set or an unresolvable diff resolve to the conservative
full set; a classifier error fails the classify job so the aggregate fails.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

PLUGIN_PREFIXES = {"typescript-risk": "plugins/typescript-risk/"}
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


def changed_paths(base: str, head: str) -> list[str]:
    output = subprocess.check_output(
        ["git", "diff", "--name-only", base, head], text=True, stderr=subprocess.PIPE
    )
    return [line.strip() for line in output.splitlines() if line.strip()]


def classify(paths: list[str]) -> dict:
    classes = {"docs": False, "plugin": False, "shared": False, "unknown": False}
    plugins: set[str] = set()
    for path in paths:
        if path in INPUT_PATHS or path in SHARED_FILES or path.startswith(SHARED_PREFIXES):
            classes["shared"] = True
        elif path in ROOT_DOCUMENTS or (path.startswith("docs/") and path.endswith(DOC_SUFFIXES)):
            classes["docs"] = True
        else:
            match = next(
                (name for name, prefix in PLUGIN_PREFIXES.items() if path.startswith(prefix)),
                None,
            )
            if match is None:
                classes["unknown"] = True
            else:
                classes["plugin"] = True
                plugins.add(match)
    if not paths:
        classes["unknown"] = True
    selection = {
        "run_docs": classes["docs"] or classes["shared"] or classes["unknown"],
        "run_typescript_risk": classes["plugin"] or classes["shared"] or classes["unknown"],
    }
    return {"classes": classes, "plugins": sorted(plugins), "selection": selection}


def render(result: dict, paths: list[str]) -> dict:
    classes = result["classes"]
    selection = result["selection"]
    summary = json.dumps(
        {
            "files": len(paths),
            "classes": classes,
            "plugins": result["plugins"],
            "run": {
                "docs": selection["run_docs"],
                "typescript-risk": selection["run_typescript_risk"],
            },
        },
        sort_keys=True,
    )
    return {
        "docs": str(classes["docs"]).lower(),
        "plugin": str(classes["plugin"]).lower(),
        "shared": str(classes["shared"]).lower(),
        "unknown": str(classes["unknown"]).lower(),
        "run_docs": str(selection["run_docs"]).lower(),
        "run_typescript_risk": str(selection["run_typescript_risk"]).lower(),
        "summary": summary,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--paths", type=Path, help="classify exactly these newline-separated paths")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.paths is not None:
        paths = [line.strip() for line in args.paths.read_text().splitlines() if line.strip()]
    else:
        if not args.base or not args.head or set(args.base) == {"0"}:
            paths = []
        else:
            paths = changed_paths(args.base, args.head)

    result = render(classify(paths), paths)
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
