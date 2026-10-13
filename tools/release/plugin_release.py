#!/usr/bin/env python3
"""Plugin identities and adapters for the unchanged shared release trust tools."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tomllib

import release_inventory as inventory
import release_policy as policy

ROOT = Path(__file__).resolve().parents[2]


def releases(root: Path = ROOT) -> dict:
    value = json.loads((root / "plugins/releases.json").read_text())
    if value.get("schema") != "gateprobes-plugin-releases/v1":
        raise policy.PolicyError("unknown plugin release schema")
    rows = value.get("plugins")
    if not isinstance(rows, dict) or not rows:
        raise policy.PolicyError("empty plugin release registry")
    prefixes = []
    for name, row in rows.items():
        if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
            raise policy.PolicyError("unsafe plugin name")
        prefix = row["tag_prefix"]
        if not re.fullmatch(r"[a-z][a-z0-9-]*-v", prefix):
            raise policy.PolicyError("unsafe plugin tag prefix")
        prefixes.append(prefix)
        inventory._safe_name(row["archive"].format(version="0.0.0"))
        manifests = row["manifests"]
        if not isinstance(manifests, list) or "plugin.json" not in manifests:
            raise policy.PolicyError("plugin identity manifest is required")
        for manifest in manifests:
            inventory._safe_name(manifest)
    if len(prefixes) != len(set(prefixes)):
        raise policy.PolicyError("duplicate plugin tag prefix")
    return rows


def resolve(plugin: str, root: Path = ROOT) -> dict:
    rows = releases(root)
    if plugin not in rows:
        raise policy.PolicyError(f"plugin has no independent release configuration: {plugin}")
    row = rows[plugin]
    versions = []
    for filename in row["manifests"]:
        path = root / "plugins" / plugin / filename
        if path.suffix == ".toml":
            document = tomllib.loads(path.read_text())["package"]
        else:
            document = json.loads(path.read_text())
        version = document["version"]
        policy.version_from_tag("v" + version)
        versions.append(version)
        if filename == "npm-shrinkwrap.json" and document["packages"][""]["version"] != version:
            raise policy.PolicyError(f"{plugin}: shrinkwrap root version differs")
    if len(set(versions)) != 1:
        raise policy.PolicyError(f"{plugin}: plugin/package/lock versions differ")
    return {"plugin": plugin, "version": versions[0],
            "tag": row["tag_prefix"] + versions[0],
            "archive": row["archive"].format(version=versions[0])}


def resolve_tag(tag: str, root: Path = ROOT) -> dict:
    matches = [name for name, row in releases(root).items()
               if tag.startswith(row["tag_prefix"])]
    if len(matches) != 1:
        raise policy.PolicyError(f"unknown or ambiguous plugin release tag: {tag}")
    row = resolve(matches[0], root)
    if tag != row["tag"]:
        raise policy.PolicyError(f"release tag does not match plugin version: expected {row['tag']}")
    return row


def verify(tag: str, commit: str, repository: str, root: Path = ROOT) -> dict:
    row = resolve_tag(tag, root)
    oid = policy.verify_git_state(root, tag, commit, "refs/remotes/origin/main")
    client = policy.GitHubClient("https://api.github.com", repository, os.environ.get("GH_TOKEN", ""))
    ci = policy.verify_ci_run(client, oid, "main")
    return {"schema_version": policy.SCHEMA_VERSION, **row,
            "repository": repository, "commit": oid,
            "protected_main": {"branch": "main", "ref": "refs/remotes/origin/main"},
            "ci": ci, "status": "pass"}


def generate_inventory(dist: Path, tag: str, commit: str, repository: str,
                       root: Path = ROOT) -> dict:
    """Use the shared inventory schema for a package-only plugin release.

    The shared Core generator requires a bare binary. Plugins distribute an
    archive, so only construction is adapted; all integrity operations use the
    unchanged shared verifier, without mislabelling an archive as a binary.
    """
    row = resolve_tag(tag, root)
    package = row["archive"]
    assets = [inventory._asset(dist, package, "package"),
              inventory._asset(dist, package + ".sbom.cdx.json", "sbom")]
    names = [str(asset["name"]) for asset in assets]
    if {path.name for path in dist.iterdir()} != set(names):
        raise inventory.InventoryError("unlisted or missing package/SBOM before inventory generation")
    checksums = sorted(names + [inventory.INVENTORY_FILE])
    subjects = sorted(checksums + [inventory.CHECKSUM_FILE])
    signatures = sorted(name + suffix for name in subjects for suffix in inventory.SIGNATURE_SUFFIXES)
    value = {"schema_version": inventory.SCHEMA_VERSION, "tag": tag,
             "source": {"repository": repository, "commit": commit},
             "assets": sorted(assets, key=lambda asset: asset["name"]),
             "inventory_file": inventory.INVENTORY_FILE, "checksum_file": inventory.CHECKSUM_FILE,
             "checksum_subjects": checksums, "integrity_subjects": subjects,
             "signature_products": signatures, "upload_set": sorted(subjects + signatures)}
    inventory.expected_upload_names(value)
    inventory._atomic_write_text(dist / inventory.INVENTORY_FILE,
                                 json.dumps(value, indent=2, sort_keys=True) + "\n")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    identity = commands.add_parser("resolve")
    selector = identity.add_mutually_exclusive_group(required=True)
    selector.add_argument("--plugin")
    selector.add_argument("--tag")
    identity.add_argument("--github-output", type=Path)
    for command in ("verify", "inventory"):
        child = commands.add_parser(command)
        child.add_argument("--tag", required=True)
        child.add_argument("--commit", required=True)
        child.add_argument("--repository", required=True)
        if command == "verify":
            child.add_argument("--output", type=Path, required=True)
            child.add_argument("--github-output", type=Path)
        else:
            child.add_argument("--dist", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "resolve":
            value = resolve(args.plugin) if args.plugin else resolve_tag(args.tag)
        elif args.command == "verify":
            value = verify(args.tag, args.commit, args.repository)
            policy._atomic_write_json(args.output, value)
        else:
            value = generate_inventory(args.dist, args.tag, args.commit, args.repository)
        if getattr(args, "github_output", None):
            with args.github_output.open("a") as stream:
                for name in ("plugin", "version", "archive"):
                    stream.write(f"{name}={value[name]}\n")
    except (policy.PolicyError, inventory.InventoryError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"plugin release error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
