#!/usr/bin/env python3
"""Verify actual native publication bytes and protection; never modify releases."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import tempfile

import release_inventory as inventory

REPOSITORY = "musutrade/GateProbes"
WORKFLOW = ".github/workflows/native-collector-release.yml"
HISTORICAL_TAG = "rust-collector-v0.1.0-rc.8"


def run(arguments: list[str]) -> str:
    return subprocess.run(arguments, check=True, capture_output=True, text=True,
                          timeout=120).stdout


def api(endpoint: str):
    return json.loads(run(["gh", "api", f"repos/{REPOSITORY}/{endpoint}"]))


def identity(tag: str, commit: str) -> str:
    if not re.fullmatch(r"rust-collector-v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag):
        raise ValueError("invalid native release tag")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("source commit must be a full SHA")
    return f"https://github.com/{REPOSITORY}/{WORKFLOW}@refs/tags/{tag}"


def preflight() -> dict:
    settings = api("immutable-releases")
    if settings.get("enabled") is not True:
        raise ValueError("repository release immutability is not enabled")
    return settings


def check_state(release: dict, tag: str, historical: bool) -> None:
    if release.get("tag_name") != tag or release.get("draft") is not False:
        raise ValueError("release tag/draft state mismatch")
    expected_rc = "-" in tag.removeprefix("rust-collector-v")
    if release.get("prerelease") is not expected_rc:
        raise ValueError("release prerelease state mismatch")
    if historical and tag != HISTORICAL_TAG:
        raise ValueError("historical exception is restricted to original RC8")
    if release.get("immutable") is not True:
        if not historical or release.get("immutable") is not False:
            raise ValueError("published release is not immutable")


def check_assets(release: dict, dist: Path, manifest: dict) -> list[dict]:
    expected = set(inventory.expected_upload_names(manifest))
    assets = release.get("assets", [])
    names = [row["name"] for row in assets]
    if len(names) != len(set(names)) or set(names) != expected:
        raise ValueError("public asset set differs from signed inventory")
    rows = []
    for asset in sorted(assets, key=lambda row: row["name"]):
        name = inventory._safe_name(asset["name"])
        path = inventory._file(dist / name, "downloaded asset")
        digest = inventory.digest(path)
        if asset.get("size") != path.stat().st_size or asset.get("digest") != "sha256:" + digest:
            raise ValueError("public asset size/digest mismatch: " + name)
        rows.append({"name": name, "id": asset["id"], "size": asset["size"], "sha256": digest})
    return rows


def verify(tag: str, commit: str, cosign: str, historical: bool = False) -> dict:
    certificate = identity(tag, commit)
    if historical and tag != HISTORICAL_TAG:
        raise ValueError("historical exception is restricted to original RC8")
    settings = preflight()
    before = api("releases/tags/" + tag)
    check_state(before, tag, historical)
    commands = []
    with tempfile.TemporaryDirectory(prefix="native-public-verification-") as directory:
        dist = Path(directory)
        download = ["gh", "release", "download", tag, "--repo", REPOSITORY, "--dir", directory]
        run(download)
        commands.append({"argv": download, "exit_code": 0})
        manifest = inventory.load(dist / inventory.INVENTORY_FILE)
        if manifest.get("tag") != tag or manifest.get("source") != {
                "repository": "https://github.com/" + REPOSITORY, "commit": commit}:
            raise ValueError("signed inventory source/tag mismatch")
        assets = check_assets(before, dist, manifest)
        subjects = manifest["integrity_subjects"]
        for name in subjects:
            path = str(dist / inventory._safe_name(name))
            signature = [cosign, "verify-blob", "--signature", path + ".sig",
                         "--certificate", path + ".crt", "--certificate-oidc-issuer",
                         "https://token.actions.githubusercontent.com", "--certificate-identity",
                         certificate, path]
            provenance = ["gh", "attestation", "verify", path, "--repo", REPOSITORY,
                          "--cert-identity", certificate, "--source-ref", "refs/tags/" + tag,
                          "--source-digest", commit, "--signer-digest", commit]
            for command in (signature, provenance):
                run(command)
                commands.append({"argv": command, "exit_code": 0})
        inventory.verify(dist, dist / inventory.INVENTORY_FILE, subjects)
        after = api("releases/tags/" + tag)
        check_state(after, tag, historical)
        if after.get("id") != before.get("id") or check_assets(after, dist, manifest) != assets:
            raise ValueError("release changed during verification")
    return {"schema": "gateprobes-native-publication/v1", "verified_at": datetime.now(timezone.utc).isoformat(),
            "repository": REPOSITORY, "tag": tag, "source_commit": commit,
            "release_id": before["id"], "draft": before["draft"], "prerelease": before["prerelease"],
            "immutable": before["immutable"], "immutability_settings": settings,
            "integrity_status": "pass", "protection_status": "complete" if before["immutable"] else "legacy-mutable",
            "certificate_identity": certificate, "signed_and_attested_subjects": len(subjects),
            "assets": assets, "commands": commands}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("preflight", "verify"))
    parser.add_argument("--tag")
    parser.add_argument("--commit")
    parser.add_argument("--cosign", default="cosign")
    parser.add_argument("--historical-rc8", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.operation == "preflight":
            value = {"immutability_settings": preflight(), "status": "pass"}
        else:
            value = verify(args.tag or "", args.commit or "", args.cosign, args.historical_rc8)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError, inventory.InventoryError) as error:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({"status": "fail", "error": str(error)}, indent=2) + "\n")
        print(str(error))
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(value, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
