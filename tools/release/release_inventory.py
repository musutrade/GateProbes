#!/usr/bin/env python3
"""Generate and verify the exact subject set for a Harness-Gate release.

The workflow deliberately calls this module for every integrity operation.  A
directory listing is never treated as an implicit release contract: the
inventory names each binary, the CycloneDX SBOM, the checksum manifest, and
the signature/certificate products that may be uploaded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Iterable


SCHEMA_VERSION = 1
CHECKSUM_FILE = "SHA256SUMS"
INVENTORY_FILE = "release-inventory.json"
SIGNATURE_SUFFIXES = (".sig", ".crt")


class InventoryError(RuntimeError):
    """A fail-closed inventory or verification error."""


def _safe_name(value: str) -> str:
    path = Path(value)
    if not value or path.is_absolute() or "/" in value or "\\" in value or "\x00" in value:
        raise InventoryError(f"asset path must be a simple relative name: {value!r}")
    if any(part in ("", ".", "..") for part in path.parts):
        raise InventoryError(f"asset path must not contain traversal: {value!r}")
    return value


def _file(path: Path, label: str) -> Path:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise InventoryError(f"missing {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise InventoryError(f"{label} is not a regular file: {path}")
    return path


def _atomic_write_text(path: Path, text: str) -> None:
    """Publish generated metadata without exposing a partially written file."""

    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _asset(dist: Path, name: str, kind: str) -> dict[str, object]:
    name = _safe_name(name)
    path = _file(dist / name, kind)
    return {
        "name": name,
        "kind": kind,
        "size_bytes": path.stat().st_size,
        "sha256": digest(path),
    }


def _names(inventory: dict[str, object], key: str) -> list[str]:
    value = inventory.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise InventoryError(f"inventory field {key!r} must be a string array")
    return list(value)


def _asset_names(inventory: dict[str, object]) -> list[str]:
    assets = inventory.get("assets")
    if not isinstance(assets, list):
        raise InventoryError("inventory assets must be an array")
    names: list[str] = []
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            raise InventoryError("inventory contains an invalid asset")
        if asset.get("kind") not in {"binary", "sbom", "package"}:
            raise InventoryError("inventory asset kind must be binary, sbom or package")
        size = asset.get("size_bytes")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise InventoryError("inventory asset size_bytes must be a non-negative integer")
        checksum = asset.get("sha256")
        if not isinstance(checksum, str) or re.fullmatch(r"[0-9a-fA-F]{64}", checksum) is None:
            raise InventoryError("inventory asset sha256 must be 64 hexadecimal characters")
        names.append(_safe_name(asset["name"]))
    if len(names) != len(set(names)):
        raise InventoryError("inventory contains duplicate asset names")
    return names


def expected_upload_names(inventory: dict[str, object]) -> list[str]:
    """Return the complete, deterministic file set allowed in a release."""

    assets = _asset_names(inventory)
    checksum_subjects = [_safe_name(name) for name in _names(inventory, "checksum_subjects")]
    integrity = [_safe_name(name) for name in _names(inventory, "integrity_subjects")]
    signatures = [_safe_name(name) for name in _names(inventory, "signature_products")]
    upload = [_safe_name(name) for name in _names(inventory, "upload_set")]
    inventory_name = inventory.get("inventory_file")
    if not isinstance(inventory_name, str):
        raise InventoryError("inventory_file must be a string")
    inventory_name = _safe_name(inventory_name)
    if inventory.get("checksum_file") != CHECKSUM_FILE:
        raise InventoryError("checksum_file must be SHA256SUMS")
    expected_checksum = sorted(set(assets + [_safe_name(inventory_name)]))
    if sorted(checksum_subjects) != expected_checksum:
        raise InventoryError("checksum_subjects must equal primary assets plus inventory")
    expected_integrity = sorted(set(checksum_subjects + [CHECKSUM_FILE]))
    if sorted(integrity) != expected_integrity:
        raise InventoryError("integrity_subjects must equal checksum subjects plus SHA256SUMS")
    expected_signatures = sorted(
        f"{name}{suffix}" for name in integrity for suffix in SIGNATURE_SUFFIXES
    )
    if sorted(signatures) != expected_signatures:
        raise InventoryError("signature_products do not cover every integrity subject")
    expected_upload = sorted(set(integrity + signatures))
    if sorted(upload) != expected_upload:
        raise InventoryError("upload_set does not equal integrity and signature products")
    return expected_upload


def generate(
    dist: Path,
    output: Path,
    binaries: Iterable[str],
    sbom: str | Iterable[str],
    tag: str,
    commit: str,
    repository: str,
    packages: Iterable[str] = (),
) -> dict[str, object]:
    binary_names = sorted({_safe_name(name) for name in binaries})
    if not binary_names:
        raise InventoryError("at least one platform binary is required")
    sbom_names = sorted({_safe_name(name) for name in ([sbom] if isinstance(sbom, str) else sbom)})
    if not sbom_names:
        raise InventoryError("at least one SBOM is required")
    assets = [_asset(dist, name, "binary") for name in binary_names]
    assets.extend(_asset(dist, name, "sbom") for name in sbom_names)
    assets.extend(_asset(dist, name, "package") for name in sorted(packages))
    inventory_name = _safe_name(output.name)
    if output.parent.resolve() != dist.resolve():
        raise InventoryError("inventory output must be directly inside dist")
    # The inventory is itself an integrity subject.  Write its stable content
    # first, then checksum/sign it along with the binaries and SBOM.
    inventory: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "tag": tag,
        "source": {
            "repository": repository,
            "commit": commit,
        },
        "assets": sorted(assets, key=lambda item: str(item["name"])),
        "inventory_file": inventory_name,
        "checksum_file": CHECKSUM_FILE,
    }
    primary_names = [str(item["name"]) for item in inventory["assets"]]
    checksum_subjects = sorted(set(primary_names + [inventory_name]))
    integrity_subjects = sorted(set(checksum_subjects + [CHECKSUM_FILE]))
    signature_products = sorted(
        f"{name}{suffix}"
        for name in integrity_subjects
        for suffix in SIGNATURE_SUFFIXES
    )
    inventory["integrity_subjects"] = integrity_subjects
    inventory["checksum_subjects"] = checksum_subjects
    inventory["signature_products"] = signature_products
    inventory["upload_set"] = sorted(set(integrity_subjects + signature_products))
    _atomic_write_text(output, json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    return inventory


def load(path: Path) -> dict[str, object]:
    try:
        _file(path, "inventory")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InventoryError(f"cannot read inventory {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise InventoryError("unsupported or malformed inventory schema")
    expected_upload_names(value)
    if value.get("inventory_file") != path.name:
        raise InventoryError("inventory_file does not match the inventory path")
    return value


def write_checksums(dist: Path, inventory: dict[str, object]) -> None:
    subjects = _names(inventory, "checksum_subjects")
    lines = []
    for name in subjects:
        path = _file(dist / name, "integrity subject")
        lines.append(f"{digest(path)}  {name}")
    target = dist / CHECKSUM_FILE
    _atomic_write_text(target, "\n".join(lines) + "\n")


def read_checksums(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise InventoryError(f"cannot read checksum manifest {path}: {exc}") from exc
    values: dict[str, str] = {}
    for line in lines:
        parts = line.split("  ", 1)
        if len(parts) != 2 or re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]) is None:
            raise InventoryError(f"malformed checksum line: {line!r}")
        name = _safe_name(parts[1])
        if name in values:
            raise InventoryError(f"duplicate checksum entry: {name}")
        values[name] = parts[0].lower()
    return values


def verify(
    dist: Path,
    inventory_path: Path,
    attested: Iterable[str] = (),
) -> None:
    if inventory_path.parent.resolve() != dist.resolve():
        raise InventoryError("inventory must be directly inside the release dist")
    inventory = load(inventory_path)
    if inventory.get("inventory_file") != inventory_path.name:
        raise InventoryError("inventory path does not match inventory_file")
    assets = inventory.get("assets", [])
    if not isinstance(assets, list):  # validated by _asset_names, retained for type narrowing
        raise InventoryError("inventory assets must be an array")
    for asset in assets:
        if not isinstance(asset, dict):
            raise InventoryError("inventory contains an invalid asset")
        name = _safe_name(str(asset["name"]))
        path = _file(dist / name, "declared asset")
        declared_size = asset["size_bytes"]
        declared_hash = str(asset["sha256"]).lower()
        if path.stat().st_size != declared_size or digest(path) != declared_hash:
            raise InventoryError(f"modified asset or asset declaration mismatch: {name}")
    expected = set(expected_upload_names(inventory))
    actual = {path.name for path in dist.iterdir()}
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details = []
        if missing:
            details.append(f"missing: {', '.join(missing)}")
        if extra:
            details.append(f"extra/unlisted: {', '.join(extra)}")
        raise InventoryError("release upload set mismatch (" + "; ".join(details) + ")")

    checksums = read_checksums(_file(dist / CHECKSUM_FILE, "checksum manifest"))
    checksum_subjects = {
        _safe_name(name) for name in _names(inventory, "checksum_subjects")
    }
    if set(checksums) != checksum_subjects:
        raise InventoryError("checksum subject set differs from inventory")
    for name, expected_hash in checksums.items():
        actual_hash = digest(_file(dist / name, "checksum subject"))
        if actual_hash != expected_hash:
            raise InventoryError(f"modified asset or checksum mismatch: {name}")

    integrity = {_safe_name(name) for name in _names(inventory, "integrity_subjects")}
    for name in integrity:
        for suffix in SIGNATURE_SUFFIXES:
            _file(dist / f"{name}{suffix}", "signature/certificate")

    attested_set = {_safe_name(name) for name in attested}
    if attested_set != integrity:
        missing = sorted(integrity - attested_set)
        extra = sorted(attested_set - integrity)
        details = []
        if missing:
            details.append(f"unattested: {', '.join(missing)}")
        if extra:
            details.append(f"unlisted attestation: {', '.join(extra)}")
        raise InventoryError("attestation subject set mismatch (" + "; ".join(details) + ")")


def list_operation(inventory: dict[str, object], operation: str) -> list[str]:
    if operation == "checksum":
        return _names(inventory, "checksum_subjects")
    if operation in {"sign", "attest"}:
        return _names(inventory, "integrity_subjects")
    if operation == "upload":
        return _names(inventory, "upload_set")
    raise InventoryError(f"unknown inventory operation: {operation}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser("generate")
    generate_parser.add_argument("--dist", type=Path, required=True)
    generate_parser.add_argument("--output", type=Path, required=True)
    generate_parser.add_argument("--package", action="append", default=[])
    generate_parser.add_argument("--binary", action="append", required=True)
    generate_parser.add_argument("--sbom", action="append", required=True)
    generate_parser.add_argument("--tag", default="")
    generate_parser.add_argument("--commit", default="")
    generate_parser.add_argument("--repository", default="")

    checksums_parser = subparsers.add_parser("checksums")
    checksums_parser.add_argument("--dist", type=Path, required=True)
    checksums_parser.add_argument("--inventory", type=Path, required=True)

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--inventory", type=Path, required=True)
    list_parser.add_argument("--operation", choices=["checksum", "sign", "attest", "upload"], required=True)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--dist", type=Path, required=True)
    verify_parser.add_argument("--inventory", type=Path, required=True)
    verify_parser.add_argument("--attested", action="append", default=[])

    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            inventory = generate(
                args.dist,
                args.output,
                args.binary,
                args.sbom,
                args.tag,
                args.commit,
                args.repository,
                args.package,
            )
            expected_upload_names(inventory)
        elif args.command == "checksums":
            write_checksums(args.dist, load(args.inventory))
        elif args.command == "list":
            for name in list_operation(load(args.inventory), args.operation):
                print(name)
        elif args.command == "verify":
            verify(args.dist, args.inventory, args.attested)
        else:  # pragma: no cover - argparse enforces commands
            raise InventoryError("missing inventory command")
    except InventoryError as exc:
        print(f"release inventory error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
