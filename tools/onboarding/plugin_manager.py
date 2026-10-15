#!/usr/bin/env python3
"""Explicit data-only product preparation, reviewable install, and lock rollback.

Core alone verifies the generic protocol and host-selected signer. This tool
never installs toolchains, executes package scripts, or changes quality policy.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

DOMAIN = b"harness-gate/plugin-manifest/v1\0"
ROOT = Path(__file__).resolve().parents[2]
NAME = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique)


def safe(path):
    path = Path(path).absolute()
    if ".." in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("symbolic link or parent traversal in path: " + str(path))
    return path


def relative(root, name):
    if not name or Path(name).is_absolute() or "\\" in name or ":" in name or any(p in ("..", ".") for p in name.split("/")):
        raise ValueError("unsafe product path: " + name)
    path = safe(root / name)
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError("missing/nonregular product input: " + name)
    return path


def exclusive(path, data):
    path = safe(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def replace(path, data):
    path = safe(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def pins(data):
    lock = decode(data)
    if set(lock) != {"schema", "plugins"} or lock["schema"] != "harness-plugin-lock/v1":
        raise ValueError("unsupported lock schema")
    rows = lock["plugins"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 64:
        raise ValueError("select 1..64 explicit products")
    seen = set()
    for row in rows:
        if not NAME.fullmatch(row["name"]) or not VERSION.fullmatch(row["version"]) or row["name"] in seen:
            raise ValueError("invalid/duplicate exact product pin")
        seen.add(row["name"])
    return rows


def prepare(args):
    root = safe(args.source)
    catalog = decode(relative(root, args.catalog).read_bytes())
    if catalog["schema"] != "gateprobes-products/v1":
        raise ValueError("unsupported product catalog")
    output = safe(args.output)
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    if len(args.product) != len(set(args.product)):
        raise ValueError("select each product once")
    if safe(args.lock_output).exists():
        raise ValueError("lock output already exists; prepare into new paths")
    for name in args.product:
        product = catalog["products"][name]
        version = product["version"]
        if not NAME.fullmatch(name) or not VERSION.fullmatch(version):
            raise ValueError("invalid product identity")
        destination = safe(output / name / version)
        if destination.exists():
            raise ValueError("prepared version already exists; never overwrite: " + str(destination))
        manifest = {k: product[k] for k in (
            "source", "core_versions", "protocol", "platforms", "presets", "programs", "dependencies")}
        manifest.update(schema="harness-plugin/v1", name=name, version=version)
        files = {path: relative(root, path).read_bytes() for path in product["files"]}
        manifest["files"] = {path: digest(data) for path, data in files.items()}
        manifest_bytes = encode(manifest)
        with tempfile.TemporaryDirectory(dir=output) as temporary:
            stage = Path(temporary) / "package"
            stage.mkdir()
            for path, data in files.items():
                target = stage / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            (stage / "plugin.json").write_bytes(manifest_bytes)
            payload = Path(temporary) / "payload"
            payload.write_bytes(DOMAIN + manifest_bytes)
            signature = subprocess.check_output([
                "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(safe(args.signing_key)), "-in", str(payload)])
            if len(signature) != 64:
                raise ValueError("v1 requires an operator-owned Ed25519 key")
            (stage / "plugin.sig").write_bytes(encode({"key_id": args.key_id, "signature": base64.b64encode(signature).decode()}))
            destination.parent.mkdir(parents=True, exist_ok=True)
            stage.rename(destination)
        rows.append({"name": name, "source": product["source"], "version": version,
                     "manifest_sha256": digest(manifest_bytes), "signer": args.key_id})
    exclusive(args.lock_output, encode({"schema": "harness-plugin-lock/v1", "plugins": rows}))


def snapshot(path):
    return base64.b64encode(path.read_bytes()).decode() if path.exists() else None


def lock_target(path):
    path = safe(path)
    if path.name != "plugins.lock.json" or path.parent.name != ".harness-gate":
        raise ValueError("active lock must be PROJECT/.harness-gate/plugins.lock.json")
    return path


def plan(args):
    data = safe(args.lock).read_bytes()
    rows = pins(data)
    active = lock_target(args.active_lock)
    store, prepared = safe(args.store), safe(args.prepared)
    if store == prepared or store.is_relative_to(prepared) or prepared.is_relative_to(store):
        raise ValueError("prepared input and installed store must be separate trees")
    value = {"schema": "gateprobes-install-plan/v1", "active_lock": str(active),
             "store": str(store), "prepared": str(prepared), "previous_lock": snapshot(active),
             "next_lock": base64.b64encode(data).decode(), "next_sha256": digest(data),
             "selection": decode(data),
             "changes": [{**row,
                          "action": "verify-existing" if (store / row["name"] / row["version"]).exists() else "install"}
                         for row in rows]}
    exclusive(args.output, encode(value))
    print(json.dumps(value, indent=2))


def preflight(core, lock, store, trusted_keys):
    command = [str(safe(core)), "--plugin-store", str(store)]
    for key in trusted_keys:
        command += ["--plugin-trusted-key", str(safe(key))]
    command += ["plugins", "--lock", str(lock), "--json"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise ValueError("Core rejected prepared plugins:\n" + result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
    report = decode(result.stdout)
    if report.get("valid") is not True or report.get("diagnostics") != []:
        raise ValueError("Core did not return a valid plugin preflight")


@contextmanager
def operation(active):
    active.parent.mkdir(parents=True, exist_ok=True)
    marker = safe(active.parent / ".plugins.install-lock")
    try:
        marker.mkdir(mode=0o700)
    except FileExistsError as error:
        raise ValueError("another install/rollback holds the project lock; after a crash inspect receipts before explicitly removing " + str(marker)) from error
    try:
        yield
    finally:
        marker.rmdir()


def apply(args):
    value = decode(safe(args.plan).read_bytes())
    with operation(lock_target(value["active_lock"])):
        _apply(args)


def _apply(args):
    value = decode(safe(args.plan).read_bytes())
    if value["schema"] != "gateprobes-install-plan/v1":
        raise ValueError("unsupported install plan")
    active = lock_target(value["active_lock"])
    store, prepared = safe(value["store"]), safe(value["prepared"])
    if store == prepared or store.is_relative_to(prepared) or prepared.is_relative_to(store):
        raise ValueError("prepared input and installed store must be separate trees")
    data = base64.b64decode(value["next_lock"], validate=True)
    rows = pins(data)
    if value.get("selection") != decode(data):
        raise ValueError("reviewed selection differs from next lock")
    expected = [{**row, "action": "verify-existing" if (store / row["name"] / row["version"]).exists() else "install"} for row in rows]
    if value.get("changes") != expected:
        raise ValueError("install changes are stale or differ from reviewed pins")
    if digest(data) != value["next_sha256"] or snapshot(active) != value["previous_lock"]:
        raise ValueError("stale or modified install plan; generate and review a new plan")
    receipt = safe(args.receipt)
    # Receipts contain rollback material before the first installation mutation.
    record = {"schema": "gateprobes-install-receipt/v1", "state": "prepared", "plan": value}
    exclusive(receipt, encode(record))
    with tempfile.TemporaryDirectory() as temporary:
        lock = Path(temporary) / "candidate.json"
        lock.write_bytes(data)
        preflight(args.core, lock, prepared, args.trusted_key)
        store.mkdir(parents=True, exist_ok=True)
        for row in rows:
            target = safe(store / row["name"] / row["version"])
            if target.exists():
                continue  # Core verifies it below; never overwrite an installed identity.
            source = safe(prepared / row["name"] / row["version"])
            target.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=target.parent) as staging:
                package = Path(staging) / "package"
                shutil.copytree(source, package, symlinks=True)
                package.rename(target)
        preflight(args.core, lock, store, args.trusted_key)
    if snapshot(active) != value["previous_lock"]:
        raise ValueError("active lock changed during install; retained receipt and immutable packages, no lock replacement")
    replace(active, data)
    record["state"] = "applied"
    replace(receipt, encode(record))
    print("Installed explicit pins; rollback receipt: " + str(receipt))


def rollback(args):
    record = decode(safe(args.receipt).read_bytes())
    with operation(lock_target(record["plan"]["active_lock"])):
        _rollback(args)


def _rollback(args):
    receipt = safe(args.receipt)
    record = decode(receipt.read_bytes())
    if record["schema"] != "gateprobes-install-receipt/v1" or record["state"] not in ("applied", "prepared"):
        raise ValueError("receipt is not a pending/applied installation")
    value = record["plan"]
    active = lock_target(value["active_lock"])
    # A crash between replacing the lock and marking the receipt is recoverable.
    current = snapshot(active)
    if current == value["next_lock"]:
        if value["previous_lock"] is None:
            active.unlink()
        else:
            replace(active, base64.b64decode(value["previous_lock"], validate=True))
    elif current != value["previous_lock"]:
        raise ValueError("active lock changed since install; refusing to overwrite unrelated work")
    record["state"] = "rolled-back"
    replace(receipt, encode(record))
    print("Restored previous lock; immutable installed packages retained for audit/offline reuse")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    command = actions.add_parser("prepare")
    command.add_argument("--source", type=Path, default=ROOT)
    command.add_argument("--catalog", default="products/onboarding/products.json")
    command.add_argument("--product", action="append", required=True)
    command.add_argument("--signing-key", type=Path, required=True)
    command.add_argument("--key-id", required=True)
    command.add_argument("--output", type=Path, required=True)
    command.add_argument("--lock-output", type=Path, required=True)
    command = actions.add_parser("plan")
    for flag in ("lock", "active-lock", "store", "prepared", "output"):
        command.add_argument("--" + flag, type=Path, required=True)
    command = actions.add_parser("apply")
    for flag in ("plan", "receipt", "core"):
        command.add_argument("--" + flag, type=Path, required=True)
    command.add_argument("--trusted-key", action="append", type=Path, required=True)
    command = actions.add_parser("rollback")
    command.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        {"prepare": prepare, "plan": plan, "apply": apply, "rollback": rollback}[args.action](args)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print("PLUGIN_INSTALL_FAILED: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
