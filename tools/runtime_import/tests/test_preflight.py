"""Independent byte-level tests for the offline runtime release preflight."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/runtime_import"))

import preflight  # noqa: E402

VERSION = "0.1.1"
SOURCE = "29c619b603ef1656dc5901466385a879806cf104"
ARCHIVE_NAME = f"gateprobes-docker-runtime-{VERSION}-linux-amd64.tar.gz"
PREFIX = ARCHIVE_NAME.removesuffix(".tar.gz")
FILES = {
    "accept.py": b"# acceptance entry\n",
    "Cargo.lock": b"# lock\n",
    "LICENSE": b"# license\n",
    "README.md": b"# readme\n",
    "THIRD_PARTY_NOTICES.txt": b"# notices\n",
    "build-inputs.json": b"{}\n",
    "gateprobes-docker-runtime": b"\x7fELFfixture\n",
    "plugin.json": b'{"name":"docker-runtime","version":"0.1.1","executable":"gateprobes-docker-runtime","protocol":"gate-runtime/v2"}\n',
    "rust-toolchain.toml": b'[toolchain]\nchannel="1.99.1"\n',
}
MODES = {name: (0o755 if name == "gateprobes-docker-runtime" else 0o644) for name in FILES}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tar_bytes(entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as stream:
        for entry in entries:
            name, data, mode = entry[:3]
            kind = entry[3] if len(entry) > 3 else tarfile.REGTYPE
            link = entry[4] if len(entry) > 4 else ""
            info = tarfile.TarInfo(name)
            info.mode, info.mtime, info.uid, info.gid = mode, 0, 0, 0
            info.type, info.linkname = kind, link
            payload = data if kind == tarfile.REGTYPE else b""
            info.size = len(payload)
            stream.addfile(info, io.BytesIO(payload))
    packed = io.BytesIO()
    with gzip.GzipFile(fileobj=packed, mode="wb", filename="", mtime=0) as gz:
        gz.write(raw.getvalue())
    return packed.getvalue()


def archive(entries=None) -> bytes:
    if entries is None:
        entries = [
            (f"{PREFIX}/{name}", data, MODES[name])
            for name, data in sorted(FILES.items())
        ]
    return tar_bytes(entries)


def sbom(components=None) -> bytes:
    if components is None:
        components = [
            {
                "type": "file",
                "name": name,
                "hashes": [{"alg": "SHA-256", "content": sha(data)}],
            }
            for name, data in sorted(FILES.items())
        ]
    value = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "docker-runtime",
                "version": VERSION,
            }
        },
        "components": components,
    }
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def inventory(archive_bytes, sbom_bytes, checksum_subjects=None) -> bytes:
    values = {
        "archive": archive_bytes,
        "sbom": sbom_bytes,
    }
    names = {f"{PREFIX}/{name}": data for name, data in FILES.items()}
    value = {
        "schema_version": 1,
        "source": {
            "repository": "https://github.com/musutrade/GateProbes",
            "commit": SOURCE,
        },
        "tag": f"docker-runtime-v{VERSION}",
        "checksum_file": "SHA256SUMS",
        "inventory_file": "release-inventory.json",
        "checksum_subjects": sorted(
            checksum_subjects
            if checksum_subjects is not None
            else [ARCHIVE_NAME, ARCHIVE_NAME + ".sbom.cdx.json", "release-inventory.json"]
        ),
        "assets": [
            {
                "kind": "package",
                "name": ARCHIVE_NAME,
                "sha256": sha(archive_bytes),
                "size_bytes": len(archive_bytes),
            },
            {
                "kind": "sbom",
                "name": ARCHIVE_NAME + ".sbom.cdx.json",
                "sha256": sha(sbom_bytes),
                "size_bytes": len(sbom_bytes),
            },
        ],
    }
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def checksums(archive_bytes, sbom_bytes, inventory_bytes) -> bytes:
    rows = {
        ARCHIVE_NAME: sha(archive_bytes),
        ARCHIVE_NAME + ".sbom.cdx.json": sha(sbom_bytes),
        "release-inventory.json": sha(inventory_bytes),
    }
    return ("\n".join(f"{value}  {name}" for name, value in sorted(rows.items())) + "\n").encode()


def pin(archive_bytes, sbom_bytes, inventory_bytes, checksum_bytes) -> bytes:
    value = {
        "schema": "gateprobes-runtime-release-pin/v1",
        "repository": "https://github.com/musutrade/GateProbes",
        "tag": f"docker-runtime-v{VERSION}",
        "source_commit": SOURCE,
        "version": VERSION,
        "archive_sha256": sha(archive_bytes),
        "sbom_sha256": sha(sbom_bytes),
        "inventory_sha256": sha(inventory_bytes),
        "checksums_sha256": sha(checksum_bytes),
        "executable_sha256": sha(FILES["gateprobes-docker-runtime"]),
    }
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def valid():
    archive_bytes = archive()
    sbom_bytes = sbom()
    inventory_bytes = inventory(archive_bytes, sbom_bytes)
    checksum_bytes = checksums(archive_bytes, sbom_bytes, inventory_bytes)
    return pin(archive_bytes, sbom_bytes, inventory_bytes, checksum_bytes), archive_bytes, sbom_bytes, inventory_bytes, checksum_bytes


def repin(archive_bytes, sbom_bytes=None, inventory_bytes=None):
    sbom_bytes = sbom() if sbom_bytes is None else sbom_bytes
    inventory_bytes = inventory(archive_bytes, sbom_bytes) if inventory_bytes is None else inventory_bytes
    checksum_bytes = checksums(archive_bytes, sbom_bytes, inventory_bytes)
    return pin(archive_bytes, sbom_bytes, inventory_bytes, checksum_bytes)


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.pin, self.archive, self.sbom, self.inventory, self.checksums = valid()

    def assert_invalid(self, pin_bytes, archive_bytes=None, sbom_bytes=None, inventory_bytes=None, checksum_bytes=None):
        with self.assertRaises(preflight.InvalidRelease):
            preflight.validate(
                pin_bytes,
                self.archive if archive_bytes is None else archive_bytes,
                self.sbom if sbom_bytes is None else sbom_bytes,
                self.inventory if inventory_bytes is None else inventory_bytes,
                self.checksums if checksum_bytes is None else checksum_bytes,
            )

    def test_valid_fixture_returns_exactly_nine_members(self):
        files = preflight.validate(self.pin, self.archive, self.sbom, self.inventory, self.checksums)
        self.assertEqual(set(files), set(FILES))
        self.assertEqual(files, FILES)

    def test_pin_missing_unknown_duplicate_and_identity(self):
        value = json.loads(self.pin)
        missing = dict(value)
        missing.pop("archive_sha256")
        self.assert_invalid(json.dumps(missing).encode())
        unknown = dict(value, unknown="x")
        self.assert_invalid(json.dumps(unknown).encode())
        text = self.pin.decode().rstrip()
        duplicate = text[:-1] + ',"tag":"other"}'
        self.assert_invalid(duplicate.encode())
        for key, replacement in [
            ("source_commit", "a" * 40),
            ("tag", "docker-runtime-v9.9.9"),
            ("repository", "https://example.invalid/repo"),
            ("archive_sha256", "0" * 64),
            ("sbom_sha256", "0" * 64),
            ("inventory_sha256", "0" * 64),
            ("checksums_sha256", "0" * 64),
            ("executable_sha256", "0" * 64),
        ]:
            changed = dict(value)
            changed[key] = replacement
            self.assert_invalid(json.dumps(changed).encode())

    def test_inventory_source_tag_and_asset_mismatch(self):
        value = json.loads(self.inventory)
        for key, replacement in [
            ("source", {"repository": "https://github.com/musutrade/GateProbes", "commit": "b" * 40}),
            ("tag", "docker-runtime-v9.9.9"),
        ]:
            changed = dict(value)
            changed[key] = replacement
            inventory_bytes = json.dumps(changed, sort_keys=True).encode()
            pin_bytes = repin(self.archive, self.sbom, inventory_bytes)
            self.assert_invalid(pin_bytes, inventory_bytes=inventory_bytes)
        changed = json.loads(self.inventory)
        changed["assets"][0]["sha256"] = "0" * 64
        inventory_bytes = json.dumps(changed, sort_keys=True).encode()
        pin_bytes = repin(self.archive, self.sbom, inventory_bytes)
        self.assert_invalid(pin_bytes, inventory_bytes=inventory_bytes)

    def test_tar_link_alias_extra_duplicate_and_oversize(self):
        members = [
            (f"{PREFIX}/{name}", data, MODES[name])
            for name, data in sorted(FILES.items())
        ]
        link = list(members)
        link[0] = (link[0][0], b"", 0o644, tarfile.LNKTYPE, link[1][0])
        alias = list(members)
        alias[0] = (f"{PREFIX}/./{alias[0][0].split('/')[-1]}", alias[0][1], alias[0][2])
        extra = list(members) + [(f"{PREFIX}/extra", b"x", 0o644)]
        duplicate = list(members) + [members[0]]
        for variant in (link, alias, extra, duplicate):
            archive_bytes = archive(variant)
            self.assert_invalid(repin(archive_bytes), archive_bytes=archive_bytes)
        wrong_mode = list(members)
        wrong_mode[0] = (wrong_mode[0][0], wrong_mode[0][1], 0o600)
        archive_bytes = archive(wrong_mode)
        self.assert_invalid(repin(archive_bytes), archive_bytes=archive_bytes)
        oversize = list(members)
        oversize[0] = (oversize[0][0], b"x" * (preflight.MAX_TAR + 1), oversize[0][2])
        archive_bytes = archive(oversize)
        self.assert_invalid(repin(archive_bytes), archive_bytes=archive_bytes)

    def test_truncated_and_corrupt_archive(self):
        truncated = self.archive[:-7]
        self.assert_invalid(repin(truncated), archive_bytes=truncated)
        corrupt = bytearray(self.archive)
        corrupt[len(corrupt) // 2] ^= 0xFF
        corrupt = bytes(corrupt)
        self.assert_invalid(repin(corrupt), archive_bytes=corrupt)

    def test_sbom_missing_swap_and_hash_mismatch(self):
        value = json.loads(self.sbom)
        missing = dict(value)
        missing["components"] = value["components"][1:]
        sbom_bytes = json.dumps(missing, sort_keys=True).encode()
        self.assert_invalid(repin(self.archive, sbom_bytes), sbom_bytes=sbom_bytes)
        swapped = dict(value)
        swapped["components"] = json.loads(json.dumps(value["components"]))
        swapped["components"][0]["name"] = "other"
        sbom_bytes = json.dumps(swapped, sort_keys=True).encode()
        self.assert_invalid(repin(self.archive, sbom_bytes), sbom_bytes=sbom_bytes)
        changed = dict(value)
        changed["components"] = json.loads(json.dumps(value["components"]))
        changed["components"][0]["hashes"][0]["content"] = "0" * 64
        sbom_bytes = json.dumps(changed, sort_keys=True).encode()
        self.assert_invalid(repin(self.archive, sbom_bytes), sbom_bytes=sbom_bytes)

    def test_published_assets_smoke_if_supplied(self):
        assets_dir = os.environ.get("RUNTIME_IMPORT_ASSETS")
        if not assets_dir:
            return
        path = Path(assets_dir)
        archive_bytes = (path / ARCHIVE_NAME).read_bytes()
        sbom_bytes = (path / (ARCHIVE_NAME + ".sbom.cdx.json")).read_bytes()
        inventory_bytes = (path / "release-inventory.json").read_bytes()
        checksum_bytes = (path / "SHA256SUMS").read_bytes()
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as stream:
            binary = stream.extractfile(f"{PREFIX}/gateprobes-docker-runtime").read()
        value = json.loads(pin(archive_bytes, sbom_bytes, inventory_bytes, checksum_bytes))
        value["executable_sha256"] = sha(binary)
        pin_bytes = json.dumps(value, sort_keys=True).encode()
        files = preflight.validate(pin_bytes, archive_bytes, sbom_bytes, inventory_bytes, checksum_bytes)
        self.assertEqual(len(files), 9)


if __name__ == "__main__":
    unittest.main()
