"""Independent hostile-archive and pre-extraction verifier tests."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys_path = ROOT / "tools/release"
import sys
sys.path.insert(0, str(sys_path))

import package_importer  # noqa: E402
import verify_importer_archive as verifier  # noqa: E402

PREFIX = verifier.PREFIX
NAMES = sorted(verifier.NAMES)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def gzip_bytes(raw: bytes) -> bytes:
    result = io.BytesIO()
    with gzip.GzipFile(fileobj=result, mode="wb", filename="", mtime=0) as zipped:
        zipped.write(raw)
    return result.getvalue()


def tar_bytes(entries) -> bytes:
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w", format=tarfile.USTAR_FORMAT) as stream:
        for entry in entries:
            name, data, mode = entry[:3]
            kind = entry[3] if len(entry) > 3 else tarfile.REGTYPE
            link = entry[4] if len(entry) > 4 else ""
            uid = entry[5] if len(entry) > 5 else 0
            gid = entry[6] if len(entry) > 6 else 0
            mtime = entry[7] if len(entry) > 7 else 0
            member = tarfile.TarInfo(name)
            member.mode, member.uid, member.gid, member.mtime = mode, uid, gid, mtime
            member.type, member.linkname = kind, link
            payload = data if kind == tarfile.REGTYPE else b""
            member.size = len(payload)
            stream.addfile(member, io.BytesIO(payload))
    return result.getvalue()


class VerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="importer-verifier-")
        output = Path(cls.temporary.name) / "out"
        output.mkdir()
        cls.archive_path = package_importer.build(ROOT, output)
        cls.archive = cls.archive_path.read_bytes()
        cls.sbom = Path(str(cls.archive_path) + ".sbom.cdx.json").read_bytes()
        cls.files = verifier.validate(cls.archive, cls.sbom, sha(cls.archive), sha(cls.sbom))
        cls.entries = [(f"{PREFIX}/{name}", cls.files[name], 0o644) for name in NAMES]

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def assert_rejected(self, archive, sbom, destination=None):
        with self.assertRaises((ValueError, tarfile.TarError, OSError)):
            if destination is None:
                verifier.validate(archive, sbom, sha(archive), sha(sbom))
            else:
                verifier.extract(archive, sbom, sha(archive), sha(sbom), destination)

    def test_canonical_package_replay_and_extraction(self):
        destination = Path(self.temporary.name) / "valid-extract"
        bundle = verifier.extract(self.archive, self.sbom, sha(self.archive), sha(self.sbom), destination)
        self.assertEqual(bundle.name, PREFIX)
        for name, data in self.files.items():
            self.assertEqual((bundle / name).read_bytes(), data)
            self.assertEqual((bundle / name).stat().st_mode & 0o777, 0o644)

    def test_digest_mismatches(self):
        with self.assertRaises(ValueError):
            verifier.validate(self.archive, self.sbom, "0" * 64, sha(self.sbom))
        with self.assertRaises(ValueError):
            verifier.validate(self.archive, self.sbom, sha(self.archive), "0" * 64)
        with self.assertRaises(ValueError):
            verifier.validate(self.archive, self.sbom, "not-a-digest", sha(self.sbom))

    def test_compressed_and_raw_size_limits(self):
        self.assert_rejected(b"x" * (verifier.LIMIT + 1), self.sbom)
        self.assert_rejected(gzip_bytes(b"\0" * (verifier.LIMIT + 1)), self.sbom)

    def test_member_set_and_duplicate_negatives(self):
        self.assert_rejected(gzip_bytes(tar_bytes(self.entries + [(f"{PREFIX}/EXTRA", b"x", 0o644)])), self.sbom)
        self.assert_rejected(gzip_bytes(tar_bytes(self.entries[:-1])), self.sbom)
        self.assert_rejected(gzip_bytes(tar_bytes(self.entries + [self.entries[0]])), self.sbom)

    def test_link_path_mode_and_owner_negatives(self):
        variants = [
            (f"{PREFIX}/LICENSE", b"", 0o644, tarfile.SYMTYPE, "README.md"),
            ("/absolute", b"x", 0o644),
            (f"{PREFIX}/../escape", b"x", 0o644),
            (f"{PREFIX}/LICENSE", self.files["LICENSE"], 0o600),
            (f"{PREFIX}/LICENSE", self.files["LICENSE"], 0o644, tarfile.REGTYPE, "", 1),
            (f"{PREFIX}/LICENSE", self.files["LICENSE"], 0o644, tarfile.REGTYPE, "", 0, 0, 1),
        ]
        for index, variant in enumerate(variants):
            entries = list(self.entries)
            relative = variant[0].removeprefix(PREFIX + "/")
            if variant[0].startswith(PREFIX + "/") and relative in NAMES:
                entries[NAMES.index(relative)] = variant
            else:
                entries = [variant, *entries]
            with self.subTest(variant=index):
                self.assert_rejected(gzip_bytes(tar_bytes(entries)), self.sbom)

    def test_hidden_extension_and_raw_trailing_bytes_are_rejected(self):
        raw = tar_bytes(self.entries)
        self.assert_rejected(gzip_bytes(raw + b"hidden"), self.sbom)
        hidden = list(self.entries)
        hidden[0] = (hidden[0][0] + ".backup", hidden[0][1], 0o644)
        self.assert_rejected(gzip_bytes(tar_bytes(hidden)), self.sbom)

    def test_sbom_duplicate_identity_and_component_negatives(self):
        duplicate = self.sbom.replace(
            b'"bomFormat": "CycloneDX"',
            b'"bomFormat": "CycloneDX", "bomFormat": "CycloneDX"',
            1,
        )
        self.assert_rejected(self.archive, duplicate)
        value = json.loads(self.sbom)
        value["metadata"]["component"]["version"] = "9.9.9"
        self.assert_rejected(self.archive, json.dumps(value).encode())
        value = json.loads(self.sbom)
        value["components"].pop()
        self.assert_rejected(self.archive, json.dumps(value).encode())
        value = json.loads(self.sbom)
        value["components"][0]["hashes"][0]["content"] = "0" * 64
        self.assert_rejected(self.archive, json.dumps(value).encode())

    def test_existing_destination_is_not_modified(self):
        destination = Path(self.temporary.name) / "existing"
        destination.mkdir()
        sentinel = destination / "keep"
        sentinel.write_text("keep")
        with self.assertRaises(FileExistsError):
            verifier.extract(self.archive, self.sbom, sha(self.archive), sha(self.sbom), destination)
        self.assertEqual(sentinel.read_text(), "keep")
        self.assertEqual(list(destination.iterdir()), [sentinel])

    def test_refusal_creates_no_destination(self):
        destination = Path(self.temporary.name) / "never-created"
        bad_archive = gzip_bytes(tar_bytes(self.entries + [(f"{PREFIX}/EXTRA", b"x", 0o644)]))
        with self.assertRaises(ValueError):
            verifier.extract(bad_archive, self.sbom, sha(bad_archive), sha(self.sbom), destination)
        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
