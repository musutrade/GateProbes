"""Release-package contract for the migrated GitHub result consumer.

These tests exercise tools/release/package_consumer.py on temporary copies of
the plugin directory so the archive shape, SBOM, determinism and rejection
paths are checked without touching the working tree. The extract-and-run
acceptance against the pinned released Core stays in tests/ (accept.py runs
both directories).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/release"))

import package_consumer  # noqa: E402

PRODUCT = "github-check"
MEMBERS = ("github_check.py", "LICENSE", "README.md", "plugin.json")
CORE = Path(os.environ.get("GATEHOUSE_CORE", ""))
STUB_ACCEPT = (
    "import os\n"
    "core = os.environ.get('GATEHOUSE_CORE', '')\n"
    "raise SystemExit(0 if os.path.isfile(core) else 3)\n"
)


class PackageContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CORE.is_file():
            raise AssertionError(f"GATEHOUSE_CORE must name the pinned released binary: {CORE}")
        cls.core = CORE
        cls.temporary = tempfile.TemporaryDirectory(prefix="consumer-package-test-")
        cls.root = Path(cls.temporary.name) / "repo"
        plugin = cls.root / "plugins" / PRODUCT
        plugin.mkdir(parents=True)
        for name in MEMBERS:
            shutil.copy2(ROOT / "plugins" / PRODUCT / name, plugin / name)
        shutil.copy2(ROOT / "plugins" / "releases.json", cls.root / "plugins" / "releases.json")
        (plugin / "accept.py").write_text(STUB_ACCEPT)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def build(self, root: Path | None = None, name: str = "out") -> Path:
        output = Path(tempfile.mkdtemp(prefix=f"consumer-{name}-"))
        self.addCleanup(shutil.rmtree, output, True)
        package_consumer.package(root or self.root, output, self.core)
        return output

    def test_deterministic_archive_sbom_and_member_set(self):
        first = self.build(name="first")
        second = self.build(name="second")
        archive_name = "gateprobes-github-check-1.0.0.tar.gz"
        self.assertEqual(sorted(p.name for p in first.iterdir()),
                         [archive_name, archive_name + ".sbom.cdx.json"])
        data = (first / archive_name).read_bytes()
        self.assertEqual(data, (second / archive_name).read_bytes())
        sbom_bytes = (first / (archive_name + ".sbom.cdx.json")).read_bytes()
        self.assertEqual(sbom_bytes, (second / (archive_name + ".sbom.cdx.json")).read_bytes())
        self.assertEqual(data[4:8], b"\x00\x00\x00\x00", "gzip header must not embed a timestamp")
        prefix = archive_name.removesuffix(".tar.gz")
        expected = {f"{prefix}/{name}": (self.root / "plugins" / PRODUCT / name).read_bytes()
                    for name in MEMBERS}
        with tarfile.open(first / archive_name) as stream:
            members = stream.getmembers()
            self.assertEqual([m.name for m in members], sorted(expected))
            for member in members:
                self.assertEqual(member.mode, 0o644)
                self.assertEqual(member.mtime, 0)
                self.assertEqual(member.uid, 0)
                self.assertEqual(member.gid, 0)
                self.assertEqual(stream.extractfile(member).read(), expected[member.name])
        sbom = json.loads(sbom_bytes)
        self.assertEqual(sbom["metadata"]["component"], {"type": "application", "name": PRODUCT,
                                                         "version": "1.0.0"})
        components = {c["name"]: c["hashes"][0]["content"] for c in sbom["components"]}
        self.assertEqual(components, {name: hashlib.sha256(expected[f"{prefix}/{name}"]).hexdigest()
                                      for name in MEMBERS})

    def test_archive_stays_inside_output_and_excludes_acceptance_files(self):
        output = self.build(name="layout")
        archive = output / "gateprobes-github-check-1.0.0.tar.gz"
        self.assertEqual(archive.parent, output)
        with tarfile.open(archive) as stream:
            names = [m.name for m in stream.getmembers()]
        self.assertFalse(any("accept" in n or "fixtures" in n or "tests" in n for n in names))

    def test_extracted_consumer_runs_from_archive_bytes(self):
        output = self.build(name="extract")
        extract = Path(tempfile.mkdtemp(prefix="consumer-extract-"))
        self.addCleanup(shutil.rmtree, extract, True)
        with tarfile.open(output / "gateprobes-github-check-1.0.0.tar.gz") as stream:
            stream.extractall(extract, filter="data")
        consumer = extract / "gateprobes-github-check-1.0.0" / "github_check.py"
        env = {k: v for k, v in os.environ.items()
               if k not in ("GH_TOKEN", "GITHUB_TOKEN", "GATEHOUSE_CHECK_TOKEN")}
        env["GATEHOUSE_CORE"] = str(self.core.resolve())
        result = subprocess.run([sys.executable, str(consumer), "--help"],
                                capture_output=True, text=True, env=env, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(consumer.read_bytes(), (self.root / "plugins" / PRODUCT / "github_check.py").read_bytes())

    def mutate(self, name: str, transform) -> Path:
        root = Path(tempfile.mkdtemp(prefix="consumer-mutate-"))
        self.addCleanup(shutil.rmtree, root, True)
        shutil.copytree(self.root, root / "repo", symlinks=False)
        manifest = root / "repo" / "plugins" / PRODUCT / name
        transform(manifest)
        return root / "repo"

    def assert_rejected(self, root: Path, message: str):
        output = Path(tempfile.mkdtemp(prefix="consumer-negative-"))
        self.addCleanup(shutil.rmtree, output, True)
        with self.assertRaises(ValueError) as raised:
            package_consumer.package(root, output, self.core)
        self.assertIn(message, str(raised.exception))

    def test_wrong_manifest_identity_is_rejected(self):
        def rewrite(field, value):
            def change(path: Path):
                document = json.loads(path.read_text())
                document[field] = value
                path.write_text(json.dumps(document))
            return change
        for field, value in (("name", "other-consumer"), ("entry", "other.py"),
                             ("authority", "quality-authority")):
            root = self.mutate("plugin.json", rewrite(field, value))
            self.assert_rejected(root, "invalid result consumer identity")

    def test_symlink_and_missing_members_are_rejected(self):
        def link(path: Path):
            path.unlink()
            os.symlink("README.md", path)
        root = self.mutate("github_check.py", link)
        self.assert_rejected(root, "symlink")

        def remove(path: Path):
            path.unlink()
        root = self.mutate("LICENSE", remove)
        self.assert_rejected(root, "not a file")

    def test_symlinked_plugin_directory_is_rejected(self):
        root = self.mutate("plugin.json", lambda path: None)
        plugin = root / "plugins" / PRODUCT
        shutil.rmtree(plugin)
        plugin.symlink_to(ROOT / "plugins" / PRODUCT, target_is_directory=True)
        output = Path(tempfile.mkdtemp(prefix="consumer-negative-"))
        self.addCleanup(shutil.rmtree, output, True)
        self.assert_rejected(root, "symlink")


if __name__ == "__main__":
    unittest.main()
