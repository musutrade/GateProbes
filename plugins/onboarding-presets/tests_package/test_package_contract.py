"""Release-package contract for the onboarding preset distribution.

Determinism, archive layout, SBOM and rejection paths run on temporary copies
with a stub acceptance script (fast). One real extracted-bundle acceptance
proves the shipped archive is source-independent. The registry contract step
runs the real 29-step acceptance separately.
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

import package_onboarding  # noqa: E402

CORE = Path(os.environ.get("GATEHOUSE_CORE", ""))
ARCHIVE = "gateprobes-onboarding-presets-1.0.8.tar.gz"
SCAFFOLD = ("plugins/releases.json",)
MEMBERS = (
    "LICENSE",
    "plugins/onboarding-presets/README.md",
    "plugins/onboarding-presets/plugin.json",
    "products/onboarding/presets/python/catalog.json",
    "products/onboarding/presets/python/flow.toml",
    "products/onboarding/presets/rust/catalog.json",
    "products/onboarding/presets/rust/flow.toml",
    "products/onboarding/products.json",
    "tools/onboarding/acceptance.py",
    "tools/onboarding/plugin_manager.py",
)
STUB_ACCEPT = (
    "import pathlib, sys\n"
    "argv = sys.argv[1:]\n"
    "core = pathlib.Path(argv[argv.index('--core') + 1])\n"
    "raise SystemExit(0 if core.is_file() else 3)\n"
)


class PackageContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CORE.is_file():
            raise AssertionError(f"GATEHOUSE_CORE must name the pinned released binary: {CORE}")
        cls.core = CORE
        cls.temporary = tempfile.TemporaryDirectory(prefix="onboarding-package-test-")
        cls.root = Path(cls.temporary.name) / "repo"
        for name in MEMBERS + SCAFFOLD:
            target = cls.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
        (cls.root / "tools/onboarding/acceptance.py").write_text(STUB_ACCEPT)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def build(self, root: Path | None = None, name: str = "out") -> Path:
        output = Path(tempfile.mkdtemp(prefix=f"onboarding-{name}-"))
        self.addCleanup(shutil.rmtree, output, True)
        package_onboarding.package(root or self.root, output, self.core)
        return output

    def test_deterministic_archive_sbom_and_member_layout(self):
        first = self.build(name="first")
        second = self.build(name="second")
        self.assertEqual(sorted(p.name for p in first.iterdir()),
                         [ARCHIVE, ARCHIVE + ".sbom.cdx.json"])
        data = (first / ARCHIVE).read_bytes()
        self.assertEqual(data, (second / ARCHIVE).read_bytes())
        self.assertEqual((first / (ARCHIVE + ".sbom.cdx.json")).read_bytes(),
                         (second / (ARCHIVE + ".sbom.cdx.json")).read_bytes())
        self.assertEqual(data[4:8], b"\x00\x00\x00\x00", "gzip header must not embed a timestamp")
        prefix = ARCHIVE.removesuffix(".tar.gz")
        expected = {f"{prefix}/{name}": (self.root / name).read_bytes() for name in MEMBERS}
        with tarfile.open(first / ARCHIVE) as stream:
            members = stream.getmembers()
            self.assertEqual([m.name for m in members], sorted(expected))
            for member in members:
                self.assertEqual(member.mode, 0o644)
                self.assertEqual(member.mtime, 0)
                self.assertEqual(member.uid, 0)
                self.assertEqual(member.gid, 0)
                self.assertTrue(member.isfile())
                self.assertEqual(stream.extractfile(member).read(), expected[member.name])
        sbom = json.loads((first / (ARCHIVE + ".sbom.cdx.json")).read_bytes())
        self.assertEqual(sbom["metadata"]["component"],
                         {"type": "application", "name": "onboarding-presets", "version": "1.0.8"})
        self.assertEqual({c["name"]: c["hashes"][0]["content"] for c in sbom["components"]},
                         {name: hashlib.sha256(expected[f"{prefix}/{name}"]).hexdigest()
                          for name in MEMBERS})

    def mutate(self, name: str, transform) -> Path:
        root = Path(tempfile.mkdtemp(prefix="onboarding-mutate-"))
        self.addCleanup(shutil.rmtree, root, True)
        shutil.copytree(self.root, root / "repo")
        transform(root / "repo" / name)
        return root / "repo"

    def assert_rejected(self, root: Path, message: str):
        output = Path(tempfile.mkdtemp(prefix="onboarding-negative-"))
        self.addCleanup(shutil.rmtree, output, True)
        with self.assertRaises(ValueError) as raised:
            package_onboarding.package(root, output, self.core)
        self.assertIn(message, str(raised.exception))

    def test_product_and_member_mismatches_are_rejected(self):
        catalog = "products/onboarding/products.json"

        def bump(path: Path):
            document = json.loads(path.read_text())
            document["products"]["rust-minimal"]["version"] = "999.0.0"
            path.write_text(json.dumps(document))
        self.assert_rejected(self.mutate(catalog, bump), "versions differ")

        def rename(path: Path):
            document = json.loads(path.read_text())
            document["products"]["python-minimal"] = document["products"].pop("python-minimal")
            document["products"]["go-minimal"] = document["products"].pop("python-minimal")
            path.write_text(json.dumps(document))
        self.assert_rejected(self.mutate(catalog, rename), "unexpected onboarding products")

        def swap_files(path: Path):
            document = json.loads(path.read_text())
            document["products"]["rust-minimal"]["files"] = [
                "products/onboarding/presets/rust/catalog.json",
                "products/onboarding/presets/rust/README.md",
            ]
            path.write_text(json.dumps(document))
        self.assert_rejected(self.mutate(catalog, swap_files), "unexpected onboarding product members")

        def corrupt(path: Path):
            path.write_text("{not json")
        self.assert_rejected(self.mutate(catalog, corrupt), "Expecting property name")

    def test_symlink_and_missing_members_are_rejected(self):
        flow = "products/onboarding/presets/rust/flow.toml"

        def link(path: Path):
            path.unlink()
            os.symlink("catalog.json", path)
        self.assert_rejected(self.mutate(flow, link), "symlink")

        def remove(path: Path):
            path.unlink()
        self.assert_rejected(self.mutate("tools/onboarding/plugin_manager.py", remove), "not a file")

    def test_extracted_bundle_acceptance_is_source_independent(self):
        root = Path(tempfile.mkdtemp(prefix="onboarding-real-"))
        self.addCleanup(shutil.rmtree, root, True)
        for name in MEMBERS + SCAFFOLD:
            target = root / "repo" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
        output = self.build(root / "repo", name="real")
        extract = Path(tempfile.mkdtemp(prefix="onboarding-extract-"))
        self.addCleanup(shutil.rmtree, extract, True)
        with tarfile.open(output / ARCHIVE) as stream:
            stream.extractall(extract, filter="data")
            self.assertTrue(all(m.isfile() for m in stream.getmembers()))
        bundle = extract / ARCHIVE.removesuffix(".tar.gz")
        work = extract / "acceptance"
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        result = subprocess.run(
            [sys.executable, str(bundle / "tools/onboarding/acceptance.py"),
             "--core", str(self.core.resolve()), "--work-dir", str(work)],
            cwd=bundle, capture_output=True, text=True, env=env, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        self.assertIn("PASS: 29 real steps", result.stdout)
        report = json.loads((work / "report.json").read_text())
        self.assertTrue(report["passed"])
        self.assertEqual(len(report["steps"]), 29)
        self.assertEqual(report["core_sha256"], hashlib.sha256(self.core.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
