"""Release-package contract for the platform actions distribution.

Determinism, archive layout, SBOM and rejection paths run on temporary copies;
the extraction test proves the shipped archive runs its Node tests without the
source checkout. The registry test entry runs the Node tests directly too.
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

import package_actions  # noqa: E402

ARCHIVE = "gateprobes-github-actions-1.0.0.tar.gz"
SCAFFOLD = ("plugins/releases.json",)
MEMBERS = (
    "LICENSE",
    "README.md",
    "actions/findings-feedback/action.yml",
    "actions/findings-feedback/feedback.cjs",
    "actions/findings-feedback/feedback.test.cjs",
    "actions/report-artifact/action.yml",
    "actions/report-artifact/prepare.cjs",
    "actions/report-artifact/prepare.test.cjs",
    "plugin.json",
)
PLUGIN = "plugins/github-actions"
STRIPPED = ("GH_TOKEN", "GITHUB_TOKEN", "GATEHOUSE_CHECK_TOKEN", "FEEDBACK_TOKEN",
            "ACTIONS_RUNTIME_TOKEN", "NODE_OPTIONS")


def clean_env() -> dict:
    return {key: value for key, value in os.environ.items() if key not in STRIPPED}


@unittest.skipUnless(shutil.which("node"), "Node.js is required for the actions package")
class PackageContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="actions-package-test-")
        cls.root = Path(cls.temporary.name) / "repo"
        for name in MEMBERS:
            target = cls.root / PLUGIN / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / PLUGIN / name, target)
        for name in SCAFFOLD:
            target = cls.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def build(self, root: Path | None = None, name: str = "out") -> Path:
        output = Path(tempfile.mkdtemp(prefix=f"actions-{name}-"))
        self.addCleanup(shutil.rmtree, output, True)
        package_actions.package(root or self.root, output)
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
        expected = {f"{prefix}/{name}": (self.root / PLUGIN / name).read_bytes() for name in MEMBERS}
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
                         {"type": "application", "name": "github-actions", "version": "1.0.0"})
        self.assertEqual({c["name"]: c["hashes"][0]["content"] for c in sbom["components"]},
                         {name: hashlib.sha256(expected[f"{prefix}/{name}"]).hexdigest()
                          for name in MEMBERS})

    def test_extracted_archive_runs_node_tests_without_source_checkout(self):
        output = self.build(name="verified")
        extract = Path(tempfile.mkdtemp(prefix="actions-extract-"))
        self.addCleanup(shutil.rmtree, extract, True)
        with tarfile.open(output / ARCHIVE) as stream:
            stream.extractall(extract, filter="data")
        bundle = extract / ARCHIVE.removesuffix(".tar.gz")
        result = subprocess.run(
            ["node", "--test", "actions/findings-feedback/feedback.test.cjs",
             "actions/report-artifact/prepare.test.cjs"],
            cwd=bundle, capture_output=True, text=True, env=clean_env(), check=False)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        self.assertIn("pass", result.stdout)

    def test_identity_and_member_negatives_are_rejected(self):
        def mutate(name: str, transform) -> Path:
            root = Path(tempfile.mkdtemp(prefix="actions-mutate-"))
            self.addCleanup(shutil.rmtree, root, True)
            shutil.copytree(self.root, root / "repo")
            transform(root / "repo" / PLUGIN / name)
            return root / "repo"

        def reject(root: Path, message: str):
            output = Path(tempfile.mkdtemp(prefix="actions-negative-"))
            self.addCleanup(shutil.rmtree, output, True)
            with self.assertRaises(ValueError) as raised:
                package_actions.package(root, output)
            self.assertIn(message, str(raised.exception))

        def patch_manifest(key: str, value):
            def mutate(path: Path):
                manifest = json.loads(path.read_text())
                manifest[key] = value
                path.write_text(json.dumps(manifest))
            return mutate

        reject(mutate("plugin.json", patch_manifest("schema", "other/v1")),
               "invalid platform action identity")
        reject(mutate("plugin.json", patch_manifest("name", "other")),
               "invalid platform action identity")
        reject(mutate("plugin.json", patch_manifest("authority", "quality-enforcement")),
               "invalid platform action identity")

        def corrupt(path: Path):
            path.write_text("{not json")
        reject(mutate("plugin.json", corrupt), "Expecting property name")

        def remove(path: Path):
            path.unlink()
        reject(mutate("actions/report-artifact/prepare.cjs", remove), "not a file")

        def link(path: Path):
            path.unlink()
            os.symlink("action.yml", path)
        reject(mutate("actions/report-artifact/prepare.test.cjs", link), "symlink")


if __name__ == "__main__":
    unittest.main()
