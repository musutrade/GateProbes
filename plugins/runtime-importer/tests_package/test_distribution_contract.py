"""Independent distribution tests for the standalone runtime importer.

The extracted installer is always exercised from archive bytes. Source imports are
limited to the release/package harness; the extracted process runs with -I,
PYTHONPATH empty, and a hostile cwd/PYTHONPATH preflight module.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/release"))
sys.path.insert(0, str(ROOT / "tools/runtime_import"))

import accept_importer  # noqa: E402
import importer_core  # noqa: E402
import package_importer  # noqa: E402
import package_workload  # noqa: E402
import plugin_release  # noqa: E402

CORE = Path(os.environ.get("GATEHOUSE_CORE", ""))
ASSETS = Path(os.environ.get("RUNTIME_IMPORT_ASSETS", ""))
PREFIX = "gateprobes-runtime-importer-0.1.0"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def protected_home() -> tempfile.TemporaryDirectory:
    home = tempfile.TemporaryDirectory(prefix="runtime-importer-test-", dir=Path.home())
    os.chmod(home.name, 0o700)
    return home


class DistributionContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CORE.is_file():
            raise AssertionError(f"GATEHOUSE_CORE must name downloaded Core0.8.0: {CORE}")
        if not ASSETS.is_dir():
            raise AssertionError(f"RUNTIME_IMPORT_ASSETS must name runtime0.1.1 assets: {ASSETS}")
        cls.temporary = tempfile.TemporaryDirectory(prefix="runtime-importer-package-")
        cls.out1 = Path(cls.temporary.name) / "out1"
        cls.out2 = Path(cls.temporary.name) / "out2"
        cls.out1.mkdir()
        cls.out2.mkdir()
        cls.archive = package_importer.build(ROOT, cls.out1)
        cls.archive2 = package_importer.build(ROOT, cls.out2)
        cls.sbom = Path(str(cls.archive) + ".sbom.cdx.json")
        cls.sbom2 = Path(str(cls.archive2) + ".sbom.cdx.json")
        cls.files = package_importer.members(ROOT, "0.1.0")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def extract(self) -> tuple[tempfile.TemporaryDirectory, Path]:
        temporary = tempfile.TemporaryDirectory(prefix="runtime-importer-extract-")
        with tarfile.open(self.archive) as stream:
            stream.extractall(temporary.name, filter="data")
        return temporary, Path(temporary.name) / PREFIX

    def clone_repo(self) -> tuple[tempfile.TemporaryDirectory, Path]:
        temporary = tempfile.TemporaryDirectory(prefix="runtime-importer-source-")
        root = Path(temporary.name) / "repo"
        root.mkdir()
        shutil.copy2(ROOT / "LICENSE", root / "LICENSE")
        shutil.copytree(ROOT / "plugins/runtime-importer", root / "plugins/runtime-importer")
        shutil.copytree(ROOT / "tools/runtime_import", root / "tools/runtime_import")
        return temporary, root

    def install(self, bundle: Path, destination: Path, home: Path, *, extra_env=None, cwd=None):
        pin = home / "runtime-pin.json"
        pin.write_bytes((bundle / "tools/runtime_import/release-pin.json").read_bytes())
        pin.chmod(0o600)
        env = dict(os.environ, PYTHONPATH="", HOME=str(home))
        env.update(extra_env or {})
        return subprocess.run(
            [sys.executable, "-I", "-B", str(bundle / "tools/runtime_import/install.py"),
             "--pin", str(pin), "--assets", str(ASSETS), "--destination", str(destination)],
            cwd=cwd or home, env=env, capture_output=True, text=True, timeout=30)

    def test_manifest_and_pins_are_exact(self):
        identity = plugin_release.resolve("runtime-importer", ROOT)
        self.assertEqual(identity["tag"], "runtime-importer-v0.1.0")
        self.assertEqual(identity["archive"], PREFIX + ".tar.gz")
        manifest = json.loads(self.files["plugins/runtime-importer/plugin.json"])
        self.assertEqual(manifest["version"], "0.1.0")
        self.assertEqual(manifest["core_versions"], ["0.8.0"])
        self.assertEqual(manifest["runtime_tag"], "docker-runtime-v0.1.1")
        pin = importer_core.contract(ROOT)
        self.assertEqual(pin["release"], "v0.8.0")
        self.assertEqual(pin["source_commit"], "1fe08f79a46426027023fb921c9d5fa05d499922")
        self.assertEqual(pin["sha256"], "2b9748bd7ab66d201129922d9e46bfbef1d068fc6a10810666674529ddbd5693")
        runtime = json.loads(self.files["tools/runtime_import/release-pin.json"])
        self.assertEqual(runtime["tag"], "docker-runtime-v0.1.1")
        self.assertEqual(runtime["source_commit"], "29c619b603ef1656dc5901466385a879806cf104")

    def test_archive_layout_modes_and_no_payload(self):
        expected_names = sorted(f"{PREFIX}/{name}" for name in package_importer.NAMES)
        with tarfile.open(self.archive) as stream:
            members = stream.getmembers()
            self.assertEqual([member.name for member in members], expected_names)
            for member in members:
                self.assertTrue(member.isfile())
                self.assertEqual(member.mode, 0o644)
                self.assertEqual(member.mtime, 0)
                self.assertEqual((member.uid, member.gid), (0, 0))
                self.assertFalse(member.issym() or member.islnk() or member.pax_headers)
        self.assertFalse(any("gateprobes-docker-runtime" in name or "harness-gate" in name
                             for name in expected_names))
        self.assertFalse(any("__pycache__" in name or name.endswith(".pyc") for name in expected_names))

    def test_deterministic_archive_and_sbom(self):
        self.assertEqual(self.archive.read_bytes(), self.archive2.read_bytes())
        self.assertEqual(self.sbom.read_bytes(), self.sbom2.read_bytes())

    def test_sbom_identity_components_and_hashes(self):
        value = json.loads(self.sbom.read_text())
        self.assertEqual(value["bomFormat"], "CycloneDX")
        self.assertEqual(value["specVersion"], "1.5")
        self.assertEqual(value["metadata"]["component"],
                         {"type": "application", "name": "runtime-importer", "version": "0.1.0"})
        rows = {row["name"]: row for row in value["components"] if row["type"] == "file"}
        self.assertEqual(set(rows), set(package_importer.NAMES))
        for name, data in self.files.items():
            self.assertEqual(rows[name]["hashes"], [{"alg": "SHA-256", "content": sha(data)}])

    def test_unsafe_source_paths_are_refused(self):
        for path in ("../escape", "/absolute", "plugins/../LICENSE", "plugins/runtime-importer/../core-pin.json"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                package_workload.checked_file(ROOT, path)

    def test_source_member_symlink_and_missing_member_fail(self):
        temporary, root = self.clone_repo()
        self.addCleanup(temporary.cleanup)
        target = root / "LICENSE"
        target.unlink()
        target.symlink_to(root / "plugins/runtime-importer/README.md")
        with self.assertRaises(ValueError):
            package_importer.members(root, "0.1.0")

        temporary2, root2 = self.clone_repo()
        self.addCleanup(temporary2.cleanup)
        (root2 / "plugins/runtime-importer/README.md").unlink()
        with self.assertRaises(ValueError):
            package_importer.members(root2, "0.1.0")

    def test_wrong_manifest_and_core_pin_fail_before_build(self):
        temporary, root = self.clone_repo()
        self.addCleanup(temporary.cleanup)
        manifest = root / "plugins/runtime-importer/plugin.json"
        value = json.loads(manifest.read_text())
        value["version"] = "9.9.9"
        manifest.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            package_importer.members(root, "0.1.0")

        temporary2, root2 = self.clone_repo()
        self.addCleanup(temporary2.cleanup)
        core_pin = root2 / "plugins/runtime-importer/core-pin.json"
        value = json.loads(core_pin.read_text())
        value["sha256"] = "0" * 64
        core_pin.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            package_importer.members(root2, "0.1.0")

    def test_core_pin_fails_before_exec(self):
        temporary = tempfile.TemporaryDirectory(prefix="runtime-importer-core-")
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        (directory / "bin").mkdir()
        (directory / "bin/harness-gate-linux-amd64").write_bytes(b"not the pinned Core")
        with mock.patch.object(importer_core.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                importer_core.verify(directory, ROOT)
            run.assert_not_called()

    def test_extracted_install_modes_and_descriptor(self):
        home = protected_home()
        self.addCleanup(home.cleanup)
        extracted, bundle = self.extract()
        self.addCleanup(extracted.cleanup)
        destination = Path(home.name) / "installation"
        result = self.install(bundle, destination, Path(home.name))
        self.assertEqual(result.returncode, 0, result.stderr)
        descriptor = destination / "installation.json"
        self.assertEqual(result.stdout.strip(), str(descriptor))
        self.assertEqual(result.stderr, "")
        executable = destination / "gateprobes-docker-runtime"
        self.assertEqual(stat.S_IMODE(descriptor.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o500)
        value = json.loads(descriptor.read_text())
        self.assertEqual(value["schema"], "gate-runtime-installation/v1")
        self.assertEqual(value["tag"], "docker-runtime-v0.1.1")
        self.assertEqual(value["executable"]["path"], str(executable))
        self.assertEqual(sha(executable.read_bytes()), value["executable"]["sha256"])
        for member in destination.iterdir():
            self.assertIn(stat.S_IMODE(member.stat().st_mode), (0o400, 0o500))

    def test_extracted_has_no_source_fallback(self):
        home = protected_home()
        self.addCleanup(home.cleanup)
        extracted, bundle = self.extract()
        self.addCleanup(extracted.cleanup)
        malicious = Path(home.name) / "malicious"
        malicious.mkdir()
        marker = malicious / "loaded"
        (malicious / "preflight.py").write_text(
            "from pathlib import Path\nPath(%r).write_text('loaded')\nraise RuntimeError('wrong preflight')\n" % str(marker))
        destination = Path(home.name) / "installation"
        result = self.install(bundle, destination, Path(home.name),
                              extra_env={"PYTHONPATH": str(malicious)}, cwd=malicious)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((destination / "installation.json").is_file())
        self.assertFalse(marker.exists())
        self.assertNotIn(str(ROOT), result.stderr)
        self.assertNotIn(str(ROOT), result.stdout)

    def test_missing_arguments_and_inputs_fail_without_destination(self):
        home = protected_home()
        self.addCleanup(home.cleanup)
        extracted, bundle = self.extract()
        self.addCleanup(extracted.cleanup)
        python = [sys.executable, "-I", "-B", str(bundle / "tools/runtime_import/install.py")]
        no_args = subprocess.run(python, cwd=home.name, env=dict(os.environ, HOME=home.name),
                                 capture_output=True, text=True)
        self.assertNotEqual(no_args.returncode, 0)

        destination = Path(home.name) / "missing-pin-install"
        pin = Path(home.name) / "pin.json"
        pin.write_bytes((bundle / "tools/runtime_import/release-pin.json").read_bytes())
        pin.chmod(0o600)
        missing_pin = subprocess.run(
            [*python, "--pin", str(Path(home.name) / "absent.json"),
             "--assets", str(ASSETS), "--destination", str(destination)],
            cwd=home.name, env=dict(os.environ, HOME=home.name), capture_output=True, text=True)
        self.assertNotEqual(missing_pin.returncode, 0)
        self.assertFalse(destination.exists())

        empty = Path(home.name) / "empty-assets"
        empty.mkdir()
        missing_assets = subprocess.run(
            [*python, "--pin", str(pin), "--assets", str(empty),
             "--destination", str(destination)],
            cwd=home.name, env=dict(os.environ, HOME=home.name), capture_output=True, text=True)
        self.assertNotEqual(missing_assets.returncode, 0)
        self.assertFalse(destination.exists())

    def test_package_end_to_end_with_downloaded_core_and_runtime(self):
        temporary, core_root = self.clone_repo()
        self.addCleanup(temporary.cleanup)
        core_root = Path(temporary.name) / "core"
        core_dir = core_root / "bin"
        core_dir.mkdir(parents=True)
        shutil.copy2(CORE, core_dir / "harness-gate-linux-amd64")
        output = Path(temporary.name) / "package-output"
        output.mkdir()
        package_importer.package(ROOT, output, core_root, ASSETS)
        self.assertEqual({path.name for path in output.iterdir()},
                         {PREFIX + ".tar.gz", PREFIX + ".tar.gz.sbom.cdx.json"})

    def test_extracted_acceptance_cases_and_no_socket_connection(self):
        home = protected_home()
        self.addCleanup(home.cleanup)
        extracted, bundle = self.extract()
        self.addCleanup(extracted.cleanup)
        with mock.patch.dict(os.environ, {"HOME": str(home.name)}):
            result = accept_importer.accept(bundle, CORE, ASSETS)
        self.assertTrue(result["passed"])
        self.assertEqual(result["cases"], 4)
        self.assertEqual(result["core_sha256"], sha(CORE.read_bytes()))
        self.assertEqual(result["scope"], "direct installed path; fake socket only; no zero-spawn claim")

    def test_production_install_import_is_adjacent_only(self):
        text = (ROOT / "tools/runtime_import/install.py").read_text()
        self.assertIn("spec_from_file_location", text)
        self.assertIn('with_name("preflight.py")', text)
        self.assertNotIn("\nimport preflight\n", text)


if __name__ == "__main__":
    unittest.main()
