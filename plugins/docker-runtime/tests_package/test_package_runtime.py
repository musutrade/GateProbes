"""Test-only package identity and archive-normalization checks before builds."""
from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/release"))

import package_runtime  # noqa: E402

MANIFEST = ROOT / "plugins/docker-runtime/plugin.json"


class ManifestIdentity(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(MANIFEST.read_text())

    def test_current_candidate_manifest_is_exact(self):
        package_runtime.validate_manifest(copy.deepcopy(self.manifest), "0.1.1")

    def test_each_identity_or_scope_field_is_strict(self):
        mutations = {
            "schema": "gateprobes-runtime-adapter/v2",
            "name": "other-runtime",
            "version": "0.1.2",
            "executable": "other-native",
            "protocol": "gate-runtime/v1",
            "authority": "measurement-only",
            "platforms": ["linux-x86_64", "linux-aarch64"],
            "core_versions": ["0.7.0", "0.7.1"],
            "status": "stable",
            "capabilities": ["inspect", "remove"],
            "limitations": [],
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(self.manifest)
                changed[field] = value
                with self.assertRaisesRegex(RuntimeError, "manifest identity"):
                    package_runtime.validate_manifest(changed, "0.1.1")

    def test_manifest_version_argument_must_match(self):
        with self.assertRaisesRegex(RuntimeError, "manifest identity"):
            package_runtime.validate_manifest(copy.deepcopy(self.manifest), "0.1.2")


class ReadinessProduct(unittest.TestCase):
    def manifest(self):
        value = json.loads(MANIFEST.read_text())
        value.update(name='docker-readiness', version='0.2.0',
                     executable='gateprobes-docker-readiness', protocol='gate-runtime/v3',
                     core_versions=['0.9.0'], capabilities=['readiness'])
        return value

    def test_explicit_product_and_cross_identity_rejection(self):
        manifest = self.manifest()
        package_runtime.validate_manifest(manifest, '0.2.0', 'docker-readiness')
        for key, value in [('name', 'docker-runtime'), ('protocol', 'gate-runtime/v2'),
                           ('executable', package_runtime.BINARY), ('core_versions', ['0.8.0']),
                           ('capabilities', ['inspect'])]:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                package_runtime.validate_manifest(dict(manifest, **{key: value}), '0.2.0', 'docker-readiness')
        with self.assertRaises(RuntimeError):
            package_runtime.validate_manifest(manifest, '0.2.0')
        with self.assertRaises(RuntimeError):
            package_runtime.product_profile('unknown')
        with self.assertRaises(RuntimeError):
            package_runtime.validate_manifest(dict(manifest, version='0.2.1'), '0.2.1', 'docker-readiness')

    def test_selected_binary_mode_and_deterministic_archive(self):
        binary = 'gateprobes-docker-readiness'
        files = {binary: b'ELF-test-only', 'plugin.json': b'{}'}
        first = package_runtime.archive_bytes('readiness', files, binary)
        self.assertEqual(first, package_runtime.archive_bytes('readiness', dict(reversed(list(files.items()))), binary))
        with tarfile.open(fileobj=io.BytesIO(first), mode='r:gz') as archive:
            self.assertEqual({m.name: m.mode for m in archive.getmembers()},
                             {'readiness/' + binary: 0o755, 'readiness/plugin.json': 0o644})

    def test_current_source_cannot_rebuild_historical_runtime_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RuntimeError, 'Cargo identity mismatch'):
                package_runtime.build(ROOT, Path(temporary))


class PackagePaths(unittest.TestCase):
    def test_member_names_are_normalized_and_deterministic(self):
        files = {
            "README.md": b"readme",
            package_runtime.BINARY: b"\x7fELF\x02\x01",
            "plugin.json": b"{}",
        }
        first = package_runtime.archive_bytes("native-1.0.0", files)
        second = package_runtime.archive_bytes(
            "native-1.0.0", dict(reversed(list(files.items())))
        )
        self.assertEqual(first, second)
        self.assertEqual(first[4:8], b"\x00\x00\x00\x00")
        with tarfile.open(fileobj=io.BytesIO(first), mode="r:gz") as archive:
            members = archive.getmembers()
        self.assertEqual(
            [member.name for member in members],
            [
                "native-1.0.0/README.md",
                "native-1.0.0/gateprobes-docker-runtime",
                "native-1.0.0/plugin.json",
            ],
        )
        for member in members:
            self.assertEqual(member.mtime, 0)
            self.assertEqual(member.uid, 0)
            self.assertEqual(member.gid, 0)
            expected_mode = 0o755 if member.name.endswith(package_runtime.BINARY) else 0o644
            self.assertEqual(member.mode, expected_mode)

    def test_unsafe_member_names_are_rejected(self):
        for name in ("../escape", "/absolute", "a/b", "", ".", ".."):
            with self.subTest(name=name):
                with self.assertRaisesRegex(RuntimeError, "invalid runtime package member"):
                    package_runtime.archive_bytes("native-1.0.0", {name: b"x"})

    def test_symlinked_manifest_is_rejected_before_native_build(self):
        with tempfile.TemporaryDirectory(prefix="runtime-package-test-") as temporary:
            root = Path(temporary)
            plugin = root / "plugins/docker-runtime"
            plugin.mkdir(parents=True)
            (root / "plugins/releases.json").parent.mkdir(parents=True, exist_ok=True)
            (root / "plugins/releases.json").write_text(
                (ROOT / "plugins/releases.json").read_text()
            )
            target = root / "manifest.json"
            target.write_text(MANIFEST.read_text())
            (plugin / "plugin.json").symlink_to(target)
            output = root / "output"
            output.mkdir()
            with self.assertRaisesRegex(ValueError, "symlink"):
                package_runtime.package(root, output, root / "core")


if __name__ == "__main__":
    unittest.main()
