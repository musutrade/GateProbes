"""Real importer0.6 package profile and deterministic bytes."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools/release'))
import package_importer
import verify_importer_archive as verifier


class PodmanPackage(unittest.TestCase):
    def test_real_profile_contains_only_podman_pins_and_exact_manifest(self):
        files = package_importer.members(ROOT, '0.6.0')
        self.assertEqual(set(files), verifier.profile('0.6.0')[1])
        manifest = json.loads(files['plugins/runtime-importer/plugin.json'])
        self.assertEqual(manifest['core_versions'], ['0.13.0'])
        self.assertEqual(manifest['runtime_tag'], 'podman-lifecycle-v0.3.0')
        from importer_core_podman import contract, runtime_contract
        historical = ROOT / 'tools/runtime_import/tests/fixtures/0.5.0'
        self.assertEqual(contract(historical, '0.5.0')['version'], '0.12.0')
        self.assertEqual(runtime_contract(historical, '0.5.0')[0]['tag'], 'podman-lifecycle-v0.2.0')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in package_importer.NAMES:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            shutil.copyfile(historical / 'plugins/runtime-importer/plugin.json', root / 'plugins/runtime-importer/plugin.json')
            shutil.copyfile(historical / 'plugins/runtime-importer/core-pin-podman.json', root / 'plugins/runtime-importer/core-pin-podman.json')
            shutil.copyfile(historical / 'tools/runtime_import/preflight.py', root / 'tools/runtime_import/preflight.py')
            shutil.copyfile(historical / 'tools/runtime_import/release-pin-podman.json', root / 'tools/runtime_import/release-pin-podman.json')
            old = package_importer.members(root, '0.5.0')
            self.assertEqual(set(old), verifier.profile('0.5.0')[1])
        self.assertNotIn('plugins/runtime-importer/core-pin.json', files)
        self.assertNotIn('tools/runtime_import/release-pin.json', files)
        with self.assertRaises(ValueError): package_importer.members(ROOT, '0.1.0')

    def test_real_package_is_deterministic_and_podman_verifies_before_extract(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temporary:
            a, b = Path(temporary)/'a', Path(temporary)/'b'; a.mkdir(); b.mkdir()
            first, second = package_importer.build(ROOT, a), package_importer.build(ROOT, b)
            self.assertEqual(first.name, 'gateprobes-runtime-importer-0.6.0.tar.gz')
            self.assertEqual(first.read_bytes(), second.read_bytes())
            sbom = Path(str(first)+'.sbom.cdx.json').read_bytes()
            self.assertEqual(sbom, Path(str(second)+'.sbom.cdx.json').read_bytes())
            raw = first.read_bytes(); sha = lambda data: hashlib.sha256(data).hexdigest()
            verifier.validate(raw, sbom, sha(raw), sha(sbom), '0.6.0')
            destination = Path(temporary)/'never'
            with self.assertRaises(ValueError):
                verifier.extract(raw, sbom, 'invalid-hash', sha(sbom), destination, '0.6.0')
            self.assertFalse(destination.exists())
