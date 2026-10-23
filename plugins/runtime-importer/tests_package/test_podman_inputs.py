"""Trusted versioned importer0.5 inputs; no unverified executable may run."""
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools/release'))
import importer_core_podman


class PodmanInputs(unittest.TestCase):
    def test_exact_published_pins_select_podman_without_changing_v1(self):
        core = importer_core_podman.contract(ROOT)
        runtime, _ = importer_core_podman.runtime_contract(ROOT)
        self.assertEqual(core['version'], '0.12.0')
        self.assertEqual(core['source_commit'], '84a306e8f35674b79aaafa0a0fecd05d6087ac24')
        self.assertEqual(runtime['tag'], 'podman-lifecycle-v0.2.0')
        self.assertEqual(runtime['source_commit'], 'e376df9a8021f9351525da630c5e3bb1ad83c767')
        self.assertEqual(runtime['archive_sha256'], 'e3112a8dffb289a5e88de9aed8c1f6bfc3eae91169a1bbd45d05db63a22e1874')
        old = json.loads((ROOT / 'tools/runtime_import/release-pin.json').read_text())
        self.assertEqual(old['tag'], 'docker-runtime-v0.1.1')

    def test_v2_pin_cannot_select_podman_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / 'tools/runtime_import'; directory.mkdir(parents=True)
            shutil.copyfile(ROOT / 'tools/runtime_import/preflight.py', directory / 'preflight.py')
            shutil.copyfile(ROOT / 'tools/runtime_import/release-pin.json', directory / 'release-pin-podman.json')
            with self.assertRaises(ValueError): importer_core_podman.runtime_contract(root)

    def test_wrong_download_digest_never_executes(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(importer_core_podman.urllib.request, 'urlopen', return_value=io.BytesIO(b'untrusted')), mock.patch.object(importer_core_podman.subprocess, 'run') as run:
            output = Path(temporary) / 'core'
            with self.assertRaises(ValueError): importer_core_podman.prepare(output, ROOT)
            run.assert_not_called()
            self.assertFalse((output / 'contract.json').exists())

    def test_wrong_readiness_download_fails_without_completed_contract(self):
        import hashlib
        payload = b'fixture-core'
        pin = dict(importer_core_podman.EXPECTED, sha256=hashlib.sha256(payload).hexdigest())
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(importer_core_podman, 'contract', return_value=pin), mock.patch.object(importer_core_podman, 'verify'), mock.patch.object(importer_core_podman.urllib.request, 'urlopen', side_effect=[io.BytesIO(payload), io.BytesIO(b'wrong-readiness')]):
            output = Path(temporary) / 'inputs'
            with self.assertRaises(ValueError): importer_core_podman.prepare(output, ROOT)
            self.assertFalse((output / 'contract.json').exists())
