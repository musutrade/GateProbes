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
        self.assertEqual(core['version'], '0.13.0')
        self.assertEqual(core['source_commit'], '565e622f77659e48604cfb9508adee14765de323')
        self.assertEqual(runtime['tag'], 'podman-lifecycle-v0.3.0')
        self.assertEqual(runtime['source_commit'], 'c802fffaee9fdbea1ce9d4642ac14cb998882b20')
        self.assertEqual(runtime['archive_sha256'], '044a1e9d6d7be82ca8e83b8f810ce6c266825a793d77f418d14efd13a69d69a0')
        old = json.loads((ROOT / 'tools/runtime_import/release-pin.json').read_text())
        self.assertEqual(old['tag'], 'docker-runtime-v0.1.1')

    def test_v2_pin_cannot_select_podman_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / 'tools/runtime_import'; directory.mkdir(parents=True)
            shutil.copyfile(ROOT / 'tools/runtime_import/preflight.py', directory / 'preflight.py')
            shutil.copyfile(ROOT / 'tools/runtime_import/release-pin.json', directory / 'release-pin-podman.json')
            with self.assertRaises(ValueError): importer_core_podman.runtime_contract(root, version='0.6.0')

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
