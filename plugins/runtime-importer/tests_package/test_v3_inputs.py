"""Trusted versioned importer0.2 inputs; no unverified executable may run."""
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
import importer_core_v3


class V3Inputs(unittest.TestCase):
    def test_exact_published_pins_select_v3_without_changing_v1(self):
        core = importer_core_v3.contract(ROOT)
        runtime, _ = importer_core_v3.runtime_contract(ROOT)
        self.assertEqual(core['version'], '0.9.0')
        self.assertEqual(runtime['tag'], 'docker-readiness-v0.2.0')
        old = json.loads((ROOT / 'tools/runtime_import/release-pin.json').read_text())
        self.assertEqual(old['tag'], 'docker-runtime-v0.1.1')

    def test_v2_pin_cannot_select_importer_v3_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / 'tools/runtime_import'; directory.mkdir(parents=True)
            shutil.copyfile(ROOT / 'tools/runtime_import/preflight.py', directory / 'preflight.py')
            shutil.copyfile(ROOT / 'tools/runtime_import/release-pin.json', directory / 'release-pin-v3.json')
            with self.assertRaises(ValueError): importer_core_v3.runtime_contract(root)

    def test_wrong_download_digest_never_executes(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(importer_core_v3.urllib.request, 'urlopen', return_value=io.BytesIO(b'untrusted')), mock.patch.object(importer_core_v3.subprocess, 'run') as run:
            output = Path(temporary) / 'core'
            with self.assertRaises(ValueError): importer_core_v3.prepare(output, ROOT)
            run.assert_not_called()
            self.assertFalse((output / 'contract.json').exists())
