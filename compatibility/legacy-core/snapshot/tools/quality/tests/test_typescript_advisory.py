"""Advisory publication must preserve failure evidence and reject stale output."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import typescript_advisory as advisory


class AdvisoryTests(unittest.TestCase):
    def test_failed_replay_retains_machine_readable_failure_and_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'advisory'
            with patch.object(advisory.acceptance, 'verify_window',
                              side_effect=ValueError('tampered retained evidence')):
                self.assertEqual(advisory.run(output), 1)
            summary = json.loads((output / 'summary.json').read_text())
            self.assertEqual(summary['status'], 'error')
            self.assertIn('tampered retained evidence', summary['error'])
            inventory = json.loads((output / 'artifacts.json').read_text())
            self.assertEqual(inventory['summary.json']['sha256'],
                             advisory.contracts.digest(output / 'summary.json'))
            before = (output / 'summary.json').read_bytes()
            with self.assertRaises(FileExistsError):
                advisory.run(output)
            self.assertEqual((output / 'summary.json').read_bytes(), before)

    def test_changed_contract_archive_is_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            retained = Path(directory)
            (retained / 'native.tar.gz').write_bytes(b'tampered')
            advisory.write(retained / 'index.json', dict(native=dict(compatible=dict(
                path='native.tar.gz', sha256='0' * 64))))
            with self.assertRaisesRegex(ValueError, 'archive digest mismatch'):
                advisory.replay_contracts(retained, retained / 'output')
            self.assertFalse((retained / 'output').exists())
