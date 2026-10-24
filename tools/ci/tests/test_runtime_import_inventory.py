"""Execute the workflow's exact inventory gate, including its no-skip checks."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[3]


class RuntimeImportInventory(unittest.TestCase):
    def test_workflow_discovers_39_and_requires_37_without_skips(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('Offline runtime import (37 offline tests', workflow)
        script = textwrap.dedent(workflow.split("<<'PYIMPORT'\n", 1)[1].split('          PYIMPORT', 1)[0])
        self.assertIn('len(tests) != 39 or len(required) != 37', script)
        self.assertIn('result.testsRun != 37 or result.skipped or result.expectedFailures', script)
        with tempfile.TemporaryDirectory(dir=Path.home()) as home:
            Path(home).chmod(0o700)
            run = subprocess.run([sys.executable, '-B', '-c', script], cwd=ROOT,
                                 env=dict(os.environ, HOME=home), capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('Ran 37 tests', run.stderr)
