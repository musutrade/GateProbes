"""The new v3 proof is required; a successful legacy job cannot replace it."""
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[3]


class ImporterV3Gate(unittest.TestCase):
    def test_required_job_cannot_pass_when_missing_skipped_or_failed(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('runtime-importer, runtime-import-v3, runtime-import-lifecycle, runtime-import-podman, plugins', workflow)
        gate = workflow.split('      - name: Require v3 importer acceptance\n', 1)[1]
        self.assertIn('RESULT: ${{ needs.runtime-import-v3.result }}', gate)
        script = textwrap.dedent(gate.split("<<'PYV3'\n", 1)[1].split('          PYV3', 1)[0])
        for selected, result, succeeds in [('true','success',True), ('true','skipped',False),
                                          ('true','failure',False), ('true','',False),
                                          ('false','skipped',True), ('unknown','success',False)]:
            run = subprocess.run([sys.executable,'-c',script], env=dict(os.environ, SELECTED=selected, RESULT=result), capture_output=True)
            self.assertEqual(run.returncode == 0, succeeds, (selected,result))

    def test_candidate_and_release_both_use_v3_inputs_and_keep_legacy_fixture(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text()
        job = ci.split('  runtime-import-v3:\n',1)[1].split('  runtime-import-joint:',1)[0]
        self.assertIn('importer_core_v3.py', job)
        self.assertIn('--plugin runtime-importer', job)
        self.assertIn('importer-v3-dist',job)
        self.assertIn('legacy_fixture.create',ci)
        release = (ROOT / '.github/workflows/collector-release.yml').read_text()
        self.assertIn('importer_core_podman.py --output', release)
        self.assertNotIn('importer_core.py --output', release)
        self.assertIn('HARNESS_GATE_IMPORTER_ACCEPTANCE:', release)
