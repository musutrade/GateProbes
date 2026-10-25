"""Exact product and release preflight cannot silently fall back to published0.2."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools/release'))
import source_risk_candidate
import plugin_release
import package_plugin


class SourceRiskReleaseIdentityTests(unittest.TestCase):
    def test_catalog_is_exact_new_identity_with_nested_manifest(self):
        row=plugin_release.resolve('rust-source-risk')
        self.assertEqual(row['version'],'0.3.0')
        self.assertEqual(row['archive'],'harness-gate-rust-source-risk-0.3.0-linux-amd64.tar.gz')
        with self.assertRaises(Exception):
            plugin_release.resolve_tag('rust-source-risk-v0.2.0')

    def test_each_actual_product_identity_must_agree(self):
        source=ROOT/'plugins/rust-source-risk'
        self.assertEqual(source_risk_candidate.identity(source,'0.3.0'),{'name':'rust-source-risk','version':'0.3.0'})
        for name in ['plugin.json','plugin.py','ast/Cargo.toml','ast/Cargo.lock']:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as tmp:
                stage=Path(tmp)
                for file in ['plugin.json','plugin.py','ast/Cargo.toml','ast/Cargo.lock']:
                    target=stage/file;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source/file,target)
                target=stage/name;target.write_text(target.read_text().replace('0.3.0','0.2.0',1))
                with self.assertRaisesRegex(ValueError,'identity mismatch'):
                    source_risk_candidate.identity(stage,'0.3.0')

    def test_release_command_cannot_omit_real_candidate_gate(self):
        result=subprocess.run([sys.executable,ROOT/'tools/release/package_plugin.py',
            '--plugin','rust-source-risk','--core-root','/missing','--output','/missing'],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('requires --source-risk-core and --source-risk-evidence',result.stderr)

    def test_wrong_published_core_is_rejected_before_tool_or_build_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary=Path(tmp)/'core';binary.write_bytes(b'wrong binary')
            with self.assertRaisesRegex(RuntimeError,'Core binary digest mismatch'):
                source_risk_candidate.environment(ROOT/'plugins/rust-source-risk',binary)

    def test_source_and_extracted_guard_require_actual_cases_and_no_skips(self):
        output = ('test_mixed_direct_variant_derive_stops_before_cargo (test_preflight.T) ... ok\n'
                  'test_exact_authored_inventory_counters_and_complexity (test_native.T) ... ok\n'
                  'Ran 66 tests in 1.0s\nOK\n')
        self.assertEqual(package_plugin.require_source_risk_tests(output),66)
        for wrong in [output+'skipped=1',output.replace('Ran 66','Ran 0'),
                      output.replace('test_mixed_direct_variant_derive_stops_before_cargo','absent')]:
            with self.assertRaises(RuntimeError):package_plugin.require_source_risk_tests(wrong)

    def test_candidate_gate_and_release_workflow_keep_fixed_old_job_separate(self):
        ci=(ROOT/'.github/workflows/ci.yml').read_text()
        self.assertIn('source-risk 0.3.0 complete candidate acceptance',ci)
        self.assertIn("RESULT: ${{ needs.source-risk-candidate.result }}",ci)
        self.assertIn('source-risk 0.2.0 current consumer acceptance',ci)
        release=(ROOT/'.github/workflows/collector-release.yml').read_text()
        self.assertIn('--source-risk-core',release)
        self.assertIn('--source-risk-evidence',release)


if __name__=='__main__':
    unittest.main()
