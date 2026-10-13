"""Retained real task-3.3 runs and adversarial native/policy provenance cases."""
import copy
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import harness_evidence as evidence
import policy_engine as engine
import project_report
import typescript_contracts as adapter

ROOT = Path(__file__).resolve().parents[3]
RETAINED = ROOT / 'docs/quality/gh-133'


class TypeScriptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = evidence.load_json(RETAINED / 'index.json')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def native(self, scenario='breaking'):
        path = self.root / scenario
        entry = self.index['native'][scenario]
        archive = RETAINED / entry['path']
        self.assertEqual(adapter.digest(archive), entry['sha256'])
        with tarfile.open(archive) as bundle:
            bundle.extractall(path, filter='data')
        self.assertEqual(adapter.digest(path / 'receipt.json'), entry['receipt_sha256'])
        return path, entry['receipt_sha256'], copy.deepcopy(entry['context'])

    def test_real_compatible_contract_and_current_client_pass(self):
        p, policy, records, report = adapter.evaluate(*self.native('compatible'))
        self.assertEqual(report['aggregate']['state'], 'pass')
        self.assertEqual(len(records), 3)
        for component in ('api', 'frontend'):
            self.assertEqual(report['components'][component]['local']['state'], 'pass')
        self.assertEqual(records[0]['metrics'][0]['value'], dict(type='count', value=0))

    def test_real_break_blocks_green_components_and_preserves_raw_relationships(self):
        root, receipt, context = self.native()
        p, policy, records, report = adapter.evaluate(root, receipt, context)
        self.assertEqual(report['aggregate']['state'], 'fail')
        for component in ('api', 'frontend'):
            self.assertEqual(report['components'][component]['local']['state'], 'pass')
            self.assertEqual(report['components'][component]['cross_component']['state'], 'fail')
        gates = [g for g in report['gates'].values() if g['policy'].startswith('contract.')]
        self.assertEqual(len(gates), 3)
        self.assertTrue(all(g['state'] == 'fail' for g in gates))
        for gate in gates:
            detail = gate['record']
            self.assertEqual(detail['contract'], records[0]['contract'])
            self.assertEqual(detail['relationship']['producer'], 'api')
            self.assertEqual(detail['relationship']['consumer'], 'frontend')
            self.assertEqual(set(detail['relationship']['subjects']), {s['id'] for s in p['subjects']})
            paths = {a['path'] for a in detail['evidence_links']['head']['artifacts']}
            self.assertTrue({'oasdiff.stdout', 'manifest.json', 'receipt.json', 'baseline.json',
                             'head-client/models/Quote.ts', 'base-client/models/Quote.ts'} <= paths)
        changes = evidence.load_json(root / 'oasdiff.stdout')
        self.assertEqual(changes[0]['id'], 'response-property-became-optional')
        manifest = evidence.load_json(root / 'manifest.json')
        self.assertEqual(manifest['tools']['generator'], '0.29.0')
        self.assertTrue(all(c['exit_status'] == 0 for c in manifest['commands']))
        self.assertIn('currency?: Quote.currency', (root / 'head-client/models/Quote.ts').read_text())
        self.assertIn('currency: Quote.currency', (root / 'base-client/models/Quote.ts').read_text())

    def rebind(self, root):
        adapter.write_json(root / 'receipt.json', dict(schema='typescript-contract-receipt/v1',
                           files=adapter.inventory(root, exclude={'receipt.json'})))
        return adapter.digest(root / 'receipt.json')

    def test_missing_tampered_and_extra_artifacts_fail_closed(self):
        root, receipt, context = self.native()
        for name in ('oasdiff.stdout', 'head-client/models/Quote.ts', 'manifest.json',
                     'angular-coverage.json', 'rust-coverage.json', 'served-openapi.json'):
            with self.subTest(name=name):
                path = root / name
                original = path.read_bytes()
                path.unlink()
                with self.assertRaises(evidence.MeasurementError):
                    adapter.evaluate(root, receipt, context)
                path.write_bytes(original + b' ')
                with self.assertRaises(evidence.MeasurementError):
                    adapter.evaluate(root, receipt, context)
                path.write_bytes(original)
        (root / 'unexpected').write_text('extra')
        with self.assertRaises(evidence.MeasurementError):
            adapter.evaluate(root, receipt, context)

    def test_receipt_and_caller_context_mismatch_fail_closed(self):
        root, receipt, context = self.native()
        with self.assertRaisesRegex(evidence.MeasurementError, 'receipt'):
            adapter.evaluate(root, 'f' * 64, context)
        for field in context:
            changed = {**context, field: 'wrong'}
            with self.subTest(field=field), self.assertRaises(evidence.MeasurementError):
                adapter.evaluate(root, receipt, changed)

    def test_measurement_failure_and_invocation_mismatch_even_with_rebound_receipt(self):
        root, _, context = self.native()
        original = evidence.load_json(root / 'manifest.json')
        mutations = [lambda m: m.update(status='failed'),
                     lambda m: m.update(consumer='other'),
                     lambda m: m['tools'].update(generator='unknown'),
                     lambda m: m.update(oasdiff_sha256='f' * 64),
                     lambda m: m['server'].update(url='http://127.0.0.1:1'),
                     lambda m: m['commands'].pop(),
                     lambda m: next(c for c in m['commands'] if c['name'] == 'oasdiff').update(exit_status=1),
                     lambda m: next(c for c in m['commands'] if c['name'] == 'head-client')['argv'].append('--wrong')]
        for index, mutation in enumerate(mutations):
            m = copy.deepcopy(original)
            mutation(m)
            adapter.write_json(root / 'manifest.json', m)
            with self.subTest(mutation=index), self.assertRaises(evidence.MeasurementError):
                adapter.evaluate(root, self.rebind(root), context)

    def test_malformed_tool_output_is_not_zero_breaks(self):
        root, _, context = self.native()
        for value in ({}, None, [dict(id='x')], [dict(id='x', text='x', level=3, source='wrong')]):
            adapter.write_json(root / 'oasdiff.stdout', value)
            with self.subTest(value=value), self.assertRaises(evidence.MeasurementError):
                adapter.evaluate(root, self.rebind(root), context)

    def test_stale_or_missing_generated_client_cannot_pass(self):
        root, _, context = self.native('compatible')
        client = root / 'sources/app/src/app/generated/models/Quote.ts'
        client.write_text(client.read_text() + '\n// edited after generation\n')
        with self.assertRaisesRegex(evidence.MeasurementError, 'consumer/generated'):
            adapter.evaluate(root, self.rebind(root), context)
        shutil.rmtree(root / 'head-client')
        with self.assertRaisesRegex(evidence.MeasurementError, 'missing generated'):
            adapter.evaluate(root, self.rebind(root), context)

    def test_equal_generated_bytes_with_changed_input_digest_are_unavailable(self):
        root, _, context = self.native('compatible')
        baseline = root / 'baseline.json'
        baseline.write_text(baseline.read_text() + '\n')
        with self.assertRaisesRegex(evidence.MeasurementError, 'bytes/input'):
            adapter.evaluate(root, self.rebind(root), context)

    def test_generic_policy_rejects_normalized_provenance_mismatch(self):
        root, receipt, context = self.native()
        p, policy, records = adapter.normalize(root, receipt, context)
        mutations = [lambda r: r[0]['contract'].update(consumer='wrong'),
                     lambda r: r[0]['contract']['baseline'].update(commit='f' * 40),
                     lambda r: r[0]['contract']['generated_client'].update(contract_sha256=r[0]['source']['sha256']),
                     lambda r: r[0]['artifacts'][0].update(sha256='f' * 64),
                     lambda r: r[0].update(status='measurement_error', metrics=[]),
                     lambda r: r[0]['capabilities'][0].update(state='unsupported'),
                     lambda r: r.pop(0)]
        for mutation in mutations:
            rows = copy.deepcopy(records)
            mutation(rows)
            result = engine.evaluate(policy, rows, project=p, expected=context,
                                     source_root=root / 'sources', artifact_root=root)
            self.assertNotEqual(result['aggregate']['state'], 'pass')
            report = project_report.report(result, p, policy)
            self.assertNotEqual(report['components']['api']['cross_component']['state'], 'pass')

    def test_cli_returns_nonzero_for_break_and_missing_artifact(self):
        root, receipt, context = self.native()
        expected, output = self.root / 'expected.json', self.root / 'report.json'
        adapter.write_json(expected, context)
        argv = [sys.executable, str(ROOT / 'tools/quality/typescript_contracts.py'),
                '--native', str(root), '--receipt-sha256', receipt,
                '--expected', str(expected), '--output', str(output)]
        for state in ('fail', 'measurement_error'):
            if state == 'measurement_error':
                (root / 'oasdiff.stdout').unlink()
            result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(evidence.load_json(output)['aggregate']['state'], state)

    def test_tool_facts_do_not_decide_generic_policy(self):
        root, receipt, context = self.native()
        p, policy, records = adapter.normalize(root, receipt, context)
        # Diagnostic policy accepting the same measured facts proves no adapter
        # verdict or oasdiff branch controls the generic engine.
        for rule in policy['rules'][:3]:
            rule['limit'] = next(m['value'] for m in records[0]['metrics'] if m['name'] == rule['metric'])
        result = engine.evaluate(policy, records, project=p, expected=context,
                                 source_root=root / 'sources', artifact_root=root)
        self.assertEqual(result['aggregate']['state'], 'pass')


if __name__ == '__main__':
    unittest.main()
