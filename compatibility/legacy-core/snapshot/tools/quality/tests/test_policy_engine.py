import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import harness_evidence as evidence
import policy_engine as engine

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'fixtures/harness-evidence'


def rule(metric='coverage.line', limit=None, **options):
    result = {'id': metric, 'scope': {'kind': 'project'}, 'metric': metric,
              'operator': 'ge', 'limit': limit or {'type': 'ratio', 'covered': 4, 'total': 5},
              'required': True, 'on_violation': 'fail',
              'remediation_classes': ['increase_meaningful_coverage']}
    result.update(options)
    return result


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.records = evidence.load_json(FIXTURES / 'polyglot.json')
        self.context = {'project': evidence.load_json(ROOT / 'fixtures/project-model/base.json'),
                        'source_root': ROOT / 'fixtures/project-model/sources',
                        'artifact_root': FIXTURES,
                        'expected': evidence.load_json(FIXTURES / 'expected.json')}
        ids = {r['subject']['id'] for r in self.records}
        self.context['project']['subjects'] = [s for s in self.context['project']['subjects']
                                               if s['id'] in ids]
        for relationship in self.context['project']['relationships']:
            relationship['subjects'] = [s for s in relationship['subjects'] if s in ids]
        self.policy = {'schema': 'harness-policy/v1', 'rules': [rule()]}

    def evaluate(self, **kwargs):
        return engine.evaluate(self.policy, self.records, **self.context, **kwargs)

    def test_baseline_and_exact_comparisons(self):
        result = self.evaluate()
        self.assertEqual(result['aggregate']['state'], 'pass')
        self.assertEqual(len(result['results']), 4)
        for op, expected in [('lt', False), ('le', True), ('eq', True),
                             ('ne', False), ('ge', True), ('gt', False)]:
            with self.subTest(operator=op):
                self.policy['rules'][0]['operator'] = op
                self.assertEqual(self.evaluate()['aggregate']['state'], 'pass' if expected else 'fail')
        self.assertTrue(engine.compare({'type': 'decimal', 'value': '9007199254740993.1'},
                                       'gt', {'type': 'decimal', 'value': '9007199254740993'}))
        self.assertTrue(engine.compare({'type': 'ratio', 'covered': 1, 'total': 3}, 'lt',
                                       {'type': 'ratio', 'covered': 3333333333333334,
                                        'total': 10000000000000000}))

    def test_same_evaluator_all_synthetic_metrics_and_ecosystems(self):
        cases = [('coverage.line', {'type': 'ratio', 'covered': 4, 'total': 5}, 'ge'),
                 ('risk.crap', {'type': 'decimal', 'value': '3'}, 'le'),
                 ('mutation.score', {'type': 'ratio', 'covered': 3, 'total': 4}, 'ge'),
                 ('contract.breaking_changes', {'type': 'count', 'value': 0}, 'eq'),
                 ('contract.schema_valid', {'type': 'boolean', 'value': True}, 'eq')]
        for record in self.records:
            for name, value in [('mutation.score', {'type': 'ratio', 'covered': 3, 'total': 4}),
                                ('contract.breaking_changes', {'type': 'count', 'value': 1})]:
                cap = next((c for c in record['capabilities'] if c['metric'] == name), None)
                if cap:
                    cap['state'] = 'supported'
                else:
                    record['capabilities'].append({'metric': name, 'state': 'supported',
                                                  'reason': 'synthetic', 'artifacts': ['raw']})
                    record['series']['metrics'].append({'name': name, 'type': value['type']})
                record['metrics'].append({'name': name, 'value': value, 'artifacts': ['raw']})
            record['status'] = ('measurement_error' if any(c['state'] == 'measurement_error'
                                for c in record['capabilities']) else 'measured')
            record['series']['metrics'].sort(key=lambda m: m['name'])
            record['series']['id'] = evidence.series_id(record['series'])
        self.policy['rules'] = [rule(name, value, operator=op) for name, value, op in cases]
        result = self.evaluate()
        self.assertEqual(len(result['results']), 20)
        for child in result['results']:
            self.assertEqual(child['state'], 'fail' if child['policy'] in
                             ('risk.crap', 'contract.breaking_changes') else 'pass')

    def test_selectors_and_caller_owned_subject_sets(self):
        first = self.records[0]['subject']
        cases = [({'kind': 'project'}, {}, 4),
                 ({'kind': 'component', 'component': first['component']}, {}, 1),
                 ({'kind': 'boundary', 'component': first['component'],
                   'boundary': first['boundary']}, {}, 1),
                 ({'kind': 'changed_subject'}, {'changed_subject': [first['id']]}, 1),
                 ({'kind': 'critical_subject'}, {'critical_subject': [first['id']]}, 1)]
        for scope, selection, count in cases:
            self.policy['rules'][0]['scope'] = scope
            result = self.evaluate(selection=selection)
            self.assertEqual(result['aggregate']['state'], 'pass')
            self.assertEqual(len(result['results']), count)
        for selection in ({}, {'critical_subject': ['unknown']},
                          {'critical_subject': [first['id'], first['id']]}):
            self.assertEqual(self.evaluate(selection=selection)['aggregate']['state'], 'measurement_error')
        self.assertEqual(self.evaluate(selection={'critical_subject': []})['aggregate']['state'], 'blocked')

    def test_capability_states_missing_and_corrupt_evidence_fail_closed(self):
        original = copy.deepcopy(self.records)
        for state, gate in [('unsupported', 'unsupported'), ('not_applicable', 'not_applicable'),
                            ('not_configured', 'blocked'), ('not_collected', 'skipped'),
                            ('measurement_error', 'measurement_error')]:
            self.records = copy.deepcopy(original)
            r = self.records[0]
            next(c for c in r['capabilities'] if c['metric'] == 'coverage.line')['state'] = state
            r['metrics'] = [m for m in r['metrics'] if m['name'] != 'coverage.line']
            if state == 'measurement_error':
                r['status'] = state
            result = self.evaluate()
            self.assertEqual(result['results'][0]['state'], gate)
            self.assertNotEqual(result['aggregate']['state'], 'pass')
            self.assertIsNone(result['results'][0]['record']['head'])
        self.records = original[1:]
        self.assertEqual(self.evaluate()['aggregate']['state'], 'measurement_error')
        self.records = []
        self.assertEqual(len(self.evaluate()['violations']), 4)
        self.records = original
        self.records[0]['artifacts'][0]['sha256'] = 'f' * 64
        self.assertEqual(self.evaluate()['aggregate']['state'], 'measurement_error')

    def test_aggregate_distinct_states_requiredness_and_missing_children(self):
        for state in engine.GateState:
            child = engine.GateResult('coverage.line', 'subject', state, 'test', {})
            result = engine.aggregate(self.policy, [child])
            self.assertEqual(result['state'] == 'pass', state in ('pass', 'informational'))
            if result['blockers']:
                self.assertEqual(result['blockers'][0]['state'], state)
            self.policy['rules'][0]['required'] = False
            self.assertEqual(engine.aggregate(self.policy, [child])['state'], 'pass')
            self.policy['rules'][0]['required'] = True
        self.assertEqual(engine.aggregate(self.policy, [])['state'], 'blocked')
        children = [engine.GateResult('coverage.line', str(i), state, '', {})
                    for i, state in enumerate((engine.GateState.FAIL, engine.GateState.MEASUREMENT_ERROR))]
        self.assertEqual({b['state'] for b in engine.aggregate(self.policy, children)['blockers']},
                         {'fail', 'measurement_error'})
        with self.assertRaisesRegex(evidence.MeasurementError, 'duplicate'):
            engine.aggregate(self.policy, children + children)
        self.assertEqual(len({json.dumps(s) for s in engine.GateState}), 10)

    def test_policy_schema_rejects_dsl_unknown_scopes_and_wrong_types(self):
        original = copy.deepcopy(self.policy)
        bad = [('expression', 'eval(anything)'), ('metric', 'unknown.metric'),
               ('required', 'false'), ('limit', {'type': 'count', 'value': 1}),
               ('scope', {'kind': 'component', 'component': 'missing'}),
               ('scope', {'kind': 'boundary', 'component': 'frontend', 'boundary': 'missing'}),
               ('operator', 'python')]
        for key, value in bad:
            self.policy = copy.deepcopy(original)
            self.policy['rules'][0][key] = value
            with self.subTest(key=key), self.assertRaises(evidence.MeasurementError):
                self.evaluate()
        self.policy['rules'] = [rule('contract.schema_valid', {'type': 'boolean', 'value': True})]
        with self.assertRaisesRegex(evidence.MeasurementError, 'boolean'):
            self.evaluate()

    def test_agent_context_base_series_and_nonblocking_information(self):
        self.policy['rules'] = [rule('risk.crap', {'type': 'decimal', 'value': '3'}, operator='le',
                                    remediation_classes=['reduce_complexity', 'increase_meaningful_coverage'])]
        base = copy.deepcopy(self.records)
        base_context = copy.deepcopy(self.context)
        base_context['expected']['commit'] = self.context['expected']['base_commit']
        # Retained raw artifact context must match the caller-owned base run.
        for r in base:
            r['context'] = copy.deepcopy(base_context['expected'])
            for a in r['artifacts']:
                a['context'] = copy.deepcopy(base_context['expected'])
        result = self.evaluate(base_records=base, base_context=base_context)
        detail = json.loads(json.dumps(result))['violations'][0]['record']
        self.assertEqual(detail['base'], detail['head'])
        for key in ('component', 'subject', 'metric', 'context', 'policy', 'measurement_series',
                    'evidence_links', 'remediation_classes'):
            self.assertTrue(detail[key])
        base[0]['series']['tool']['version'] += '-changed'
        base[0]['series']['id'] = evidence.series_id(base[0]['series'])
        self.assertEqual(self.evaluate(base_records=base, base_context=base_context)['aggregate']['state'],
                         'measurement_error')
        self.policy['rules'][0]['on_violation'] = 'informational'
        self.assertEqual(self.evaluate()['aggregate']['state'], 'pass')
        self.policy['rules'][0]['on_violation'] = 'warning'
        self.assertEqual(self.evaluate()['results'][0]['state'], 'warning')

    def test_omitted_project_subject_ambiguous_series_and_collector_verdict(self):
        self.context['project'] = evidence.load_json(ROOT / 'fixtures/project-model/base.json')
        result = self.evaluate()
        missing = result['violations'][0]
        self.assertEqual(missing['record']['subject']['kind'], 'contract/v1')
        self.assertEqual(missing['state'], 'measurement_error')
        self.policy['rules'][0]['scope'] = {'kind': 'component', 'component': 'frontend'}
        duplicate = copy.deepcopy(self.records[0])
        duplicate['id'] += '-second-series'
        duplicate['series']['tool']['version'] += '-new'
        duplicate['series']['id'] = evidence.series_id(duplicate['series'])
        self.records.append(duplicate)
        result = self.evaluate()
        self.assertEqual(result['aggregate']['state'], 'measurement_error')
        self.assertIn('ambiguous', result['results'][0]['reason'])
        self.records.pop()
        self.records[0]['release_status'] = 'pass'
        self.assertEqual(self.evaluate()['aggregate']['state'], 'measurement_error')

    def test_cli_serializes_failure_and_exit_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy, output = Path(tmp) / 'policy.json', Path(tmp) / 'result.json'
            self.policy['rules'][0]['operator'] = 'gt'
            self.policy['rules'][0]['scope'] = {'kind': 'component', 'component': 'frontend'}
            policy.write_text(json.dumps(self.policy))
            command = [sys.executable, str(ROOT / 'policy_engine.py'), '--reference-only', '--policy', str(policy),
                       '--evidence', str(FIXTURES / 'polyglot.json'), '--project',
                       str(ROOT / 'fixtures/project-model/base.json'), '--source-root',
                       str(self.context['source_root']), '--artifact-root', str(FIXTURES),
                       '--expected', str(FIXTURES / 'expected.json'), '--output', str(output)]
            run = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(run.returncode, 1, run.stderr)
            self.assertEqual(json.loads(output.read_text())['aggregate']['state'], 'fail')
