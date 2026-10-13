"""GH-132: native collector replay plus explicitly derived policy-seam cases.

Counter/identity mutations below exercise generic policy, not new native runs or
adapter certification. Untouched base/head replay and thresholds use raw counters.
"""
import copy
import hashlib
from pathlib import Path
import shutil
import tarfile
import unittest

import test_typescript_reference as frontend
from test_policy_engine import rule
import harness_evidence as evidence
import policy_engine as engine
import project_model as model
import rust_reference as rust


class TypeScriptPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        frontend.TypeScriptCollectorTests.setUpClass()

    def setUp(self):
        self.fixture = frontend.TypeScriptCollectorTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        self.records = f.run_adapter()
        self.context = dict(project=f.project, source_root=f.workspace,
                            artifact_root=f.output, expected=copy.deepcopy(f.request['context']))
        f.request['context'] = dict(commit='b' * 40, base_commit='c' * 40,
                                    target='node-jsdom', run='gh132-base-replay')
        f.output = f.root / 'base-output'
        f.output.mkdir()
        f.request['output_root'] = str(f.output)
        f.rebind()
        self.base = f.run_adapter()
        sources = f.root / 'base-sources'
        shutil.copytree(f.workspace, sources)
        self.base_context = dict(project=copy.deepcopy(f.project), source_root=sources,
                                 artifact_root=f.output, expected=copy.deepcopy(f.request['context']))
        self.head = next(r for r in self.records if r['subject']['path'].endswith('/pricing.ts')
                         and r['subject']['kind'] == 'file/v1')
        self.prior = next(r for r in self.base if r['subject']['id'] == self.head['subject']['id'])
        self.policy = {'schema': 'harness-policy/v1', 'rules': [rule(
            scope={'kind': 'subject', 'subject': self.head['subject']['id']},
            ratchet={'deny_regression': True, 'allow_legacy_debt': True})]}
        self.mappings = {'schema': 'subject-mappings/v1', 'project': f.project['id'], 'mappings': []}

    def evaluate(self, **options):
        arguments = dict(base_records=self.base, base_context=self.base_context, mappings=self.mappings)
        arguments.update(options)
        return engine.evaluate(self.policy, self.records, **self.context, **arguments)

    @staticmethod
    def value(record, covered):
        # Controlled policy input derived from native 4/6; never a claimed tool run.
        next(m for m in record['metrics'] if m['name'] == 'coverage.line')['value']['covered'] = covered

    def change_identity(self, kind):
        subject = self.head['subject']
        old = copy.deepcopy(subject)
        source = self.context['source_root'] / subject['path']
        if kind == 'modify':
            source.write_bytes(source.read_bytes() + b'\n// policy lineage fixture\n')
            subject['source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
        elif kind == 'rename':
            subject['discriminator'] += ':renamed'
        elif kind == 'move':
            subject['path'] = str(Path(subject['path']).with_name('moved-pricing.ts'))
            shutil.copyfile(source, self.context['source_root'] / subject['path'])
        subject['id'] = model.subject_id(self.context['project']['id'], subject)
        self.head['source'] = dict(path=subject['path'], sha256=subject['source_sha256'])
        for artifact in self.head['artifacts']:
            artifact['source'] = copy.deepcopy(self.head['source'])
        # Only the selected file is needed here; sibling function evidence refers
        # to the old bytes in the modify case and is deliberately excluded.
        self.records = [self.head]
        self.context['project']['subjects'] = [copy.deepcopy(subject)]
        self.policy['rules'][0]['scope']['subject'] = subject['id']
        self.mappings['mappings'] = [dict(kind=kind, **{'from': old['id']},
                                         to=[subject['id']], reason='controlled policy lineage fixture')]
        return old

    def test_native_thresholds_and_unchanged_legacy_debt(self):
        self.assertEqual(next(m['value'] for m in self.head['metrics'] if m['name'] == 'coverage.line'),
                         {'type': 'ratio', 'covered': 4, 'total': 6})
        result = self.evaluate()
        self.assertEqual(result['aggregate']['state'], 'pass')
        detail = result['debt_ledger'][0]['record']
        self.assertEqual(detail['ratchet']['debt'], 'unchanged')
        self.assertTrue(detail['ratchet']['legacy_debt_allowed'])
        self.assertTrue(detail['baseline']['inherits_history'])
        del self.policy['rules'][0]['ratchet']
        for covered, expected in ((4, 'pass'), (5, 'fail')):
            self.policy['rules'][0]['limit'] = dict(type='ratio', covered=covered, total=6)
            self.assertEqual(self.evaluate()['aggregate']['state'], expected)

    def test_regression_improvement_new_and_resolved_debt(self):
        for base, head, debt, state in ((4, 3, 'regressed', 'fail'), (3, 4, 'improved', 'pass'),
                                       (6, 4, 'new', 'fail'), (4, 6, 'resolved', 'pass'),
                                       (6, 5, 'none', 'fail')):
            with self.subTest(base=base, head=head):
                self.value(self.prior, base)
                self.value(self.head, head)
                result = self.evaluate()
                self.assertEqual(result['aggregate']['state'], state)
                detail = result['results'][0]['record']
                self.assertEqual(detail['ratchet']['debt'], debt)
                self.assertEqual(bool(result['debt_ledger']), debt != 'none')
        self.value(self.prior, 4)
        self.value(self.head, 4)
        self.policy['rules'][0]['ratchet']['allow_legacy_debt'] = False
        self.assertEqual(self.evaluate()['aggregate']['state'], 'fail')

    def test_modify_rename_move_inherit_only_explicit_history(self):
        for kind in ('modify', 'rename', 'move'):
            with self.subTest(kind=kind):
                # Restore a fresh pair for each independently derived identity.
                if kind != 'modify':
                    self.setUp()
                old = self.change_identity(kind)
                result = self.evaluate()
                self.assertEqual(result['aggregate']['state'], 'pass')
                lineage = result['results'][0]['record']['baseline']
                self.assertEqual(lineage, dict(classification='modified', lineage_kind=kind,
                                              lineage_base_subject=old['id'], inherits_history=True))
                self.mappings['mappings'] = []
                result = self.evaluate()
                self.assertEqual(result['aggregate']['state'], 'fail')
                self.assertEqual(result['debt_ledger'][0]['record']['ratchet']['debt'], 'new')

    def test_missing_base_and_ambiguous_identity_fail_closed(self):
        for options in (dict(base_records=None, base_context=None, mappings=None),
                        dict(base_records=[]), dict(base_records=self.base + [self.prior]),
                        dict(base_context=None)):
            with self.subTest(options=list(options)):
                self.assertEqual(self.evaluate(**options)['aggregate']['state'], 'measurement_error')
        self.change_identity('rename')
        self.mappings['mappings'].append(copy.deepcopy(self.mappings['mappings'][0]))
        self.assertEqual(self.evaluate()['aggregate']['state'], 'measurement_error')

    def test_unavailable_base_coverage_blocks_incremental_credit(self):
        for state in ('unsupported', 'not_collected', 'not_configured', 'not_applicable'):
            with self.subTest(state=state):
                base = copy.deepcopy(self.base)
                record = next(r for r in base if r['subject']['id'] == self.head['subject']['id'])
                next(c for c in record['capabilities'] if c['metric'] == 'coverage.line')['state'] = state
                record['metrics'] = [m for m in record['metrics'] if m['name'] != 'coverage.line']
                self.assertEqual(self.evaluate(base_records=base)['aggregate']['state'], 'measurement_error')
        self.records.append(copy.deepcopy(self.head))
        self.assertEqual(self.evaluate()['aggregate']['state'], 'measurement_error')

    def test_incompatible_series_preserves_no_favorable_debt_result(self):
        for field in ('tool', 'normalization', 'source_identity', 'runtime', 'rule'):
            with self.subTest(field=field):
                base = copy.deepcopy(self.base)
                for record in base:
                    record['series'][field]['version'] += '-incompatible'
                    record['series']['id'] = evidence.series_id(record['series'])
                result = self.evaluate(base_records=base)
                self.assertEqual(result['aggregate']['state'], 'measurement_error')
                self.assertEqual(result['debt_ledger'], [])
        self.change_identity('rename')
        self.mappings['mappings'] = []
        self.assertEqual(self.evaluate(base_records=base)['aggregate']['state'], 'measurement_error')

    def test_unavailable_risk_template_and_route_cannot_inherit_file_coverage(self):
        for metric in ('complexity.cyclomatic', 'risk.crap', 'coverage.line'):
            candidates = [self.head] if metric != 'coverage.line' else [
                r for r in self.records if r['subject']['kind'] == 'route/v1'
                or r['subject']['path'].endswith('/app.ts')]
            self.assertTrue(candidates)
            for record in candidates:
                with self.subTest(metric=metric, subject=record['subject']['path']):
                    self.assertNotIn(metric, [m['name'] for m in record['metrics']])
                    self.policy['rules'][0].update(metric=metric, limit=(
                        dict(type='count', value=10) if metric == 'complexity.cyclomatic' else
                        dict(type='decimal', value='30') if metric == 'risk.crap' else
                        dict(type='ratio', covered=0, total=1)))
                    self.policy['rules'][0]['scope']['subject'] = record['subject']['id']
                    result = self.evaluate()
                    self.assertEqual(result['results'][0]['state'], 'unsupported')
                    self.assertEqual(result['aggregate']['state'], 'blocked')
                    self.assertIsNone(result['violations'][0]['record']['head'])

    def test_agent_violation_retains_actionable_base_head_evidence(self):
        self.value(self.prior, 6)
        result = self.evaluate()
        detail = result['violations'][0]['record']
        self.assertEqual(detail['component'], 'typescript')
        self.assertEqual(detail['subject'], self.head['subject'])
        self.assertEqual(detail['metric'], 'coverage.line')
        self.assertEqual(detail['base'], dict(type='ratio', covered=6, total=6))
        self.assertEqual(detail['head'], dict(type='ratio', covered=4, total=6))
        self.assertEqual(detail['context'], self.context['expected'])
        self.assertEqual(detail['remediation_classes'], ['increase_meaningful_coverage'])
        for label, record in (('base', self.prior), ('head', self.head)):
            self.assertEqual(detail['measurement_series'][label], record['series']['id'])
            self.assertEqual(detail['evidence_links'][label],
                             dict(evidence_id=record['id'], artifacts=record['artifacts']))

    def test_real_rust_and_typescript_share_policy_with_distinct_series(self):
        history = evidence.load_json(frontend.ROOT / 'fixtures/rust-reference/history.json')
        root = self.fixture.root / 'rust'
        archive = frontend.ROOT.parents[1] / history['retained_candidate']['path']
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),
                         history['retained_candidate']['sha256'])
        with tarfile.open(archive) as bundle:
            bundle.extractall(root, filter='data')
        sources = self.fixture.root / 'rust-sources'
        rust.sources_from_archive(root / 'head-source.tar', sources)
        candidate = evidence.load_json(root / 'candidate.json')
        context = dict(commit=candidate['commit'], base_commit=candidate['base_sha'],
                       target=candidate['target'], run=candidate['run_id'])
        projection, original, mismatches = rust.project_production(
            root, sources, context, evidence.load_json(root / 'production.json'))
        self.assertEqual(mismatches, [])
        # Each retained ecosystem validates in its own original target context.
        # Generic gate aggregation then evaluates both sets of required rules.
        del self.policy['rules'][0]['ratchet']
        frontend_result = self.evaluate()
        mixed_policy = dict(schema='harness-policy/v1',
                            rules=self.policy['rules'] + projection.rules)
        gates = [engine.GateResult(**r) for r in frontend_result['results'] + original['results']]
        self.assertEqual(engine.aggregate(mixed_policy, gates)['state'], 'fail')
        self.policy['rules'][0]['limit'] = dict(type='ratio', covered=4, total=6)
        frontend_result = self.evaluate()
        mixed_policy['rules'] = self.policy['rules'] + projection.rules
        gates = [engine.GateResult(**r) for r in frontend_result['results'] + original['results']]
        self.assertEqual(engine.aggregate(mixed_policy, gates)['state'], original['aggregate']['state'])
        self.assertEqual(projection.evaluate(), original)
        rust_series = projection.records[0]['series']
        self.assertNotEqual(rust_series['id'], self.head['series']['id'])
        with self.assertRaises(evidence.MeasurementError):
            evidence.require_compatible_series(rust_series, self.head['series'])
        # Use a valid Rust base record in a comparison of the same source identity:
        # the series boundary itself must reject it before debt is granted.
        with self.assertRaisesRegex(evidence.MeasurementError, 'series'):
            engine.ratchet.baseline(self.head, 'coverage.line',
                                   [{**self.prior, 'series': rust_series}], self.base_context, ({}, {}))


if __name__ == '__main__':
    unittest.main()
