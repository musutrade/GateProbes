"""GH-134 retained native history and the full frontend rejection matrix."""
import copy
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_typescript_reference as frontend
import harness_evidence as evidence
import typescript_acceptance as acceptance
import typescript_semantics as ts


class FreshNativeNegativeTests(frontend.TypeScriptCollectorTests):
    # Re-run every GH-131 integrity/provenance/transport case on fresh GH-134 bytes.
    native_directory = acceptance.RETAINED / 'regression-head'
    semantics_directory = native_directory

    def replace_artifact(self, files, manifest, name, value):
        files[name] = json.dumps(value).encode()
        manifest['artifacts'][name].update(sha256=ts.digest(files[name]), bytes=len(files[name]))

    def test_missing_native_coverage(self):
        def mutate(files, manifest):
            name = next(n for n in files if n.endswith('/coverage-final.json'))
            coverage = json.loads(files[name])
            del coverage[self.receipt['coverage_root'] + '/src/app/pricing.ts']
            self.replace_artifact(files, manifest, name, coverage)
        self.rewrite_native(mutate)
        self.assert_failure('measurement_error')

    def test_duplicate_native_symbols(self):
        def mutate(files, manifest):
            name = next(n for n in files if n.endswith('/coverage-final.json'))
            coverage = json.loads(files[name])
            row = coverage[self.receipt['coverage_root'] + '/src/app/pricing.ts']
            row['fnMap']['duplicate'] = copy.deepcopy(row['fnMap']['0'])
            row['f']['duplicate'] = row['f']['0']
            self.replace_artifact(files, manifest, name, coverage)
        self.rewrite_native(mutate)
        self.assert_failure('measurement_error')

    def test_ambiguous_parser_symbols(self):
        index = json.loads(self.index)
        functions = index['files']['src/app/pricing.ts']['functions']
        functions.append(copy.deepcopy(functions[0]))
        data = json.dumps(index).encode()
        (self.workspace / 'index.json').write_bytes(data)
        self.request['parameters']['receipt']['index_sha256'] = ts.digest(data)
        self.assert_failure('measurement_error')

    def test_tampered_source_map_inventory(self):
        def mutate(files, manifest):
            name = self.bundle.maps_for('src/app/pricing.ts')[0]
            files[name] += b'\n'
        self.rewrite_native(mutate)
        self.assert_failure('measurement_error')

    def test_missing_source_maps(self):
        def mutate(files, manifest):
            for name in list(files):
                if name.endswith('.map'):
                    del files[name]
                    del manifest['artifacts'][name]
        self.rewrite_native(mutate)
        self.assert_failure('measurement_error')


class NativeWindowTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_two_real_pairs_exact_counters_outcomes_and_debt(self):
        result = acceptance.verify_window(acceptance.RETAINED, self.root)
        self.assertEqual(result, evidence.load_json(acceptance.RETAINED / 'results.json'))
        for pair, covered, state in [('compatible', 5, 'pass'), ('regression', 4, 'fail')]:
            self.assertEqual(result['counters'][pair + '-base']['pricing'], dict(covered=5, total=6))
            self.assertEqual(result['counters'][pair + '-head']['pricing'], dict(covered=covered, total=6))
            for report in result['pairs'][pair].values():
                self.assertEqual(report['report']['aggregate']['state'], state)
            base = acceptance.unpack(acceptance.RETAINED / (pair + '-base/native.tar.gz'))
            head = acceptance.unpack(acceptance.RETAINED / (pair + '-head/native.tar.gz'))
            bm, hm = (json.loads(run['manifest.json']) for run in (base, head))
            self.assertNotEqual(bm['revision'], hm['revision'])
            self.assertEqual(bm['working_tree'], '')
            self.assertEqual(hm['working_tree'], '')
            self.assertEqual(bm['configuration_digests'], hm['configuration_digests'])
            self.assertNotEqual(base['sources/app/src/app/pricing.spec.ts'],
                                head['sources/app/src/app/pricing.spec.ts'])
        self.assertEqual(result['unexplained_mismatches'], [])

    def test_native_receipts_match_retained_git_parent_and_source_bytes(self):
        window = evidence.load_json(acceptance.RETAINED / 'window.json')['runs']
        for pair in ('compatible', 'regression'):
            clone = self.root / pair
            subprocess.run(['git', 'clone', '--quiet', str(acceptance.RETAINED / (pair + '.bundle')),
                            str(clone)], check=True, capture_output=True)
            def git(*args):
                return subprocess.run(['git', *args], cwd=clone, check=True,
                                      capture_output=True).stdout
            base, head = (window[pair + '-' + side]['commit'] for side in ('base', 'head'))
            self.assertEqual(git('rev-parse', head + '^').decode().strip(), base)
            self.assertEqual(window[pair + '-head']['base_commit'], base)
            for side in ('base', 'head'):
                name = pair + '-' + side
                files = acceptance.unpack(acceptance.RETAINED / name / 'native.tar.gz')
                commit = window[name]['commit']
                self.assertEqual(json.loads(files['manifest.json'])['revision'], commit)
                for path, data in files.items():
                    if path.startswith('sources/'):
                        self.assertEqual(git('show', commit + ':fixture/' + path[8:]), data)

    def pair(self):
        return [acceptance.replay(acceptance.RETAINED, 'compatible-' + side, self.root / side)
                for side in ('base', 'head')]

    def test_changed_semantic_series_blocks_without_rewriting_historical_debt(self):
        base, head = self.pair()
        policy = acceptance.policy(acceptance.pricing(head)['subject']['id'], 9, 10)
        before = copy.deepcopy(base['records'])
        initial = acceptance.evaluate(base, head, policy)
        self.assertEqual(initial['debt_ledger'][0]['record']['ratchet']['debt'], 'unchanged')
        for field in ('tool', 'normalization', 'source_identity', 'runtime', 'rule'):
            with self.subTest(field=field):
                changed = {**head, 'records': copy.deepcopy(head['records'])}
                series = acceptance.pricing(changed)['series']
                series[field]['version'] += '-incompatible'
                series['id'] = evidence.series_id(series)
                result = acceptance.evaluate(base, changed, policy)
                self.assertEqual(result['aggregate']['state'], 'measurement_error')
                self.assertIn('series', result['results'][0]['reason'])
                self.assertNotIn('ratchet', result['results'][0]['record'])
                self.assertEqual(base['records'], before)
        restored = acceptance.evaluate(base, head, policy)
        self.assertEqual(restored, initial)

    def test_required_unsupported_metrics_never_gain_numeric_defaults(self):
        base, head = self.pair()
        for metric in ('coverage.branch', 'complexity.cyclomatic', 'risk.crap'):
            with self.subTest(metric=metric):
                policy = acceptance.policy(acceptance.pricing(head)['subject']['id'])
                policy['rules'][0]['metric'] = metric
                if metric == 'complexity.cyclomatic':
                    policy['rules'][0]['limit'] = dict(type='count', value=1)
                elif metric == 'risk.crap':
                    policy['rules'][0]['limit'] = dict(type='decimal', value='1')
                result = acceptance.evaluate(base, head, policy)
                self.assertEqual(result['aggregate']['state'], 'blocked')
                self.assertEqual(result['results'][0]['state'], 'unsupported')
                self.assertFalse(any(m['name'] == metric for m in acceptance.pricing(head)['metrics']))

    def test_missing_and_duplicate_base_evidence_block_legacy_debt(self):
        base, head = self.pair()
        policy = acceptance.policy(acceptance.pricing(head)['subject']['id'], 9, 10)
        for records in ([], base['records'] + [acceptance.pricing(base)]):
            with self.subTest(size=len(records)):
                result = acceptance.evaluate({**base, 'records': records}, head, policy)
                self.assertEqual(result['aggregate']['state'], 'measurement_error')

    def test_disallowed_legacy_debt_fails_and_keeps_ledger(self):
        base, head = self.pair()
        policy = acceptance.policy(acceptance.pricing(head)['subject']['id'], 9, 10)
        policy['rules'][0]['ratchet']['allow_legacy_debt'] = False
        result = acceptance.evaluate(base, head, policy)
        self.assertEqual(result['aggregate']['state'], 'fail')
        self.assertEqual(result['debt_ledger'][0]['record']['ratchet']['debt'], 'unchanged')


if __name__ == '__main__':
    unittest.main()
