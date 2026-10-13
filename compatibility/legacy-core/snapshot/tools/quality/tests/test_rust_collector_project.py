"""Generic transport tests; synthetic reports do not certify a delivery tuple."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

QUALITY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(QUALITY))
import harness_evidence as evidence
import project_model as model
import rust_collector_entry as entry
import rust_collector_project as adapter
import rust_native_driver as native


def binding_for(report, source_root, output, collector_version='0.0.0-test'):
    """Test preparation only: a real host must independently approve this input."""
    collector = {'name': 'harness-gate-rust-collector', 'version': collector_version}
    context = {'target': 'native', 'run': 'project-test', 'commit': 'a' * 40, 'base_commit': 'b' * 40}
    project = {'schema': 'harness-project/v1', 'id': 'native-test', 'metadata': {}, 'relationships': [],
               'components': [{'id': 'rust', 'path': '.', 'metadata': {},
                               'targets': [{'id': 'native', 'boundaries': ['production'], 'metadata': {}}],
                               'source_boundaries': [{'id': 'production', 'path': '.', 'role': 'production',
                                                      'metadata': {}}]}], 'subjects': []}
    sources = {p['relative']: p['sha256'] for p in report['source_inventory']}
    for function in report['functions']:
        subject = {'id': 'subject-identity/v1:' + '0' * 64, 'identity_version': 'subject-identity/v1',
                   'component': 'rust', 'target': 'native', 'boundary': 'production', 'kind': 'function/v1',
                   'path': function['source_lines'][0][0], 'discriminator': adapter.fingerprint(function['owner']),
                   'metadata': {}}
        subject['source_sha256'] = sources[subject['path']]
        subject['id'] = model.subject_id(project['id'], subject)
        project['subjects'].append(subject)
    identity = adapter.measurement_identity(report)
    metrics = {'coverage.line': 'ratio', 'coverage.function': 'ratio', 'coverage.region': 'ratio',
               'complexity.cyclomatic': 'count', 'risk.crap': 'rational'}
    series = {'name': 'native-project-test', 'collector': collector,
              'tool': {'name': 'native-toolchain', 'version': adapter.fingerprint(report['tools'])},
              'rule': {'name': 'native-project', 'version': adapter.fingerprint(identity)},
              'runtime': {'name': 'rustc', 'version': native.RUSTC_COMMIT},
              'source_identity': {'name': 'rustc-def-path-hash-expansion', 'version': '1'},
              'normalization': {'name': 'native-project', 'version': identity['projection_sha256']},
              'target': 'native', 'metrics': [{'name': m, 'type': t} for m, t in sorted(metrics.items())]}
    series['id'] = evidence.series_id(series)
    inner = {'schema': 'harness-project-collector-request/v1', 'project': project['id'], 'collector': collector,
             'context': context, 'workspace_root': str(source_root), 'output_root': str(output),
             'selection': {}, 'bindings': [{'subject': s['id'], 'capability': m, 'series': series['id']}
                                          for s in project['subjects'] for m in sorted(metrics)]}
    return {'schema': 'rust-project-collector-binding/v1', 'input': inner, 'invocation_id': 'project-test',
            'config_digest': 'c' * 64, 'capture': {'path': str(source_root), 'anchor': report['artifact_anchor']},
            'project': project, 'series': series, 'native_identity': identity,
            'capabilities': [{'metric': m, 'state': 'supported', 'reason': 'native counters'} for m in sorted(metrics)]}


def request_for(binding, path):
    path.write_text(json.dumps(binding))
    digest = native.file_hash(path)
    request = {'protocol_version': 2, 'result_schema_version': '1',
               'adapter': binding['input']['collector'] | {'executable': '/synthetic/collector',
                           'source_digest': '0' * 64,
                           'signature': {'algorithm': 'synthetic', 'key_id': 'test', 'value': 'unsigned-test'}},
               'invocation_id': binding['invocation_id'], 'step_id': 'native', 'timeout_ms': 1000,
               'config_digest': binding['config_digest'], 'artifact_root': binding['input']['output_root'],
               'nonce': 'synthetic-nonce', 'issued_at_ms': 1, 'expires_at_ms': 1000,
               'args': ['collect', '--binding', str(path), '--binding-sha256', digest],
               'environment': {}, 'capabilities': {'network': [], 'resources': [], 'environment': []},
               'input': copy.deepcopy(binding['input'])}
    return request, digest


class ProjectTransportTests(unittest.TestCase):
    def test_repository_relative_package_prefix_is_pinned_and_checked(self):
        package = self.root / 'apps/server'
        package.mkdir(parents=True)
        (package / 'fixture.rs').write_bytes((self.root / 'fixture.rs').read_bytes())
        binding = copy.deepcopy(self.binding)
        binding['source_prefix'] = 'apps/server'
        subject = binding['project']['subjects'][0]
        subject['path'] = 'apps/server/fixture.rs'
        subject['id'] = model.subject_id(binding['project']['id'], subject)
        for claim in binding['input']['bindings']:
            claim['subject'] = subject['id']
        response = adapter.project_report(self.report, binding)
        record = response['collection']['evidence'][0]
        self.assertEqual(record['source']['path'], 'apps/server/fixture.rs')
        raw = json.loads((self.output / record['artifacts'][0]['path']).read_text())
        self.assertEqual(raw['source_prefix'], 'apps/server')
        for prefix in ('../apps', '/apps', 'apps//server', 'apps/./server', 'apps\\server'):
            binding['source_prefix'] = prefix
            with self.assertRaisesRegex(ValueError, 'invalid package source prefix'):
                adapter.project_report(self.report, binding)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        source = self.root / 'fixture.rs'
        source.write_text('fn selected() {}\n')
        self.output = self.root / 'output'
        self.output.mkdir()
        self.report = {'series': native.SERIES, 'scope': 'synthetic',
                       'tools': {'rustc': {'version': 'synthetic rustc\nmultiline version'}}, 'flags': [], 'cfg': [],
                       'build_inputs': [], 'adapter_sha256': 'a' * 64, 'artifact_anchor': 'b' * 64,
                       'mapping_complete_for_declared_scope': True, 'passed': False,
                       'source_inventory': [{'relative': 'fixture.rs', 'sha256': native.file_hash(source)}],
                       'functions': [{'owner': 'synthetic-selected', 'source_lines': [['fixture.rs', 1]],
                                      'lines': {'covered': 0, 'count': 1}, 'regions': {'covered': 0, 'count': 1},
                                      'blocks': [0], 'cc': 7, 'crap': 56.0, 'crap_exact': [56, 1], 'passed': False}]}
        self.binding = binding_for(self.report, self.root, self.output)
        self.path = self.root / 'binding.json'
        self.request, self.digest = request_for(self.binding, self.path)

    def test_low_coverage_is_transport_completion_with_exact_facts(self):
        binding = adapter.load_binding(self.request, self.path, self.digest)
        response = adapter.project_report(self.report, binding)
        self.assertEqual(response['status'], 'PASS')
        record = response['collection']['evidence'][0]
        values = {m['name']: m['value'] for m in record['metrics']}
        self.assertEqual(values['risk.crap'], {'type': 'rational', 'numerator': 56, 'denominator': 1})
        self.assertEqual(values['coverage.line'], {'type': 'ratio', 'covered': 0, 'total': 1})
        raw = json.loads((self.output / record['artifacts'][0]['path']).read_text())
        self.assertNotIn('passed', raw)
        self.assertNotIn('passed', raw['functions'][0])
        self.assertEqual(raw['tools'], self.report['tools'])
        self.assertEqual(raw['functions'][0]['crap'], 56.0)
        self.assertFalse(self.report['passed'])  # Original report is unchanged.

    def test_owner_artifacts_do_not_repeat_unrelated_report_inventory(self):
        report = copy.deepcopy(self.report)
        second = copy.deepcopy(report['functions'][0])
        second['owner'] = 'another-owner'
        report['functions'].append(second)
        report['exclusions'] = [{'diagnostic': 'x' * 100000}]
        report['definition_inventory'] = [{'diagnostic': 'y' * 100000}]
        binding = binding_for(report, self.root, self.output)
        response = adapter.project_report(report, binding)
        self.assertLess(sum(a['bytes'] for a in response['artifacts']), 20000)
        owners = []
        for artifact in response['artifacts']:
            raw = json.loads((self.output / artifact['path']).read_text())
            self.assertEqual(raw['schema'], 'rust-native-owner-artifact/v1')
            self.assertEqual(raw['native_report_sha256'], adapter.fingerprint(report))
            self.assertEqual(raw['artifact_anchor'], report['artifact_anchor'])
            self.assertEqual(raw['native_identity'], adapter.measurement_identity(report))
            self.assertEqual(len(raw['functions']), 1)
            owners.append(raw['functions'][0]['owner'])
            self.assertNotIn('exclusions', raw)
            self.assertNotIn('definition_inventory', raw)
        self.assertEqual(set(owners), {'synthetic-selected', 'another-owner'})
        self.assertEqual(len(report['exclusions'][0]['diagnostic']), 100000)

    def test_capability_states_never_become_zero_values(self):
        for state in ('unsupported', 'not_configured', 'not_collected', 'not_applicable', 'measurement_error'):
            with self.subTest(state=state):
                output = self.root / state
                output.mkdir()
                binding = copy.deepcopy(self.binding)
                binding['input']['output_root'] = str(output)
                for capability in binding['capabilities']:
                    capability['state'] = state
                response = adapter.project_report(self.report, binding)
                record = response['collection']['evidence'][0]
                self.assertEqual(record['metrics'], [])
                self.assertEqual({c['state'] for c in record['capabilities']}, {state})
                self.assertEqual(record['status'], 'measurement_error' if state == 'measurement_error' else 'unavailable')

    def test_binding_tamper_stale_context_claims_and_signed_args(self):
        mutations = [lambda r: r['input']['context'].update(commit='f' * 40),
                     lambda r: r['input']['bindings'].append(copy.deepcopy(r['input']['bindings'][0])),
                     lambda r: r['input']['bindings'].pop(), lambda r: r['args'].append('--fallback'),
                     lambda r: r.update(invocation_id='another-run'), lambda r: r.update(protocol_version=True),
                     lambda r: r.update(final_outcome='PASS')]
        for mutate in mutations:
            request = copy.deepcopy(self.request)
            mutate(request)
            with self.subTest(request=request), self.assertRaises(ValueError):
                adapter.load_binding(request, self.path, self.digest)
        self.path.write_text(self.path.read_text() + ' ')
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            adapter.load_binding(self.request, self.path, self.digest)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_missing_owner_wrong_identity_and_stale_source_write_no_artifacts(self):
        for mutate in (lambda r: r.update(functions=[]), lambda r: r.update(adapter_sha256='f' * 64),
                       lambda r: r.update(artifact_anchor='f' * 64),
                       lambda r: r['source_inventory'][0].update(sha256='f' * 64)):
            damaged = copy.deepcopy(self.report)
            mutate(damaged)
            with self.subTest(report=damaged), self.assertRaises(ValueError):
                adapter.project_report(damaged, self.binding)
            self.assertEqual(list(self.output.iterdir()), [])

    def test_unknown_delivery_tuple_has_no_native_launch_or_fallback(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, 'argv', ['collector', *self.request['args']]), \
             patch.object(sys, 'stdin', io.StringIO(json.dumps(self.request))), \
             patch.object(entry, 'doctor', return_value={}), \
             patch.object(native, 'certify') as certify, patch.object(native, 'run') as run, \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(entry.main(), 1)
        certify.assert_not_called()
        run.assert_not_called()
        response = json.loads(stdout.getvalue())
        self.assertEqual(response['collection']['schema'], 'harness-project-collector-response/v1')
        self.assertEqual(response['collection']['evidence'], [])
        self.assertEqual(response['status'], 'FAIL')
        self.assertIn('unknown tested Core/protocol/ABI', response['collection']['error'])
        self.assertEqual(list(self.output.iterdir()), [])

    def test_runtime_failure_preserves_generic_error_envelope_without_producers(self):
        for message in ('unsupported host ABI', 'missing/modified private runtime: bin/llvm-cov'):
            with self.subTest(message=message):
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(sys, 'argv', ['collector', *self.request['args']]), \
                     patch.object(sys, 'stdin', io.StringIO(json.dumps(self.request))), \
                     patch.object(entry, 'doctor', side_effect=ValueError(message)), \
                     patch.object(native, 'certify') as certify, patch.object(native, 'run') as run, \
                     contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    self.assertEqual(entry.main(), 1)
                certify.assert_not_called()
                run.assert_not_called()
                self.assertEqual(json.loads(stdout.getvalue()), {
                    'schema_version': '1', 'status': 'FAIL',
                    'invocation_id': self.request['invocation_id'], 'artifacts': [],
                    'collection': {'schema': 'harness-project-collector-response/v1',
                                   'evidence': [], 'error': message}})
                self.assertEqual(list(self.output.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
