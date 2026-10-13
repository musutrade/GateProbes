"""GH-131: real retained frontend evidence through the generic collector boundary."""
import copy
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collector_runner as runner
import harness_evidence as evidence
import project_model as model
import typescript_reference as adapter
import typescript_semantics as ts

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'fixtures/typescript-angular'


class TypeScriptCollectorTests(unittest.TestCase):
    native_directory = FIXTURE / 'evidence'
    semantics_directory = FIXTURE / 'semantics'

    @classmethod
    def setUpClass(cls):
        cls.native = (cls.native_directory / 'native.tar.gz').read_bytes()
        cls.index = (cls.semantics_directory / 'source-index.json').read_bytes()
        cls.receipt = evidence.load_json(cls.semantics_directory / 'receipt.json')
        with tarfile.open(fileobj=io.BytesIO(cls.native), mode='r:gz') as archive:
            cls.files = {m.name: archive.extractfile(m).read() for m in archive.getmembers()}
        cls.manifest = json.loads(cls.files['manifest.json'])
        sources = {p.removeprefix('sources/app/'): data for p, data in cls.files.items()
                   if p.startswith('sources/app/src/')}
        cls.bundle = ts.read_bundle(cls.native, cls.index, cls.receipt, sources)

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.workspace, self.output = self.root / 'workspace', self.root / 'output'
        self.output.mkdir()
        for name, data in self.files.items():
            if name.startswith('sources/'):
                path = self.workspace / name.removeprefix('sources/')
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        (self.workspace / 'native.tar.gz').write_bytes(self.native)
        (self.workspace / 'index.json').write_bytes(self.index)
        subjects = []
        for path in ('src/app/pricing.ts', 'src/app/standard-quote.ts',
                     'src/app/priority-quote.ts', 'src/app/app.routes.ts', 'src/app/quote-client.ts'):
            subjects.extend(row['subject'] for row in self.bundle.measure(path))
        route = ts.source_subject('typescript-reference', 'src/app/app.routes.ts',
                                  self.bundle.index['src/app/app.routes.ts'], None,
                                  'node-jsdom', 'production-ts')
        route.update(kind='route/v1', discriminator='angular-route:details')
        route['id'] = model.subject_id('typescript-reference', route)
        subjects.append(route)
        for path in ('src/app/app.ts', 'src/app/generated/models/Quote.ts'):
            subjects.append(ts.source_subject('typescript-reference', path, self.bundle.index[path],
                                              None, 'node-jsdom', 'production-ts'))
        self.project = {'schema': 'harness-project/v1', 'id': 'typescript-reference',
                        'metadata': {}, 'relationships': [], 'subjects': subjects,
                        'components': [{'id': 'typescript', 'path': 'app', 'metadata': {},
                                        'targets': [{'id': 'node-jsdom', 'boundaries': ['production-ts'],
                                                     'metadata': {}}],
                                        'source_boundaries': [{'id': 'production-ts', 'path': 'app/src',
                                                               'role': 'production', 'metadata': {}}]}]}
        self.request = {'schema': 'harness-collector-request/v1', 'project': self.project['id'],
                        'component': 'typescript', 'collector': adapter.COLLECTOR,
                        'context': {'commit': 'a' * 40, 'base_commit': 'b' * 40,
                                    'target': 'node-jsdom', 'run': 'gh131-retained-replay'},
                        'requested_capabilities': list(evidence.METRIC_TYPES),
                        'workspace_root': str(self.workspace), 'output_root': str(self.output),
                        'parameters': {'native': 'native.tar.gz', 'index': 'index.json',
                                       'subjects': copy.deepcopy(subjects)}}
        self.request['parameters']['receipt'] = {
            **self.receipt, 'schema': 'typescript-collector-replay/v1',
            'native_revision': self.manifest['revision'], 'request': copy.deepcopy(adapter.binding(self.request))}

    def run_adapter(self, transport=None):
        return runner.run_collector(transport or runner.InternalAdapter(adapter.collect),
                                    self.request, project=self.project)

    def reset_output(self):
        shutil.rmtree(self.output)
        self.output.mkdir()

    def assert_failure(self, code, transport=None):
        with self.assertRaises(runner.CollectionError) as caught:
            self.run_adapter(transport)
        self.assertEqual(caught.exception.code, code)

    def rebind(self):
        self.request['parameters']['receipt']['request'] = copy.deepcopy(adapter.binding(self.request))

    def rewrite_native(self, mutate):
        files = dict(self.files)
        manifest = json.loads(files['manifest.json'])
        mutate(files, manifest)
        files['manifest.json'] = json.dumps(manifest).encode()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            for path, data in files.items():
                member = tarfile.TarInfo(path)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        data = buffer.getvalue()
        (self.workspace / 'native.tar.gz').write_bytes(data)
        self.request['parameters']['receipt']['native_sha256'] = ts.digest(data)

    def test_real_mixed_subjects_and_all_capabilities_through_both_transports(self):
        internal = self.run_adapter()
        self.reset_output()
        external = self.run_adapter(runner.SubprocessAdapter(
            (sys.executable, str(ROOT / 'typescript_reference.py')), timeout_seconds=10))
        self.assertEqual(internal, external)
        self.assertEqual({r['subject']['id'] for r in internal},
                         {s['id'] for s in self.project['subjects']})
        self.assertTrue({'file/v1', 'method/v1', 'function/v1', 'route/v1'} <=
                        {r['subject']['kind'] for r in internal})
        for record in internal:
            self.assertEqual({c['metric'] for c in record['capabilities']}, set(evidence.METRIC_TYPES))
            for capability in record['capabilities']:
                self.assertEqual(capability['state'] == 'supported',
                                 capability['metric'] in {m['name'] for m in record['metrics']})
            if record['subject']['kind'] == 'route/v1':
                self.assertEqual(record['status'], 'unavailable')
                self.assertEqual(record['metrics'], [])
            self.assertNotIn('decision', record)
        pricing = next(r for r in internal if r['subject']['path'] == 'app/src/app/pricing.ts'
                       and r['subject']['kind'] == 'file/v1')
        self.assertEqual(next(m['value'] for m in pricing['metrics'] if m['name'] == 'coverage.line'),
                         {'type': 'ratio', 'covered': 4, 'total': 6})
        golden = evidence.load_json(self.semantics_directory / 'native-counters.json')
        for path, scopes in golden['files'].items():
            rows = [r for r in internal if r['subject']['path'] == 'app/' + path
                    and r['subject']['kind'] != 'route/v1']
            self.assertEqual(len(rows), len(scopes))
            for row, scope in zip(rows, scopes):
                values = {m['name']: m['value'] for m in row['metrics']}
                for metric, native in [('coverage.line', 'lines'), ('coverage.function', 'functions')]:
                    self.assertEqual(values[metric], {'type': 'ratio', **scope[native]})
        for record in internal:
            if record['subject']['path'] in ('app/src/app/app.ts', 'app/src/app/generated/models/Quote.ts'):
                self.assertEqual(record['status'], 'unavailable')
                self.assertEqual({c['state'] for c in record['capabilities']}, {'unsupported'})

    def test_crap_is_explicitly_unsupported_with_no_invented_value_or_series(self):
        self.request['requested_capabilities'] = ['risk.crap']
        self.rebind()
        for record in self.run_adapter():
            crap = next(c for c in record['capabilities'] if c['metric'] == 'risk.crap')
            self.assertEqual(crap['state'], 'unsupported')
            self.assertNotIn('risk.crap', {m['name'] for m in record['metrics']})
            self.assertEqual(record['series'], ts.measurement_series(
                self.bundle.toolchain, record['subject']['target'], record['subject']['boundary']))

    def test_single_capability_request_preserves_existing_measurement_series(self):
        self.request['requested_capabilities'] = ['coverage.line']
        self.rebind()
        for record in self.run_adapter():
            self.assertEqual(record['series'], ts.measurement_series(
                self.bundle.toolchain, record['subject']['target'], record['subject']['boundary']))

    def test_rebound_unknown_method_identity_and_duplicate_scope_fail_closed(self):
        original = copy.deepcopy(self.request)
        subject = self.request['parameters']['subjects'][0]
        subject['discriminator'] = 'fabricated-source-identity'
        subject['id'] = model.subject_id(self.project['id'], subject)
        self.rebind()
        self.assert_failure('measurement_error')
        self.request = original
        self.request['parameters']['subjects'].append(self.request['parameters']['subjects'][0])
        self.rebind()
        self.assert_failure('measurement_error')

    def test_zero_denominator_remains_explicitly_unavailable(self):
        def mutate(files, manifest):
            name = next(n for n in files if n.endswith('/coverage-final.json'))
            coverage = json.loads(files[name])
            row = next(r for p, r in coverage.items() if p.endswith('/pricing.ts'))
            row['statementMap'], row['s'] = {}, {}
            files[name] = json.dumps(coverage).encode()
            manifest['artifacts'][name].update(sha256=ts.digest(files[name]), bytes=len(files[name]))
        self.rewrite_native(mutate)
        for record in self.run_adapter():
            if record['subject']['path'] == 'app/src/app/pricing.ts':
                capability = next(c for c in record['capabilities'] if c['metric'] == 'coverage.line')
                self.assertEqual(capability['state'], 'not_applicable')
                self.assertNotIn('coverage.line', {m['name'] for m in record['metrics']})

    def test_request_contract_rejects_unknown_duplicate_or_scoped_capabilities(self):
        for capabilities in (['invented'], ['coverage.line'] * 2,
                             [{'kind': 'method/v1', 'metric': 'coverage.line'}], []):
            with self.subTest(capabilities=capabilities):
                self.request['requested_capabilities'] = capabilities
                self.assert_failure('invalid_request')

    def test_replay_binding_rejects_changed_context_collector_and_scope(self):
        original = copy.deepcopy(self.request)
        for key in ('commit', 'base_commit', 'target', 'run', 'collector', 'scope', 'revision'):
            with self.subTest(key=key):
                self.request = copy.deepcopy(original)
                if key in self.request['context']:
                    self.request['parameters']['receipt']['request']['context'][key] = 'stale'
                elif key == 'collector':
                    self.request['collector'] = {'name': 'typescript-reference', 'version': '2'}
                elif key == 'scope':
                    self.request['parameters']['subjects'].pop()
                else:
                    self.request['parameters']['receipt']['native_revision'] = '0' * 40
                self.assert_failure('measurement_error')

    def test_input_tampering_staleness_malformed_parser_and_path_escape(self):
        for case in ('native', 'index', 'source', 'configuration', 'malformed', 'escape'):
            with self.subTest(case=case):
                if case == 'escape':
                    self.request['parameters']['native'] = '../native.tar.gz'
                    self.assert_failure('measurement_error')
                    continue
                name = {'native': 'native.tar.gz', 'index': 'index.json', 'malformed': 'index.json',
                        'source': 'app/src/app/pricing.ts', 'configuration': 'app/angular.json'}[case]
                path = self.workspace / name
                before = path.read_bytes()
                path.write_bytes(b'{' if case == 'malformed' else before + b'\n')
                if case == 'malformed':
                    self.request['parameters']['receipt']['index_sha256'] = ts.digest(b'{')
                self.assert_failure('measurement_error')
                path.write_bytes(before)
                self.request['parameters']['receipt']['index_sha256'] = self.receipt['index_sha256']

    def test_failed_tool_incomplete_collection_and_undeclared_native_artifact(self):
        mutations = [lambda files, manifest: manifest['commands'][0].update(exit_status=1),
                     lambda files, manifest: manifest.update(status='partial'),
                     lambda files, manifest: files.update({'undeclared.txt': b'bad'})]
        for mutate in mutations:
            self.rewrite_native(mutate)
            self.assert_failure('measurement_error')

    def test_receipted_source_map_failure(self):
        def mutate(files, manifest):
            name = self.bundle.maps_for('src/app/pricing.ts')[0]
            value = json.loads(files[name])
            value['sourcesContent'][0] += '\n'
            files[name] = json.dumps(value).encode()
            manifest['artifacts'][name].update(sha256=ts.digest(files[name]), bytes=len(files[name]))
        self.rewrite_native(mutate)
        self.assert_failure('measurement_error')

    def test_response_omission_tampering_undeclared_artifact_and_provenance(self):
        for case, code in [('omission', 'missing_capability'), ('tampering', 'artifact_tampering'),
                           ('undeclared', 'undeclared_artifact'), ('provenance', 'invalid_evidence'),
                           ('stale', 'stale_context'), ('decision', 'invalid_response')]:
            def corrupt(request):
                response = adapter.collect(request)
                record = response['evidence'][0]
                if case == 'omission':
                    record['capabilities'].pop()
                elif case == 'tampering':
                    (self.output / record['artifacts'][0]['path']).write_bytes(b'bad')
                elif case == 'undeclared':
                    (self.output / 'extra').write_text('bad')
                elif case == 'provenance':
                    record['artifacts'][0]['context'] = {**request['context'], 'run': 'stale'}
                elif case == 'stale':
                    record['context'] = {**request['context'], 'run': 'stale'}
                else:
                    response['decision'] = 'pass'
                return response
            with self.subTest(case=case):
                self.assert_failure(code, runner.InternalAdapter(corrupt))
                self.reset_output()

    def test_nonzero_exit_timeout_and_malformed_stdout_fail_closed(self):
        run = f'import runpy; runpy.run_path({str(ROOT / "typescript_reference.py")!r}, run_name="__main__")'
        for script, deadline, code in [(run + '; sys.exit(7)', 10, 'subprocess_exit'),
                                       ('import time; time.sleep(30); ' + run, 0.1, 'timeout'),
                                       (run + '; print("extra")', 10, 'malformed_json')]:
            with self.subTest(code=code):
                self.assert_failure(code, runner.SubprocessAdapter((sys.executable, '-c',
                    f'import sys; sys.path.insert(0, {str(ROOT)!r}); ' + script), deadline))
                self.reset_output()


if __name__ == '__main__':
    unittest.main()
