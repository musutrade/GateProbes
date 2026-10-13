"""Synthetic contract tests, explicitly not native capture/ABI certification."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

QUALITY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(QUALITY))
import collector_runner as runner
import harness_evidence as evidence
import rust_collector_contract as contract
import rust_native_driver as native

spec = importlib.util.spec_from_file_location('delivery_synthetic', QUALITY / 'fixtures/collectors/synthetic.py')
synthetic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(synthetic)


def fixture():
    """Invented test-only identities must never enter the shipped tested matrix."""
    sha = 'a' * 64
    tools = [{'name': name, 'path': 'bin/' + name, 'sha256': sha, 'version': 'synthetic'}
             for name in ('driver', 'rustc', 'rustc-driver-library', 'llvm-cov', 'llvm-profdata', 'python')]
    protocol = {'request': 'harness-collector-request/v1', 'response': 'harness-collector-response/v1',
                'evidence': 'harness-evidence/v1', 'project_request': 'harness-project-collector-request/v1',
                'project_response': 'harness-project-collector-response/v1', 'adapter_result_schema_version': '1'}
    abi = {'target': 'x86_64-unknown-linux-gnu', 'glibc': 'synthetic', 'kernel': 'synthetic',
           'runtime_dependencies_sha256': sha}
    measurement = {'native_series': native.SERIES, 'normalized_series': ['measurement-series/v1:' + sha],
                   'compiler_commit': 'b' * 40, 'llvm_version': 'synthetic',
                   'compiler_inventory_schema': 'synthetic', 'adapter_sha256': sha,
                   'projection_sha256': sha, 'classifier_sha256': sha, 'normalization': 'synthetic',
                   'configuration_sha256': sha, 'source_boundary': 'synthetic fixture only'}
    manifest = {'schema': 'rust-collector-delivery/v1',
                'collector': {'name': 'harness-gate-rust-collector', 'version': '0.0.0-test'},
                'source_commit': 'b' * 40, 'protocol': protocol, 'host_abi': abi,
                'payloads': [{'path': t['path'], 'sha256': sha, 'role': 'tool'} for t in tools],
                'tools': tools, 'measurement': measurement,
                'capabilities': [{'metric': 'coverage.line', 'state': 'supported',
                                  'scope': 'synthetic fixture only', 'reason': 'contract test'}],
                'dependency_inventory_sha256': sha, 'license_inventory_sha256': sha}
    observed = {'core': {'version': '0.0.0-test', 'commit': 'b' * 40, 'sha256': sha},
                'host_abi': copy.deepcopy(abi), 'protocol': copy.deepcopy(protocol),
                'tools': [{k: v for k, v in t.items() if k != 'path'} for t in tools]}
    manifest['core_compatibility'] = [copy.deepcopy(observed['core'])]
    matrix = {'schema': 'rust-collector-compatibility/v1',
              'tested': [{'manifest_sha256': contract.fingerprint(manifest), 'environment': copy.deepcopy(observed),
                          'receipt': {'path': 'synthetic-receipt.json', 'sha256': sha,
                                      'kind': 'reviewed-native-capture-and-core-evaluation'}}]}
    return manifest, matrix, observed


class DeliveryManifestTests(unittest.TestCase):
    def test_host_configuration_schema_is_explicit_and_versioned(self):
        manifest, matrix, observed = fixture()
        manifest['schema'] = 'rust-collector-delivery/v2'
        measurement = manifest['measurement']
        del measurement['normalized_series']
        del measurement['configuration_sha256']
        measurement['configuration_authority'] = 'quality-trusted-state/v1'
        matrix['tested'][0]['manifest_sha256'] = contract.fingerprint(manifest)
        self.assertEqual(contract.load_manifest(json.dumps(manifest)), manifest)
        self.assertEqual(contract.preflight(manifest, matrix, observed), matrix['tested'][0]['receipt'])
        for mutate in (
            lambda m: m.update(schema='rust-collector-delivery/v3'),
            lambda m: m.update(schema='rust-collector-delivery/v1'),
            lambda m: m['measurement'].pop('configuration_authority'),
            lambda m: m['measurement'].update(configuration_authority='untrusted'),
            lambda m: m['measurement'].update(configuration_sha256='a' * 64),
            lambda m: m['measurement'].update(normalized_series=['measurement-series/v1:' + 'a' * 64]),
        ):
            damaged = copy.deepcopy(manifest)
            mutate(damaged)
            with self.subTest(manifest=damaged), self.assertRaises(contract.DeliveryError):
                contract.validate_manifest(damaged)

    def test_exact_tuple_and_empty_production_matrix(self):
        manifest, matrix, observed = fixture()
        self.assertEqual(contract.load_manifest(json.dumps(manifest)), manifest)
        self.assertEqual(contract.preflight(manifest, matrix, observed), matrix['tested'][0]['receipt'])
        production = json.loads((QUALITY / 'rust-collector-compatibility.json').read_text())
        self.assertEqual(production['tested'], [])
        with self.assertRaisesRegex(contract.DeliveryError, 'unknown'):
            contract.preflight(manifest, production, observed)

    def test_malformed_manifest(self):
        manifest, _, _ = fixture()
        for raw in ('{', '{"schema":1,"schema":2}', 'NaN', '[]'):
            with self.subTest(raw=raw), self.assertRaises(contract.DeliveryError):
                contract.load_manifest(raw)
        mutations = [lambda m: m.update(final_outcome='pass'),
                     lambda m: m.pop('measurement'),
                     lambda m: m['collector'].update(version='>=1.0.0'),
                     lambda m: m['tools'][0].update(sha256='bad'),
                     lambda m: m['tools'].pop(),
                     lambda m: m['tools'].append(m['tools'][0]),
                     lambda m: m['payloads'].append(m['payloads'][0]),
                     lambda m: m['capabilities'].append(m['capabilities'][0])]
        for mutate in mutations:
            damaged = copy.deepcopy(manifest)
            mutate(damaged)
            with self.subTest(manifest=damaged), self.assertRaises(contract.DeliveryError):
                contract.load_manifest(json.dumps(damaged))
        for path in ('../escape', '/absolute', 'a//b', 'a/./b', 'a\\b', 'C:tool'):
            damaged = copy.deepcopy(manifest)
            damaged['payloads'][0]['path'] = path
            with self.subTest(path=path), self.assertRaises(contract.DeliveryError):
                contract.validate_manifest(damaged)

    def test_unknown_combinations_and_wrong_tools_fail_before_sampling(self):
        mutations = [lambda m, o: o['core'].update(version='9.9.9'),
                     lambda m, o: o['core'].update(sha256='c' * 64),
                     lambda m, o: o['protocol'].update(request='harness-collector-request/v2'),
                     lambda m, o: o['protocol'].update(project_response='harness-project-collector-response/v2'),
                     lambda m, o: o['host_abi'].update(glibc='different'),
                     lambda m, o: o['tools'][0].update(sha256='c' * 64),
                     lambda m, o: o['tools'][0].update(version='different'),
                     lambda m, o: o['tools'].pop(),
                     lambda m, o: m['collector'].update(version='0.0.1-test'),
                     lambda m, o: m['measurement'].update(normalization='different')]
        for mutate in mutations:
            manifest, matrix, observed = fixture()
            mutate(manifest, observed)
            launched = []
            with self.subTest(mutation=mutate), self.assertRaises(contract.DeliveryError):
                contract.preflight(manifest, matrix, observed)
                launched.append('producer')
            self.assertEqual(launched, [])

    def test_receipt_required_and_duplicate_tuple_rejected(self):
        for change in ('missing', 'duplicate'):
            manifest, matrix, observed = fixture()
            if change == 'missing':
                matrix['tested'][0].pop('receipt')
            else:
                matrix['tested'].append(copy.deepcopy(matrix['tested'][0]))
            with self.assertRaises(contract.DeliveryError):
                contract.preflight(manifest, matrix, observed)

    def test_relocation_never_establishes_history_equivalence(self):
        manifest, _, _ = fixture()
        original = {'measurement': manifest['measurement'], 'tools': manifest['tools'],
                    'host_abi': manifest['host_abi'], 'flags': native.FLAGS,
                    'cfg_sha256': 'a' * 64, 'build_inputs_sha256': 'a' * 64,
                    'scope': 'synthetic', 'hotspots_sha256': 'a' * 64}
        for tool in original['tools']:
            tool['path'] = '/original/' + tool['path']
        contract.require_same_capture_identity(original, copy.deepcopy(original))
        for field in ('path', 'sha256'):
            moved = copy.deepcopy(original)
            moved['tools'][0][field] = '/relocated/bin/driver' if field == 'path' else 'c' * 64
            with self.assertRaisesRegex(contract.DeliveryError, 'reviewed series transition'):
                contract.require_same_capture_identity(original, moved)
        self.assertEqual(original['tools'][0]['path'], '/original/bin/driver')


class MeasurementContractTests(unittest.TestCase):
    def setUp(self):
        work = QUALITY.parents[1] / 'target/gh-227/contract-tests'
        work.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=work)
        self.addCleanup(self.temp.cleanup)
        self.project = evidence.load_json(QUALITY / 'fixtures/project-model/base.json')
        record = evidence.load_json(QUALITY / 'fixtures/harness-evidence/polyglot.json')[0]
        self.request = {'schema': 'harness-collector-request/v1', 'project': self.project['id'],
                        'component': record['component'], 'collector': record['collector'],
                        'context': record['context'], 'requested_capabilities': ['coverage.line', 'coverage.branch'],
                        'workspace_root': str(QUALITY / 'fixtures/project-model/sources'),
                        'output_root': self.temp.name, 'parameters': {}}

    def measure(self, adapter):
        return contract.measure(adapter, self.request, project=self.project)

    def test_low_coverage_is_complete_facts_without_verdict(self):
        def low(request):
            response = synthetic.collect(request)
            for metric in response['evidence'][0]['metrics']:
                if metric['name'] == 'coverage.line':
                    metric['value']['covered'] = 0
            return response
        result = self.measure(runner.InternalAdapter(low))
        self.assertIsInstance(result, contract.MeasurementComplete)
        metric = next(m for m in result.records[0]['metrics'] if m['name'] == 'coverage.line')
        self.assertEqual(metric['value']['covered'], 0)
        self.assertGreater(metric['value']['total'], 0)
        self.assertNotIn('passed', result.records[0])

    def test_all_capability_states_remain_distinct_without_invented_values(self):
        result = self.measure(runner.InternalAdapter(synthetic.collect))
        self.assertIsInstance(result, contract.MeasurementComplete)
        record = result.records[0]
        self.assertEqual({c['state'] for c in record['capabilities']},
                         {'supported', 'unsupported', 'not_configured', 'not_collected',
                          'not_applicable', 'measurement_error'})
        measured = {m['name'] for m in record['metrics']}
        for capability in record['capabilities']:
            if capability['state'] != 'supported':
                self.assertNotIn(capability['metric'], measured)

    def test_incomplete_and_operational_errors_never_supply_records(self):
        for scenario in ('measurement_error', 'unlisted_artifact', 'missing_capability', 'stale_commit', 'release_decision'):
            self.request['parameters'] = {'scenario': scenario}
            result = self.measure(runner.InternalAdapter(synthetic.collect))
            self.assertIsInstance(result, contract.MeasurementFailure, scenario)
            self.assertFalse(hasattr(result, 'records'))

    def test_legacy_nonzero_with_partial_json_is_not_success(self):
        for code in (1, 7):
            result = self.measure(runner.SubprocessAdapter((sys.executable, '-c',
                                  'import sys; print("{partial"); sys.exit(' + str(code) + ')')))
            self.assertIsInstance(result, contract.MeasurementFailure)
            self.assertEqual(result.code, 'subprocess_exit')

    def test_legacy_certify_exit_keeps_threshold_failure(self):
        for passed in (True, False):
            output = Path(self.temp.name) / 'legacy.json'
            with patch.object(sys, 'argv', ['rust_native_driver.py', 'certify', '--evidence', self.temp.name,
                                           '--anchor', 'a' * 64, '--output', str(output)]), \
                    patch.object(native, 'certify', return_value={'passed': passed, 'coverage': {'covered': 0}}):
                self.assertEqual(native.main(), 0 if passed else 1)
                self.assertEqual(json.loads(output.read_text())['passed'], passed)

    def test_native_missing_evidence_cannot_be_legacy_threshold_success(self):
        with self.assertRaises(OSError):
            native.certify(Path(self.temp.name), 'a' * 64)


if __name__ == '__main__':
    unittest.main()
