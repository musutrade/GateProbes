"""Incomplete or tampered acceptance reports cannot satisfy the publication gate."""
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools/release'))
import accept_importer_podman as acceptance


def report():
    rows = []
    for i, case in enumerate(acceptance.CASES):
        rows.append({'case': case, 'passed': True,
                     'exit': 0 if i < 2 else 2 if case in acceptance.PARSE_ERRORS else 1,
                     'connections': 3 if i < 2 else 0, 'files_created': [], 'stderr_empty': True,
                     'stdout_sha256': acceptance.digest(b''),
                     'descriptor_path': '/private/installed/installation.json',
                     'descriptor_mode': 0o400, 'descriptor_sha256': 'a' * 64,
                     'routes': [['GET', '/v6.1.4/libpod/info'], ['GET', '/v6.1.4/libpod/images/' + 'b' * 64 + '/json'], ['GET', '/v6.1.4/libpod/info']] if i < 2 else []})
    runtime = acceptance.RUNTIME_0_5
    return {'schema': 'gateprobes-importer-podman-acceptance/v1',
            'runtime_tag': runtime['tag'], 'runtime_version': runtime['version'],
            'core_version': acceptance.CORE_VERSION, 'core_sha256': acceptance.EXPECTED['sha256'],
            'importer_archive_sha256': acceptance.digest(b'archive'),
            'importer_sbom_sha256': acceptance.digest(b'sbom'), 'passed': len(rows), 'cases': rows}


class PodmanReport(unittest.TestCase):
    def test_historical_fixtures_are_pinned_and_exact(self):
        import hashlib
        import inspect
        self.assertEqual(acceptance.FIXTURE_VERSION, '0.2.0')
        self.assertEqual(
            hashlib.sha256(acceptance.FIXTURE_PATH.read_bytes()).hexdigest(),
            acceptance.FIXTURE_SHA256,
        )
        self.assertEqual(acceptance.fixture.PREFIX, 'gateprobes-podman-lifecycle-0.2.0-linux-amd64')
        self.assertEqual(acceptance.fixture.CORE_SHA, '6890e4465c9d86f53cffe8c58103a650babd03db895e27ae99928659c4f1d1d6')
        self.assertIn("'version': '0.2.0'", inspect.getsource(acceptance.fixture.run_case))
        old_record, old = acceptance.load_fixture('0.1.0')
        self.assertEqual(hashlib.sha256(old_record['path'].read_bytes()).hexdigest(), old_record['sha256'])
        self.assertEqual(old.PREFIX, 'gateprobes-podman-lifecycle-0.1.0-linux-amd64')
        self.assertEqual(old.CORE_SHA, '912a65b17353226becf955de8e74a9c4b7389bf5b273c9a935c6fd68797b18f2')

    def test_identity_bound_to_both_assets_and_core(self):
        value = report()
        acceptance.verify_report(value, b'archive', b'sbom')
        for field in ('schema', 'runtime_tag', 'runtime_version', 'core_version', 'core_sha256', 'importer_archive_sha256', 'importer_sbom_sha256', 'passed'):
            bad = copy.deepcopy(value); bad[field] = 'wrong'
            with self.subTest(field=field), self.assertRaises(ValueError):
                acceptance.verify_report(bad, b'archive', b'sbom')

    def test_missing_reordered_and_duplicated_cases_fail(self):
        for rows in (report()['cases'][:-1], list(reversed(report()['cases'])), [report()['cases'][0]] * 21):
            bad = report(); bad['cases'] = rows
            with self.assertRaises(ValueError): acceptance.verify_report(bad, b'archive', b'sbom')

    def test_negative_effects_and_false_pass_fail(self):
        for field, value in [('connections', 1), ('routes', [['POST', '/create']]),
                             ('stdout_sha256', acceptance.digest(b'leaked')), ('files_created', ['plan']),
                             ('descriptor_mode', 0o600), ('descriptor_path', '/tmp/installation.json'),
                             ('passed', False), ('exit', 0)]:
            bad = report(); bad['cases'][2][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                acceptance.verify_report(bad, b'archive', b'sbom')
