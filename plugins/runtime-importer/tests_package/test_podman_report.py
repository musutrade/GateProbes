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
                     'routes': [['GET', '/v6.1.4/libpod/info'], ['GET', '/v6.1.4/libpod/images/' + 'b' * 64 + '/json'], ['GET', '/v6.1.4/libpod/info']] if i < 2 else []})
    return {'schema': 'gateprobes-importer-podman-acceptance/v1', 'core_sha256': acceptance.EXPECTED['sha256'],
            'importer_archive_sha256': acceptance.digest(b'archive'),
            'importer_sbom_sha256': acceptance.digest(b'sbom'), 'passed': len(rows), 'cases': rows}


class PodmanReport(unittest.TestCase):
    def test_identity_bound_to_both_assets_and_core(self):
        value = report()
        acceptance.verify_report(value, b'archive', b'sbom')
        for field in ('schema', 'core_sha256', 'importer_archive_sha256', 'importer_sbom_sha256', 'passed'):
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
                             ('passed', False), ('exit', 0)]:
            bad = report(); bad['cases'][2][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                acceptance.verify_report(bad, b'archive', b'sbom')
