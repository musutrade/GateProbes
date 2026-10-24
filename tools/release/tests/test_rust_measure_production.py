import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools/release'))
sys.path.insert(0, str(ROOT / 'plugins/rust-measure'))
import rust_measure_production as production


class RustMeasureProductionTests(unittest.TestCase):
    def test_fixed_production_core_and_release_are_exact(self):
        core = production.load_core_pin()
        self.assertEqual(core['source_commit'], '6ec99b8f56477ce1b79a12a16e93f745eee6bb42')
        self.assertEqual(core['files']['tools/quality/source_measure.py'],
                         'e9021ad820daf04749f84e321eb0f0466925d097702ca85e43e1e712046720d7')
        self.assertEqual(core['files']['tools/quality/tests/rust_measure_candidate_acceptance.py'],
                         '445f669cf5bf07df783bcfd12f4587565bf6c01891711246fbe3b6421ab25382')
        self.assertIn(core['acceptance'], core['files'])
        release = production.load_release_pin()
        self.assertEqual(release['release'], 'rust-measure-v0.4.0')
        self.assertEqual(release['sha256'],
                         'd3015acd152dfcc8ac53ee1aa653454aa51244a94ca97645bccf6cd2db6bf126')
        self.assertEqual(release['binary_sha256'],
                         '8770863b6e051f42428babac48fb04e58a688b29a32ae233a8cb1faf7b2ac0f2')
        self.assertEqual(release['source_commit'],
                         'd47afd65254f310f3f34c2bb548773eb9f31b121')

    def test_missing_and_mismatched_core_files_fail(self):
        pin = production.load_core_pin()
        name = pin['acceptance']
        one_file = dict(pin, files={name: pin['files'][name]})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                production.verify_core(root, one_file)
            path.unlink()
            with self.assertRaisesRegex(ValueError, 'missing production Core file'):
                production.verify_core(root, one_file)

    def test_missing_and_mismatched_release_binary_fail(self):
        pin = production.load_release_pin()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, 'missing released measurer binary'):
                production.verify_release_binary(root / 'missing', pin)
            binary = root / 'harness-gate-rust-measure'
            binary.write_text('not the published binary')
            (root / 'plugin.json').write_text(json.dumps({
                'analyzer': pin['analyzer'], 'version': pin['version'], 'rule': pin['rule']}))
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                production.verify_release_binary(binary, pin)

    def test_release_identity_and_archive_fail_closed(self):
        pin = production.load_release_pin()
        cases = {'release': 'latest', 'asset': '../asset.tar.gz',
                 'source_commit': 'main', 'certificate_identity': 'https://github.com/evil/repo',
                 'sha256': '0', 'binary_sha256': '0'}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'pin.json'
            for key, value in cases.items():
                with self.subTest(key=key):
                    path.write_text(json.dumps({**pin, key: value}))
                    with self.assertRaises(ValueError):
                        production.load_release_pin(path)

    def test_production_acceptance_rejects_incomplete_or_tampered_output(self):
        from production_contract import check_acceptance
        good = {
            'consumer': {'analyzer': 'harness-gate-rust-measure', 'version': '0.4.0',
                         'rule': 'mccabe-rust-3'},
            'series': {'analyzer': 'harness-gate-rust-measure/0.4.0'},
            'symbols': ['included', 'nested', 'plain'],
            'excluded': [[3, 1, 4, 17]],
            'legacy_rejected': True,
            'mutated_span_rejected': True,
            'invalid_identities_rejected': 4,
        }
        check_acceptance(good)
        for key, value in (
            ('consumer', {'analyzer': 'harness-gate-rust-measure', 'version': '0.3.1',
                          'rule': 'mccabe-rust-3'}),
            ('series', {'analyzer': 'harness-gate-rust-measure/0.3.1'}),
            ('symbols', ['plain']),
            ('excluded', [[9, 9, 9, 9]]),
            ('legacy_rejected', False),
            ('mutated_span_rejected', False),
            ('invalid_identities_rejected', 3),
        ):
            with self.subTest(key=key), self.assertRaises(SystemExit):
                check_acceptance({**good, key: value})


if __name__ == '__main__':
    unittest.main()
