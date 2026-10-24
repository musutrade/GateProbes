import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rust_measure_candidate as candidate


class RustMeasureCandidateTests(unittest.TestCase):
    def test_fixed_core_and_legacy_identity_are_exact(self):
        core = candidate.load_core_pin()
        self.assertEqual(core['source_commit'], 'd76a3130a13a565643f5b9fda8f5a5f2b7d28453')
        self.assertEqual(core['files']['tools/quality/source_measure.py'],
                         'fbf82e6a3b311b175c85f9195e666b74257bdd0d11ed55c3a47dca69859a540d')
        self.assertIn(core['acceptance'], core['files'])
        legacy = candidate.load_legacy_pin()
        self.assertEqual(legacy['release'], 'rust-measure-v0.3.1')
        self.assertEqual(legacy['sha256'], '5d3130b8d6673b9e32133be88fa69e4404f1d4ecc5ae022f7abf008c9b06302f')
        self.assertEqual(legacy['binary_sha256'], 'f17ec90502005ddb161143cd5683a292fa1ccde7f4715291e0a0f82ae5b519ad')

    def test_version_route_is_explicit_and_unknown_fails(self):
        self.assertEqual(candidate.route_version('0.3.1'), 'legacy')
        self.assertEqual(candidate.route_version('0.4.0'), 'candidate')
        for version in ('0.3.0', '0.4.1', 'latest', ''):
            with self.assertRaises(ValueError):
                candidate.route_version(version)

    def test_core_hash_mismatch_and_missing_file_fail(self):
        pin = candidate.load_core_pin()
        name = pin['acceptance']
        one_file = dict(pin, files={name: pin['files'][name]})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                candidate.verify_core(root, one_file)
            path.unlink()
            with self.assertRaisesRegex(ValueError, 'missing candidate Core file'):
                candidate.verify_core(root, one_file)

    def test_legacy_missing_and_hash_mismatch_fail(self):
        pin = candidate.load_legacy_pin()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, 'missing legacy measurer binary'):
                candidate.verify_legacy(root / 'missing', pin)
            binary = root / 'harness-gate-rust-measure'
            binary.write_text('not the released binary')
            (root / 'plugin.json').write_text(json.dumps({
                'analyzer': pin['analyzer'], 'version': pin['version'], 'rule': pin['rule']}))
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                candidate.verify_legacy(binary, pin)


if __name__ == '__main__':
    unittest.main()
