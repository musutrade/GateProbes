import json
import os
from pathlib import Path
import tempfile
import unittest
from fractions import Fraction
from unittest.mock import patch
from measure import crap, line_coverage, measure, source_inventories, strict_json
from test_toolchain_compatibility import logged_run, retained_measure, retained_root, tool_identity

HERE = Path(__file__).resolve().parent

class ArithmeticTests(unittest.TestCase):
    def test_exact_threshold(self):
        self.assertEqual(crap(10, 100, 100), {'numerator': 10, 'denominator': 1})
        self.assertEqual(crap(11, 100, 100), {'numerator': 11, 'denominator': 1})
        self.assertEqual(crap(4, 1, 2), {'numerator': 6, 'denominator': 1})
        self.assertIsNone(crap(1, 0, 0))

    def test_nested_zero_region_overrides_covered_parent(self):
        source = b'outer\nmissed\nend\n'
        self.assertEqual(line_coverage(source, [(0, len(source), 1), (6, 13, 0)], []), (2, 3))

    def test_nested_callable_does_not_borrow_parent_hits(self):
        source = b'outer\nclosure\nend\n'
        self.assertEqual(line_coverage(source, [(0, len(source), 1)], [(6, 14)]), (2, 2))

    def test_crossing_regions_rejected(self):
        with self.assertRaisesRegex(ValueError, 'crossing'):
            line_coverage(b'1234567890', [(0, 7, 1), (3, 10, 0)], [])

    def test_duplicate_json_and_unsafe_integer(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'data.json'
            for text in ('{"a":1,"a":2}', '{"a":9007199254740992}', '{"a":NaN}'):
                p.write_text(text)
                with self.assertRaises(ValueError): strict_json(p)

class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root, cls.tmp = retained_root('rust-source-native-test-')
        if cls.tmp:
            cls.addClassCleanup(cls.tmp.cleanup)
        cls.inventory = Path(os.environ.get('RUST_SOURCE_INVENTORY', HERE / 'inventory'))
        identity = tool_identity(cls.root)
        cls.source = cls.root / 'sample.rs'
        cls.source.write_text('''fn ten(x: bool) { if x {} if x {} if x {} if x {} if x {} if x {} if x {} if x {} if x {} }
fn eleven(x: bool) { if x {} if x {} if x {} if x {} if x {} if x {} if x {} if x {} if x {} if x {} }
async fn unpolled() { if true { std::hint::black_box(1); } }
fn main() { ten(true); eleven(true); std::mem::drop(unpolled()); }
''')
        binary = cls.root / 'sample'
        logged_run(cls.root, 'compile', ['rustc', '--edition=2024', '-C', 'instrument-coverage', cls.source, '-o', binary])
        logged_run(cls.root, 'execute', [binary], env=dict(os.environ, LLVM_PROFILE_FILE=str(cls.root / 'raw-%p.profraw')))
        tools = identity['tools']
        profile = cls.root / 'merged.profdata'
        logged_run(cls.root, 'merge', [tools['llvm-profdata']['path'], 'merge', '-sparse', *cls.root.glob('*.profraw'), '-o', profile])
        cls.llvm = cls.root / 'llvm.json'
        exported = logged_run(cls.root, 'export', [tools['llvm-cov']['path'], 'export', '-instr-profile=' + str(profile), binary])
        cls.llvm.write_bytes(exported.stdout)

    def result(self, path=None):
        return retained_measure(self.root, self._testMethodName,
                                lambda: measure(self.root, ['sample.rs'], path or self.llvm, self.inventory))

    def test_real_native_threshold_and_unpolled_async(self):
        rows = {f['name']: f for f in self.result()['functions']}
        self.assertEqual(rows['ten']['risk.crap'], {'numerator': 10, 'denominator': 1})
        self.assertEqual(rows['eleven']['risk.crap'], {'numerator': 11, 'denominator': 1})
        self.assertEqual(rows['unpolled']['coverage.function']['numerator'], 0)
        self.assertEqual(rows['unpolled']['coverage.line']['numerator'], 0)

    def mutate(self, action):
        data = json.loads(self.llvm.read_text())
        action(data['data'][0]['functions'])
        p = self.root / (self._testMethodName + '-tampered.json')
        p.write_text(json.dumps(data))
        return p

    def test_missing_function_rejected(self):
        p = self.mutate(lambda rows: rows.pop(next(i for i, f in enumerate(rows) if f['regions'][0][:2] == [1, 1])))
        with self.assertRaisesRegex(ValueError, 'missing native mapping'): self.result(p)

    def test_wrong_anchor_rejected(self):
        def change(rows):
            f = next(f for f in rows if f['filenames'][0] == str(self.source))
            f['regions'][0][1] += 1
        with self.assertRaisesRegex(ValueError, 'exact source anchor'): self.result(self.mutate(change))

    def test_duplicate_native_instance_rejected(self):
        def change(rows):
            rows.append(next(f for f in rows if f['filenames'][0] == str(self.source)))
        with self.assertRaisesRegex(ValueError, 'duplicate native'): self.result(self.mutate(change))

    def test_all_bad_anchors_and_missing_owners_reported_together(self):
        def change(rows):
            for f in rows:
                if f['regions'][0][0] in (1, 2):
                    f['regions'][0][1] += 1
            rows[:] = [f for f in rows if f['regions'][0][0] != 3]
        with self.assertRaises(ValueError) as error:
            self.result(self.mutate(change))
        message = str(error.exception)
        self.assertIn('missing exact source anchor: sample.rs:[1, 2]', message)
        self.assertIn('missing exact source anchor: sample.rs:[2, 2]', message)
        self.assertIn('source callable missing native mapping', message)
        self.assertIn('sample.rs:[3, 1]', message)
        self.assertIn('no measurements produced', message)

    def test_ambiguous_and_missing_anchors_are_both_reported(self):
        inventories = source_inventories(self.root, ['sample.rs'], self.inventory)
        first, second = inventories['sample.rs'][:2]
        second['anchors'].append(first['anchors'][0])
        def change(rows):
            for f in rows:
                if f['regions'][0][0] == 2:
                    f['regions'][0][1] += 1
        with patch('measure.source_inventories', return_value=inventories):
            with self.assertRaises(ValueError) as error:
                self.result(self.mutate(change))
        self.assertIn('ambiguous exact source anchor: sample.rs:[1, 1]', str(error.exception))
        self.assertIn('missing exact source anchor: sample.rs:[2, 2]', str(error.exception))

if __name__ == '__main__': unittest.main()
