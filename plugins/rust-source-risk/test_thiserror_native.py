"""Explicit Linux native subset verification. Requires the built candidate inventory.

Uses real capture, retained profiles/objects, discover and collect. Corruption
cases mutate actual LLVM export or duplicate one inventory owner, then call the
unchanged native mapper; they are fault injections, not compiler certifications.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

import plugin
from measure import measure, source_inventories
from test_toolchain_compatibility import logged_run, retained_root, write

HERE = Path(__file__).resolve().parent
SOURCE = 'apps/server/src/lib.rs'


class ThiserrorNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root, temporary = retained_root('thiserror-native-')
        if temporary:
            cls.addClassCleanup(temporary.cleanup)
        fixture = cls.root / 'fixture'
        shutil.copytree(HERE / 'fixtures/thiserror-subset', fixture)
        source = fixture / SOURCE
        source.write_text(source.read_text() + '\npub fn never(flag: bool) -> usize { if flag { 5 } else { 6 } }\n')
        logged_run(cls.root, 'git-init', ['git', 'init', fixture])
        logged_run(cls.root, 'git-add', ['git', '-C', fixture, 'add', '.'])
        logged_run(cls.root, 'git-commit', ['git', '-C', fixture, '-c', 'user.name=Fixture',
                   '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'fixed native input'])
        cls.capture = cls.root / 'capture'
        logged_run(cls.root, 'capture', [sys.executable, HERE / 'capture.py', '--repository', fixture,
                   '--output', cls.capture, '--target-dir', cls.root / 'target', '--source-root', 'apps/server/src',
                   '--input', 'Cargo.toml', '--input', 'Cargo.lock', '--input', 'apps/server/src',
                   '--input', 'tests', '--test', 'integration'])
        cls.bundle = json.loads((cls.capture / 'bundle.json').read_text())
        cls.request = cls.bundle['request']
        cls.workspace = Path(cls.request['workspace_root'])
        cls.cfg = cls.request['parameters']['receipt']['pipeline']['target_cfg']
        cls.llvm = cls.root / 'reexport.json'
        cls.measured = plugin.reexport(cls.request, cls.llvm)
        cls.inventory = HERE / 'inventory'
        write(cls.root / 'measured.json', cls.measured)

    def test_exact_authored_inventory_counters_and_complexity(self):
        rows = self.measured['functions']
        self.assertEqual([(r['name'], r['kind'], r['start'], r['end'], r['complexity']) for r in rows], [
            ('classify', 'method', [27,5], [29,6], 2),
            ('branch', 'function', [31,1], [33,2], 2),
            ('closure', 'function', [34,1], [37,2], 1),
            ('<closure>', 'closure', [35,18], [35,43], 2),
            ('never', 'function', [55,1], [55,63], 2),
        ])
        ast = source_inventories(self.workspace, [SOURCE], self.inventory, self.cfg)[SOURCE]
        for row, original in zip(rows, ast, strict=True):
            for key in ('start', 'end', 'anchors', 'body', 'complexity'):
                self.assertEqual(row[key], original[key])
            self.assertEqual(row['native_instances'], 1)
            for metric in ('coverage.function', 'coverage.line', 'coverage.region'):
                value = row[metric]
                self.assertGreater(value['denominator'], 0)
                self.assertEqual(value['numerator'], 0 if row['name']=='never' else value['denominator'])
        self.assertEqual(rows[-1]['risk.crap'], {'numerator':6, 'denominator':1})

    def test_discover_collect_preserve_zero_execution(self):
        self.assertEqual(plugin.discover(self.request), self.request['parameters']['subjects'])
        result = plugin.collect(self.request)
        self.assertEqual(len(result['evidence']), 5)
        metrics = {r['name']:r['value'] for r in result['evidence'][-1]['metrics']}
        self.assertEqual(metrics['coverage.function'], {'type':'ratio','covered':0,'total':1})
        self.assertEqual(metrics['complexity.cyclomatic'], {'type':'count','value':2})
        write(self.root / 'collection.json', result)

    def rejected(self, label, data, reason, inventory=None):
        path = self.root / (label + '.json')
        write(path, data)
        with self.assertRaisesRegex(ValueError, reason) as error:
            measure(self.workspace, [SOURCE], path, inventory or self.inventory, self.cfg)
        (self.root / (label + '.stderr')).write_text(str(error.exception))

    def test_missing_and_unmatched_native_mapping_fail(self):
        data = json.loads(self.llvm.read_text())
        for unit in data['data']:
            unit['functions'] = [f for f in unit['functions'] if f['regions'][0][0] != 55]
        self.rejected('missing-authored-counter', data, 'source callable missing native mapping')
        data = json.loads(self.llvm.read_text())
        for unit in data['data']:
            for f in unit['functions']:
                if f['regions'][0][0] == 31:
                    f['regions'][0][:2] = [1, 1]
        self.rejected('unmatched-native-anchor', data, 'missing exact source anchor')

    def test_multifile_native_region_fails(self):
        data = json.loads(self.llvm.read_text())
        for unit in data['data']:
            for f in unit['functions']:
                if f['regions'][0][0] == 31:
                    f['filenames'].append(str(self.workspace / 'generated.rs'))
                    region = copy.deepcopy(f['regions'][0]);region[5] = len(f['filenames'])-1
                    f['regions'].append(region)
        self.rejected('multifile-expansion', data, 'multi-file native expansion needs a certified mapping')

    def test_ambiguous_inventory_owner_fails(self):
        wrapper = self.root / 'ambiguous-inventory'
        wrapper.write_text('#!' + sys.executable + '\nimport subprocess,sys,json\n'
            + f'r=subprocess.run([{str(self.inventory)!r},*sys.argv[1:]],input=sys.stdin.read(),capture_output=True,text=True,check=True)\n'
            + 'rows=json.loads(r.stdout);rows.append(next(r for r in rows if r["name"]=="branch"));print(json.dumps(rows))\n')
        wrapper.chmod(0o700)
        self.rejected('ambiguous-inventory-owner', json.loads(self.llvm.read_text()),
                      'ambiguous exact source anchor', wrapper)


if __name__ == '__main__':
    unittest.main()
