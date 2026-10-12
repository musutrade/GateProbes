"""Positive evidence always comes from the pinned real compiler and LLVM tools."""
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

QUALITY = Path(__file__).resolve().parents[1]
ROOT = QUALITY.parents[1]
sys.path.insert(0, str(QUALITY))
import rust_native_driver as native
import rust_native_policy as policy
from native_policy_fixture import prepare as prepare_policy, set_limit


class NativeDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        driver = os.environ.get('NATIVE_DRIVER')
        sysroot = os.environ.get('NATIVE_DRIVER_SYSROOT')
        if not driver or not sysroot:
            raise unittest.SkipTest('NATIVE_DRIVER and NATIVE_DRIVER_SYSROOT required: pinned rustc-dev compiler fixture')
        base = ROOT / 'target/gh-220/driver-tests'
        base.mkdir(parents=True, exist_ok=True)
        cls.work = Path(tempfile.mkdtemp(dir=base))
        cls.driver, cls.sysroot = Path(driver), Path(sysroot)
        cls.evidence = cls.work / 'complete'
        cls.anchor = native.collect_fixture(QUALITY / 'fixtures/rust-native/driver_complete.rs',
                                            cls.evidence, cls.driver, cls.sysroot)
        cls.report = native.certify(cls.evidence, cls.anchor)
        native.write_json(cls.work / 'report.json', cls.report)
        cls.capture = json.loads((cls.evidence / 'capture.json').read_text())
        cls.units = [u | {'inventory': json.loads((cls.evidence / u['inventory']).read_text())}
                     for u in cls.capture['units']]
        cls.llvm = json.loads((cls.evidence / 'native-export.stdout').read_text())

    def mapped(self, units=None, llvm=None, sources=None):
        return native.map_native(units if units is not None else self.units,
                                 llvm if llvm is not None else self.llvm,
                                 sources if sources is not None else self.capture['production_sources'], [])

    def test_dependency_cache_is_per_export_and_preserves_instance_inventory(self):
        llvm = copy.deepcopy(self.llvm)
        for name in ('dependency-one', 'dependency-two'):
            llvm['data'][0]['functions'].append({
                'name': name, 'filenames': ['/declared-dependency/lib.rs'],
                'regions': [[1, 1, 1, 2, 0, 0, 0, 0]], 'count': 0, 'branches': []})
        for owner in ('dependency-a', 'dependency-b'):
            with patch.object(native, 'exclude_region_file', wraps=native.exclude_region_file) as classify:
                report = native.map_native(self.units, llvm, self.capture['production_sources'],
                                           [{'id': owner, 'root': '/declared-dependency'}])
            self.assertEqual(classify.call_count, 1)
            entries = [row for row in report['exclusions'] if row.get('symbol', '').startswith('dependency-')]
            self.assertEqual(len(entries), 2)
            self.assertTrue(all(row['owners'] == [owner] for row in entries))
        with self.assertRaisesRegex(ValueError, 'unattributed LLVM source'):
            native.map_native(self.units, llvm, self.capture['production_sources'], [])

    def test_real_generated_constructor_closure_async_and_instances(self):
        if os.name == 'nt':
            self.assertEqual(list(self.evidence.glob('*.ilk')), [],
                             'incremental link padding must not enter native profiling sections')
        self.assertTrue(self.report['mapping_complete_for_declared_scope'])
        self.assertFalse(self.report['backend_complete'])
        rows = {f['name']: f for f in self.report['functions']}
        self.assertEqual(rows['future']['blocks'][0], 1)
        self.assertEqual(rows['future::{closure#0}']['blocks'][0], 0)
        self.assertEqual(len(rows['generic']['instances']), 2)
        self.assertGreater(rows['closure::{closure#0}']['blocks'][0], 0)
        self.assertNotEqual(rows['first']['definition']['expansion'], rows['second']['definition']['expansion'])
        self.assertTrue(any('clone' in name for name in rows))
        self.assertTrue(any(f['kind'].startswith('Ctor') for f in rows.values()))
        self.assertTrue(any(not f['explicit_coverage_enabled'] for f in rows.values()))
        self.assertNotIn('not_production', str(rows))
        self.assertFalse(rows['legacy_debt']['passed'])
        self.assertEqual(rows['legacy_debt']['crap_exact'], [56, 1])
        constant = next(d for d in self.units[0]['inventory']['definitions'] if d['name'] == 'Marker::CODE')
        self.assertEqual(constant['role'], 'compile-time')
        self.assertIsNotNone(constant['ctfe_sha256'])
        self.assertIn('constant_marker', constant['span']['expansion']['kind'])

    def test_definition_and_constant_inventory_cannot_be_omitted(self):
        for mutation in ('missing', 'duplicate', 'role', 'ctfe'):
            units = copy.deepcopy(self.units)
            definitions = units[0]['inventory']['definitions']
            if mutation == 'missing':
                definitions.pop(1)
            elif mutation == 'duplicate':
                definitions[-1]['id'] = definitions[0]['id']
            elif mutation == 'role':
                next(d for d in definitions if d['role'] == 'runtime')['role'] = 'declaration'
            else:
                next(d for d in definitions if d['role'] == 'compile-time')['ctfe_mir'] = 'forged'
            with self.assertRaises(ValueError):
                self.mapped(units)

    def test_cfg_changes_actual_compiled_inventory_and_history(self):
        directory = self.work / 'extra'
        anchor = native.collect_fixture(QUALITY / 'fixtures/rust-native/driver_complete.rs', directory,
                                        self.driver, self.sysroot, ['feature="extra"'])
        report = native.certify(directory, anchor)
        self.assertIn('conditional', [f['name'] for f in report['functions']])
        self.assertNotIn('conditional', [f['name'] for f in self.report['functions']])
        with self.assertRaisesRegex(ValueError, 'incompatible'):
            policy.require_history(self.report, report, [])

    def test_missing_duplicate_ambiguous_and_unattributed_native_regions(self):
        for kind in ['missing', 'duplicate', 'duplicate-block', 'owner', 'ambiguity', 'count', 'unknown']:
            with self.subTest(kind=kind):
                llvm = copy.deepcopy(self.llvm)
                units = copy.deepcopy(self.units)
                functions = llvm['data'][0]['functions']
                if kind == 'missing':
                    functions.pop()
                elif kind == 'duplicate':
                    functions.append(copy.deepcopy(functions[0]))
                elif kind == 'duplicate-block':
                    functions[0]['regions'].append(copy.deepcopy(functions[0]['regions'][0]))
                elif kind == 'owner':
                    units[0]['inventory']['owners'].pop()
                elif kind == 'ambiguity':
                    units[0]['inventory']['owners'][1]['dummy_symbol'] = units[0]['inventory']['owners'][0]['dummy_symbol']
                elif kind == 'count':
                    functions[0]['regions'][0][4] = -1
                else:
                    functions[0]['filenames'] = ['/unowned/source.rs']
                with self.assertRaises(ValueError):
                    self.mapped(units, llvm)

    def test_source_expansion_cfg_and_compiler_tampering(self):
        for kind in ['hash', 'span', 'expansion', 'compiler', 'mapping', 'block', 'source-id']:
            with self.subTest(kind=kind):
                units = copy.deepcopy(self.units)
                inv = units[0]['inventory']
                owner = next(o for o in inv['owners'] if o['name'] == 'first')
                if kind == 'hash':
                    next(s for s in inv['sources'] if s['source'] is not None)['sha256'] = '0' * 64
                elif kind == 'span':
                    owner['span']['end'] = 99999999
                elif kind == 'expansion':
                    owner['span']['expansion'].pop('macro_def')
                elif kind == 'compiler':
                    inv['rustc_commit'] = '0' * 40
                elif kind == 'mapping':
                    owner['mappings'].pop()
                elif kind == 'block':
                    owner['blocks'][0]['id'] = 10
                else:
                    owner['span']['source_id'] = -1
                with self.assertRaises((ValueError, KeyError)):
                    self.mapped(units)

    def test_manifest_and_native_reexport_reject_mutated_json(self):
        path = self.evidence / 'native-export.stdout'
        original = path.read_bytes()
        manifest = (self.evidence / 'manifest.json').read_bytes()
        try:
            data = copy.deepcopy(self.llvm)
            data['data'][0]['functions'][0]['regions'][0][4] += 1
            native.write_json(path, data)
            with self.assertRaisesRegex(ValueError, 'tampering'):
                native.certify(self.evidence, self.anchor)
            forged_anchor = native.seal(self.evidence)
            with self.assertRaisesRegex(ValueError, 'differs from native'):
                native.certify(self.evidence, forged_anchor)
        finally:
            path.write_bytes(original)
            (self.evidence / 'manifest.json').write_bytes(manifest)

    def test_history_missing_or_incompatible_cannot_reset_debt(self):
        with self.assertRaisesRegex(ValueError, 'baseline'):
            policy.require_history(None, self.report, [])
        for field in ['series', 'tools', 'flags', 'cfg', 'scope', 'build_inputs', 'adapter_sha256']:
            with self.subTest(field=field):
                altered = copy.deepcopy(self.report)
                altered[field] = None
                with self.assertRaisesRegex(ValueError, 'incompatible'):
                    policy.require_history(self.report, altered, [])
        policy.require_history(self.report, self.report, [])

    def test_real_cargo_production_test_exclusion_and_inactive_source_inventory(self):
        project = self.work / 'cargo-source'
        shutil.copytree(QUALITY / 'fixtures/rust-native/cargo-complete', project)
        capture = self.work / 'cargo'
        anchor = native.collect_cargo(project / 'Cargo.toml', capture, self.driver, self.sysroot, ['contract'],
                                      wrapper=os.environ.get('NATIVE_PLUGIN_BINARY'))
        raw = capture / 'raw'
        report = native.certify(raw, anchor)
        native.write_json(self.work / 'cargo-report.json', report)
        self.assertTrue(report['backend_complete'])  # This Cargo package only.
        names = [f['name'] for f in report['functions']]
        self.assertIn('production', names)
        self.assertNotIn('project_owned_contract', names)
        self.assertNotIn('not_a_production_function', names)
        self.assertNotIn('cfg_inactive', names)
        self.assertIn('src/inactive.rs', [s['relative'] for s in report['source_inventory']])
        saved = json.loads((raw / 'capture.json').read_text())
        self.assertEqual(sum(not u['production'] for u in saved['units']), 1)
        original = (raw / 'capture.json').read_bytes()
        for production in (True, False):
            altered = copy.deepcopy(saved)
            altered['units'].remove(next(u for u in altered['units'] if u['production'] == production))
            native.write_json(raw / 'capture.json', altered)
            with self.assertRaisesRegex(ValueError, 'selection differs'):
                native.certify(raw, native.seal(raw))
        (raw / 'capture.json').write_bytes(original)
        self.assertEqual(native.seal(raw), anchor)

    def test_released_rust_core_receives_real_native_debt(self):
        binary = os.environ.get('HARNESS_GATE_NATIVE_POLICY_BINARY')
        if not binary:
            self.skipTest('HARNESS_GATE_NATIVE_POLICY_BINARY required for shipped CLI integration')
        head = self.work / 'head'
        anchor = native.collect_fixture(QUALITY / 'fixtures/rust-native/driver_complete.rs', head,
                                        self.driver, self.sysroot)
        context = {'target': 'native', 'run': 'real-native-fixture', 'commit': 'a' * 40, 'base_commit': 'b' * 40}
        configured = prepare_policy(self.work / 'configured-policy', native.certify(self.evidence, self.anchor),
                                    self.evidence, context)
        report = policy.evaluate(self.evidence, self.anchor, head, anchor, self.work / 'policy', binary,
                                 context, context | {'commit': 'c' * 40, 'base_commit': 'a' * 40}, 'native-fixture', **configured)
        self.assertEqual(report['aggregate']['state'], 'fail')
        self.assertTrue(report['gates'])
        self.assertNotIn('measurement_error', {r['state'] for r in report['gates'].values()})
        debt = next(r for r in report['gates'].values() if r['record']['metric'] == 'risk.crap'
                    and r['record']['head'].get('numerator') == 56)
        self.assertEqual(debt['record']['ratchet']['debt'], 'unchanged')
        self.assertEqual(debt['state'], 'informational')
        self.assertTrue(debt['record']['policy']['required'])
        # Touch the same compiler owner, preserving its untested CC=7. The
        # changed-function CRAP limit must reject existing debt, through Rust.
        changed_source = self.work / 'changed.rs'
        changed_source.write_text((QUALITY / 'fixtures/rust-native/driver_complete.rs').read_text()
                                  .replace('if n == 1 { 1 }', 'if n == 1 { 9 }'), newline='\n')
        changed = self.work / 'changed'
        changed_anchor = native.collect_fixture(changed_source, changed, self.driver, self.sysroot)
        regression = policy.evaluate(self.evidence, self.anchor, changed, changed_anchor,
                                     self.work / 'changed-policy', binary, context,
                                     context | {'commit': 'd' * 40, 'base_commit': 'a' * 40}, 'native-fixture', **configured)
        blocked = next(r for r in regression['gates'].values() if r['record']['metric'] == 'risk.crap'
                       and r['record']['head'].get('numerator') == 56)
        self.assertEqual(blocked['state'], 'fail')
        self.assertFalse(blocked['record']['ratchet']['legacy_debt_allowed'])
        # Keep the debt function identical but remove its previous test reach.
        # The historical ratchet must reject worsening unmodified code as well.
        covered_source = self.work / 'covered.rs'
        covered_source.write_text((QUALITY / 'fixtures/rust-native/driver_complete.rs').read_text()
                                  .replace('fn main() {', 'fn main() {\n    for n in 0..8 { legacy_debt(n); }'), newline='\n')
        covered = self.work / 'covered'
        covered_anchor = native.collect_fixture(covered_source, covered, self.driver, self.sysroot)
        worse = policy.evaluate(covered, covered_anchor, self.evidence, self.anchor,
                                self.work / 'worse-policy', binary, context,
                                context | {'commit': 'e' * 40, 'base_commit': 'a' * 40}, 'native-fixture', **configured)
        regressed = next(r for r in worse['gates'].values() if r['record']['metric'] == 'risk.crap'
                         and r['record']['head'].get('numerator') == 56)
        self.assertEqual(regressed['state'], 'fail')
        self.assertEqual(regressed['record']['ratchet']['debt'], 'new')
        self.assertEqual(regressed['record']['base']['numerator'], 7)
        # Raising the configured ceiling cannot excuse a measured regression.
        set_limit(configured['repository_root'], 100)
        relaxed = policy.evaluate(covered, covered_anchor, self.evidence, self.anchor,
                                 self.work / 'configured-worse-policy', binary, context,
                                 context | {'commit': 'f' * 40, 'base_commit': 'a' * 40},
                                 'native-fixture', **configured)
        regressed = next(r for r in relaxed['gates'].values() if r['record']['metric'] == 'risk.crap'
                         and r['record']['head'].get('numerator') == 56)
        self.assertEqual(regressed['state'], 'fail')
        self.assertEqual(regressed['record']['base']['numerator'], 7)


if __name__ == '__main__':
    unittest.main()
