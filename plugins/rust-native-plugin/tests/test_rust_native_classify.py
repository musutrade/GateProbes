"""Native positive classifications; all JSON mutations are rejection cases."""
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
import rust_native_classify as classify
from test_native_artifact_paths import WindowsRelativePath


class NativeFileClassificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        driver, sysroot = os.environ.get('NATIVE_DRIVER'), os.environ.get('NATIVE_DRIVER_SYSROOT')
        if not driver or not sysroot:
            raise unittest.SkipTest('NATIVE_DRIVER and NATIVE_DRIVER_SYSROOT required for real file classification')
        base = ROOT / 'target/gh-221/file-tests'
        base.mkdir(parents=True, exist_ok=True)
        cls.work = Path(tempfile.mkdtemp(dir=base))
        project = cls.work / 'project'
        shutil.copytree(QUALITY / 'fixtures/rust-native/file-classification', project)
        cls.evidence = []
        cls.anchors = []
        for name, features in [('default', []), ('extra', ['extra'])]:
            output = cls.work / name
            anchor = native.collect_cargo(project / 'Cargo.toml', output, driver, sysroot, ['contract'], features)
            cls.anchors.append(anchor)
            cls.evidence.append(classify.load_evidence(output / 'raw', anchor))
        cls.default, cls.extra = cls.evidence
        for name, evidence, witness in [('default', cls.default, cls.extra), ('extra', cls.extra, cls.default)]:
            native.write_json(cls.work / (name + '-classification.json'), classify.classify(evidence, witness))
        native.write_json(cls.work / 'anchors.json', dict(zip(('default', 'extra'), cls.anchors)))

    def rows(self, evidence=None, witness=None):
        return {r['relative']: r for r in classify.classify(evidence or self.default, witness)['files']}

    def test_declarations_and_module_forwarding_have_no_parent_machine_code(self):
        rows = self.rows()
        for name in ('src/declarations.rs', 'src/forward/mod.rs', 'src/lib.rs'):
            self.assertEqual(rows[name]['status'], 'not_applicable')
            self.assertEqual(rows[name]['reason'], 'declarations_only')
            self.assertIsNone(rows[name]['metrics'])
            self.assertTrue(rows[name]['definitions'])
        self.assertEqual(rows['src/forward/child.rs']['execution'], 'observed_hits')

    def test_generated_constants_and_runtime_derive_task_local(self):
        rows = self.rows()
        marker = rows['src/markers.rs']
        self.assertEqual(marker['reason'], 'compile_time_definitions_only')
        constants = [d for d in marker['definitions'] if d['role'] == 'compile-time']
        self.assertTrue(constants and all(d['ctfe_sha256'] and d['span']['expansion'] for d in constants))
        for name in ('generated', 'derived', 'local'):
            row = rows['src/' + name + '.rs']
            self.assertEqual(row['status'], 'measured')
            self.assertTrue(row['generated_runtime'])
            self.assertTrue(all(o['instances'] for o in row['owners']))
        never = next(o for o in rows['src/generated.rs']['owners'] if o['name'].endswith('::never'))
        self.assertTrue(never['blocks'] and all(c == 0 for c in never['blocks']))

    def test_unexecuted_is_real_zero_with_positive_denominator(self):
        row = self.rows()['src/unexecuted.rs']
        self.assertEqual(row['status'], 'measured')
        self.assertEqual(row['execution'], 'zero_hits')
        self.assertEqual(row['metrics']['owner_regions']['covered'], 0)
        self.assertGreater(row['metrics']['owner_regions']['count'], 0)
        self.assertTrue(all(o['instances'] for o in row['owners']))

    def test_cfg_requires_real_same_source_feature_witness_and_keeps_orphan_error(self):
        plain = self.rows()
        self.assertEqual(plain['src/conditional.rs']['status'], 'measurement_error')
        rows = self.rows(witness=self.extra)
        conditional = rows['src/conditional.rs']
        self.assertEqual(conditional['status'], 'not_applicable')
        self.assertEqual(conditional['reason'], 'outside_selected_feature_configuration')
        self.assertTrue(conditional['selection_witness']['runtime_owners'])
        self.assertIsNone(conditional['metrics'])
        self.assertEqual(rows['src/orphan.rs']['status'], 'measurement_error')
        self.assertEqual(self.rows(self.extra)['src/conditional.rs']['status'], 'measured')
        self.assertEqual(len(rows), 11)

    def test_missing_export_owner_ctfe_and_tampered_sources_fail_closed(self):
        evidence = self.default
        for mutation in ('llvm', 'owner', 'definition', 'ctfe', 'source'):
            with self.subTest(mutation=mutation):
                units = copy.deepcopy(evidence['units'])
                llvm = classify.read_json(evidence['directory'] / 'native-export.stdout')
                unit = next(u for u in units if u['production'])
                if mutation == 'llvm':
                    symbols = {s for f in evidence['report']['functions'] for s in f['instances']}
                    llvm['data'][0]['functions'] = [f for f in llvm['data'][0]['functions'] if f['name'] not in symbols]
                elif mutation == 'owner':
                    unit['inventory']['owners'].pop()
                elif mutation == 'definition':
                    unit['inventory']['definitions'].pop(2)
                elif mutation == 'ctfe':
                    next(d for d in unit['inventory']['definitions'] if d['role'] == 'compile-time')['ctfe_mir'] = 'forged'
                else:
                    next(s for s in unit['inventory']['sources'] if s['source'] is not None)['sha256'] = '0' * 64
                with self.assertRaises(ValueError):
                    native.map_native(units, llvm, evidence['capture']['production_sources'], evidence['capture']['dependency_exclusions'])

    def test_manifest_source_inventory_config_and_llvm_mutations_cannot_waive_file(self):
        raw = self.default['directory']
        for name in ('capture.json', 'native-export.stdout', 'source/src/declarations.rs'):
            original = (raw / name).read_bytes()
            try:
                (raw / name).write_bytes(original + b' ')
                with self.assertRaisesRegex(ValueError, 'tampering'):
                    classify.load_evidence(raw, self.anchors[0])
            finally:
                (raw / name).write_bytes(original)
        original = (raw / 'capture.json').read_bytes()
        manifest = (raw / 'manifest.json').read_bytes()
        try:
            for kind in ('inventory', 'cfg'):
                capture = json.loads(original)
                if kind == 'inventory':
                    capture['production_sources'].pop(next(iter(capture['production_sources'])))
                else:
                    capture['cfg']['samples'] = ['fabricated']
                native.write_json(raw / 'capture.json', capture)
                forged = native.seal(raw)
                if kind == 'inventory':
                    with self.assertRaisesRegex(ValueError, 'selection differs'):
                        classify.load_evidence(raw, forged)
                else:
                    # Re-sealing is not authorization to replace the reviewed anchor.
                    with self.assertRaisesRegex(ValueError, 'untrusted manifest'):
                        classify.load_evidence(raw, self.anchors[0])
        finally:
            (raw / 'capture.json').write_bytes(original)
            (raw / 'manifest.json').write_bytes(manifest)

    def test_series_source_target_sample_and_flags_cannot_supply_cfg_witness(self):
        for key in ('series', 'tools', 'flags', 'scope', 'build_inputs', 'adapter_sha256'):
            witness = self.extra | {'report': self.extra['report'] | {key: None}}
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'incompatible'):
                classify.classify(self.default, witness)
        for mutation in ('inventory', 'samples', 'target', 'target_cfg'):
            witness = self.extra | {'report': copy.deepcopy(self.extra['report'])}
            if mutation == 'inventory':
                witness['report']['source_inventory'].pop()
            elif mutation == 'samples':
                witness['report']['cfg']['samples'] = []
            elif mutation == 'target':
                witness['report']['cfg']['units'][0]['target'] = 'other'
            else:
                witness['report']['cfg']['units'][0]['cfg'].append('target_os="other"')
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'incompatible'):
                classify.classify(self.default, witness)

    def test_reviewed_archive_replays_real_mapping_without_original_binaries(self):
        raw = self.work / 'archive'
        shutil.copytree(self.default['directory'], raw)
        report = self.work / 'reviewed-report.json'
        native.write_json(report, self.default['report'])
        digest = native.file_hash(report)
        for name in self.default['capture']['binaries']:
            (raw / name).unlink()
        # Archive replay must not invoke tools or attempt the recorded external paths.
        with patch.object(native, 'certify', side_effect=AssertionError('unexpected native recertification')), \
                patch.object(classify, 'Path', WindowsRelativePath):
            archived = classify.load_evidence(raw, self.anchors[0], report, digest)
        self.assertEqual(archived['mode'], 'reviewed-archive-replay')
        self.assertEqual(set(archived['missing_binaries']), set(self.default['capture']['binaries']))
        self.assertEqual(classify.classify(archived)['files'], classify.classify(self.default)['files'])
        with self.assertRaisesRegex(ValueError, 'untrusted reviewed report'):
            classify.load_evidence(raw, self.anchors[0], report, '0' * 64)
        original = report.read_bytes()
        report.write_bytes(original + b' ')
        with self.assertRaisesRegex(ValueError, 'untrusted reviewed report'):
            classify.load_evidence(raw, self.anchors[0], report, digest)
        report.write_bytes(original)
        (raw / 'native-export.stdout').unlink()
        with self.assertRaisesRegex(ValueError, 'missing non-binary evidence'):
            classify.load_evidence(raw, self.anchors[0], report, digest)


if __name__ == '__main__':
    unittest.main()
