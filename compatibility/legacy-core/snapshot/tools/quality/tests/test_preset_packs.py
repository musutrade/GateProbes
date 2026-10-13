"""Reference pack defaults stay data, pinned to accepted measurement boundaries."""
import copy
import gzip
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import typescript_semantics as ts

ROOT = Path(__file__).resolve().parents[3]
PRESETS = ROOT / 'tools/harness-gate/fixtures/preset-compat'
FIXTURES = ROOT / 'tools/quality/fixtures'
CORE_FIXTURES = ROOT / 'tools/harness-gate/fixtures'


def read(path):
    return json.loads(path.read_text())


class PresetPackTests(unittest.TestCase):
    def test_rust_preserves_entire_accepted_series_and_policy(self):
        reference = read(CORE_FIXTURES / 'workflow/collectors/certified-rust-profiles.json')
        pack = read(PRESETS / 'packs/rust.json')
        self.assertEqual(pack['files']['.harness-gate/packs/${binding}/capabilities.json']['series'], reference['series'])
        rules = copy.deepcopy(reference['rules'])
        for rule in rules:
            rule['id'] = '${binding}.' + rule['metric']
            rule['scope'] = {'kind': 'component', 'component': '${binding}'}
        self.assertEqual(pack['files']['.harness-gate/packs/${binding}/policy.json']['rules'], rules)

    def test_typescript_uses_native_series_and_unsupported_crap(self):
        fixture = FIXTURES / 'typescript-angular'
        bundle = ts.read_bundle((fixture / 'evidence/native.tar.gz').read_bytes(),
                                (fixture / 'semantics/source-index.json').read_bytes(),
                                read(fixture / 'semantics/receipt.json'),
                                {p.relative_to(fixture / 'app').as_posix(): p.read_bytes()
                                 for p in (fixture / 'app/src').rglob('*') if p.is_file()})
        pack = read(PRESETS / 'packs/typescript.json')
        capabilities = pack['files']['.harness-gate/packs/${binding}/capabilities.json']
        self.assertEqual(capabilities['series'], ts.measurement_series(bundle.toolchain, 'node-jsdom', 'production-ts'))
        native = bundle.measure('src/app/pricing.ts')[0]
        for metric, state in capabilities['states'].items():
            self.assertEqual(native['states'][metric], state)
        self.assertNotIn('risk.crap', native['values'])
        rules = pack['files']['.harness-gate/packs/${binding}/policy.json']['rules']
        self.assertFalse(next(r for r in rules if r['metric'] == 'risk.crap')['required'])
        self.assertEqual({r['metric'] for r in rules if r['required']}, {'coverage.line', 'coverage.function'})

    def test_contract_series_and_rules_come_from_native_reference(self):
        native = json.loads(gzip.decompress((FIXTURES / 'generic-core/contract-compatible.input.json.gz').read_bytes()))
        pack = read(PRESETS / 'packs/api-contract.json')
        record = next(r for r in native['head']['records'] if r['subject']['kind'] == 'contract/v1')
        self.assertEqual(pack['files']['.harness-gate/packs/${binding}/capabilities.json']['series'], record['series'])
        rules = [copy.deepcopy(r) for r in native['policy']['rules'] if r['scope']['kind'] == 'relationship']
        for rule in rules:
            rule['id'] = '${binding}.' + rule['metric']
            rule['scope'] = {'kind': 'relationship', 'relationship': '${binding}'}
        self.assertEqual(pack['files']['.harness-gate/packs/${binding}/policy.json']['rules'], rules)

    def test_reference_recipes_reuse_packs_and_database_has_no_implicit_quality(self):
        mixed = read(PRESETS / 'angular-rust-postgres.packs.json')
        self.assertEqual([p['pack'] for p in mixed], ['typescript', 'rust', 'api-contract'])
        for name, index in [('angular-only', 0), ('rust-api', 1)]:
            self.assertEqual(read(PRESETS / (name + '.packs.json'))[0]['pack'], mixed[index]['pack'])
        self.assertFalse((PRESETS / 'generic.packs.json').exists())
        for p in (PRESETS / 'packs').glob('*.json'):
            self.assertNotIn('postgres', p.read_text())

    def test_docs_keep_reference_composition_migration_and_policy_anchors(self):
        docs = (ROOT / 'docs/quality-presets.md').read_text()
        for anchor in ('frontend=vue', 'backend=go', 'database=postgres', 'flow-only',
                       'unsupported', 'CRAP <= 30', '4/5', 'engineering-policy.md',
                       'quality-collectors.md', 'quality-compilation.md', 'registry',
                       'Required Quality Aggregate'):
            self.assertIn(anchor, docs)


class FrozenPresetProvenanceTests(unittest.TestCase):
    def test_frozen_inputs_match_recorded_inventory_and_digests(self):
        manifest = json.loads((PRESETS / 'provenance.json').read_text())
        actual = {p.relative_to(PRESETS).as_posix() for p in PRESETS.rglob('*') if p.is_file()}
        self.assertEqual(actual, set(manifest['files']) | {'provenance.json'})
        for relative, record in manifest['files'].items():
            self.assertEqual(hashlib.sha256((PRESETS / relative).read_bytes()).hexdigest(),
                             record['sha256'], relative)
