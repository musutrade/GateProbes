"""GH-130: native replay, source identity, fail-closed mapping and series semantics."""
import copy
import io
import json
from pathlib import Path
import sys
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import harness_evidence as evidence
import typescript_semantics as ts

FIXTURE = Path(__file__).resolve().parents[1] / 'fixtures/typescript-angular'
PRICING = 'src/app/pricing.ts'


class TypeScriptSemanticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = (FIXTURE / 'evidence/native.tar.gz').read_bytes()
        cls.parser = (FIXTURE / 'semantics/source-index.json').read_bytes()
        cls.receipt = json.loads((FIXTURE / 'semantics/receipt.json').read_text())
        cls.sources = {str(p.relative_to(FIXTURE / 'app')): p.read_bytes()
                       for p in (FIXTURE / 'app/src').rglob('*') if p.is_file()}
        cls.bundle = ts.read_bundle(cls.archive, cls.parser, cls.receipt, cls.sources)

    def setUp(self):
        self.b = copy.deepcopy(self.bundle)

    def test_exact_native_file_and_function_counters(self):
        golden = json.loads((FIXTURE / 'semantics/native-counters.json').read_text())
        for path, scopes in golden['files'].items():
            with self.subTest(path=path):
                rows = self.b.measure(path)
                self.assertEqual(len(rows), len(scopes))
                for row, expected in zip(rows, scopes):
                    for metric, native in [('coverage.line', 'lines'), ('coverage.function', 'functions')]:
                        self.assertEqual(row['values'][metric], {'type': 'ratio', **expected[native]})
                    for metric in ('coverage.branch', 'complexity.cyclomatic', 'risk.crap'):
                        self.assertEqual(row['states'][metric], 'unsupported')
                        self.assertNotIn(metric, row['values'])
        rows = self.b.measure(PRICING)
        self.assertEqual(rows[0]['values']['coverage.line']['total'], 6)
        self.assertEqual(rows[1]['values']['coverage.line'], {'type': 'ratio', 'covered': 3, 'total': 5})

    def test_duplicate_method_names_and_anonymous_arrows_have_unique_original_identities(self):
        methods = [self.b.measure('src/app/' + name + '.ts')[1]['subject']
                   for name in ('pricing', 'standard-quote', 'priority-quote')]
        self.assertEqual(len({s['id'] for s in methods}), 3)
        for subject, owner in zip(methods, ('Pricing', 'StandardQuote', 'PriorityQuote')):
            self.assertIn(owner + '.quote', subject['discriminator'])
            self.assertEqual(subject['kind'], 'method/v1')
            self.assertEqual(subject['source_sha256'], ts.digest(self.sources[subject['path'][4:]]))
            self.assertGreater(subject['span']['start_column'], 0)
        arrows = self.b.measure('src/app/app.routes.ts')[1:]
        self.assertEqual(len({r['subject']['id'] for r in arrows}), 2)
        self.assertTrue(all('ArrowFunction' in r['subject']['discriminator'] for r in arrows))

    def test_basename_unknown_and_fabricated_native_coordinates_rejected(self):
        for path in ('pricing.ts', 'src/other/pricing.ts', '../src/app/pricing.ts'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.b.measure(path)
        self.b.native[PRICING]['fnMap']['0']['decl']['start']['column'] = 1
        with self.assertRaisesRegex(ValueError, 'fabricated function|incomplete measured'):
            self.b.measure(PRICING)

    def test_ambiguous_and_incomplete_parser_joins_rejected(self):
        function = self.b.index[PRICING]['functions'][0]
        self.b.index[PRICING]['functions'].append(copy.deepcopy(function))
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            self.b.measure(PRICING)
        self.b = copy.deepcopy(self.bundle)
        self.b.native[PRICING]['fnMap'].clear()
        self.b.native[PRICING]['f'].clear()
        with self.assertRaisesRegex(ValueError, 'incomplete native function'):
            self.b.measure(PRICING)

    def test_tampered_native_archive_or_parser_index_rejected_at_entry(self):
        for archive, parser in [(self.archive + b'x', self.parser), (self.archive, self.parser + b' ')]:
            with self.subTest(parser=parser is self.parser), self.assertRaisesRegex(ValueError, 'integrity'):
                ts.read_bundle(archive, parser, self.receipt, self.sources)

    def test_stale_or_missing_request_sources_rejected(self):
        for delete in (False, True):
            sources = dict(self.sources)
            if delete:
                del sources[PRICING]
            else:
                sources[PRICING] += b'\n'
            with self.subTest(delete=delete), self.assertRaisesRegex(ValueError, 'source snapshot'):
                ts.read_bundle(self.archive, self.parser, self.receipt, sources)

    def test_receipted_incomplete_or_invalid_collection_still_fails_closed(self):
        with tarfile.open(fileobj=io.BytesIO(self.archive), mode='r:gz') as archive:
            originals = {m.name: archive.extractfile(m).read() for m in archive.getmembers()}
        for case in ('failed command', 'incomplete status', 'missing artifact', 'modified artifact',
                     'bad configuration', 'duplicate artifact', 'path escape'):
            files = dict(originals)
            manifest = json.loads(files['manifest.json'])
            name = next(iter(manifest['artifacts']))
            if case == 'failed command':
                manifest['commands'][0]['exit_status'] = 1
            elif case == 'incomplete status':
                manifest['status'] = 'partial'
            elif case == 'missing artifact':
                del files[name]
            elif case == 'modified artifact':
                files[name] += b'x'
            elif case == 'bad configuration':
                manifest['configuration_digests'][next(iter(manifest['configuration_digests']))] = '0' * 64
            elif case == 'path escape':
                files['../outside'] = b'x'
            files['manifest.json'] = json.dumps(manifest).encode()
            output = io.BytesIO()
            entries = list(files.items())
            if case == 'duplicate artifact':
                entries.append(entries[0])
            with tarfile.open(fileobj=output, mode='w:gz') as archive:
                for path, data in entries:
                    member = tarfile.TarInfo(path)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            data = output.getvalue()
            receipt = {**self.receipt, 'native_sha256': ts.digest(data)}
            with self.subTest(case=case), self.assertRaises(ValueError):
                ts.read_bundle(data, self.parser, receipt, self.sources)

    def map_name(self):
        return self.b.maps_for(PRICING)[0]

    def test_missing_ambiguous_map_and_emitted_linkage_rejected(self):
        name = self.map_name()
        for case in ('missing', 'duplicate', 'emitted', 'linkage'):
            self.b = copy.deepcopy(self.bundle)
            if case == 'missing':
                del self.b.artifacts[name]
            elif case == 'duplicate':
                duplicate = name.replace('.js.map', '-copy.js.map')
                self.b.artifacts[duplicate] = self.b.artifacts[name]
                self.b.artifacts[duplicate[:-4]] = self.b.artifacts[name[:-4]].replace(
                    Path(name).name.encode(), Path(duplicate).name.encode())
            elif case == 'emitted':
                del self.b.artifacts[name[:-4]]
            else:
                self.b.artifacts[name[:-4]] += b'\n//# sourceMappingURL=other.js.map\n'
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.b.measure(PRICING)

    def test_source_map_semantic_negatives_even_if_artifacts_are_rehashed(self):
        name = self.map_name()
        original = json.loads(self.b.artifacts[name])
        cases = {
            'stale content': lambda m: m['sourcesContent'].__setitem__(0, 'stale'),
            'missing content': lambda m: m.pop('sourcesContent'),
            'ambiguous source': lambda m: (m['sources'].append(m['sources'][0]), m['sourcesContent'].append(m['sourcesContent'][0])),
            'basename': lambda m: m['sources'].__setitem__(0, 'pricing.ts'),
            'path escape': lambda m: m['sources'].__setitem__(0, '../pricing.ts'),
            'source root': lambda m: m.update(sourceRoot='../'),
            'indexed map': lambda m: m.update(sections=[]),
            'missing mappings': lambda m: m.update(mappings=''),
            'unmapped source': lambda m: m.update(mappings='A'),
            'truncated VLQ': lambda m: m.update(mappings='g'),
            'invalid VLQ': lambda m: m.update(mappings='!'),
            'bad source index': lambda m: m.update(mappings='ACAA'),
            'bad source column': lambda m: m.update(mappings='AAAD'),
            'bad source line': lambda m: m.update(mappings='AADA'),
            'bad name index': lambda m: m.update(mappings='AAAA/////D'),
            'duplicate generated coordinate': lambda m: m.update(mappings='AAAA,AAAA'),
            'bad generated column': lambda m: m.update(mappings='/////DAAA'),
        }
        for label, mutate in cases.items():
            mapping = copy.deepcopy(original)
            mutate(mapping)
            with self.subTest(case=label), self.assertRaises(ValueError):
                ts.validate_map(mapping, self.b.artifacts[name[:-4]].decode(), self.sources)

    def test_partial_mapping_cannot_supply_measured_subjects(self):
        name = self.map_name()
        mapping = json.loads(self.b.artifacts[name])
        mapping['mappings'] = 'AAAA'
        self.b.artifacts[name] = json.dumps(mapping).encode()
        with self.assertRaisesRegex(ValueError, 'incomplete measured'):
            self.b.measure(PRICING)

    def test_duplicate_json_provenance_fields_are_ambiguous(self):
        name = self.map_name()
        self.b.artifacts[name] = b'{"sources": [],' + self.b.artifacts[name].lstrip()[1:]
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
            self.b.measure(PRICING)

    def test_native_missing_map_is_not_perfect_coverage(self):
        with self.assertRaisesRegex(ValueError, 'source-map provenance'):
            self.b.measure('src/app/app.config.ts')

    def test_template_and_generated_multisource_remain_unsupported(self):
        for path in ('src/app/app.ts', 'src/app/details/details.ts', 'src/app/generated/models/Quote.ts'):
            with self.subTest(path=path):
                row = self.b.measure(path)[0]
                self.assertEqual(set(row['states'].values()), {'unsupported'})
                self.assertEqual(row['values'], {})
                self.assertNotIn('subject', row)

    def test_zero_denominator_has_no_numeric_value(self):
        self.assertEqual(ts.ratio([]), ('not_applicable', None))
        row = self.b.native[PRICING]
        row['statementMap'], row['s'] = {}, {}
        for result in self.b.measure(PRICING):
            self.assertEqual(result['states']['coverage.line'], 'not_applicable')
            self.assertNotIn('coverage.line', result['values'])
        row['fnMap'], row['f'] = {}, {}
        self.b.index[PRICING]['functions'] = []
        result = self.b.measure(PRICING)[0]
        self.assertEqual(result['states']['coverage.function'], 'not_applicable')
        self.assertNotIn('coverage.function', result['values'])

    def test_bundled_map_keeps_exactly_one_original_source_per_subject(self):
        expected = self.b.measure(PRICING)
        name = self.map_name()
        mapping = json.loads(self.b.artifacts[name])
        mapping['sources'].append('src/duplicate.ts')
        mapping['sourcesContent'].append(mapping['sourcesContent'][0])
        self.b.sources['src/duplicate.ts'] = self.b.sources[PRICING]
        # Map an additional emitted line to a second, byte-identical source.
        mapping['mappings'] += ';ACAA'
        self.b.artifacts[name] = json.dumps(mapping).encode()
        self.b.artifacts[name[:-4]] += b'\n\n//# sourceMappingURL=' + Path(name).name.encode()
        self.assertEqual(self.b.measure(PRICING), expected)

    def test_invalid_and_incomplete_counters_do_not_become_defaults(self):
        for value in (-1, True, 0.5, '1'):
            self.b.native[PRICING]['s']['0'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'counter'):
                self.b.measure(PRICING)
        self.b = copy.deepcopy(self.bundle)
        del self.b.native[PRICING]['f']['0']
        with self.assertRaisesRegex(ValueError, 'incomplete native counters'):
            self.b.measure(PRICING)

    def test_utf16_coordinates_and_invalid_columns(self):
        ts.position({'line': 1, 'column': 3}, 'a😀')
        with self.assertRaisesRegex(ValueError, 'UTF-16'):
            ts.position({'line': 1, 'column': 4}, 'a😀')

    def test_every_tool_boundary_and_normalization_change_breaks_series_compatibility(self):
        base = ts.measurement_series(self.b.toolchain, 'node-jsdom', 'production-ts')
        evidence.require_compatible_series(base, copy.deepcopy(base))
        for field in ('typescript', 'builder', 'test_builder', 'runner', 'coverage_provider',
                      'angular', 'cli', 'npm', 'node', 'dom', 'measured_environment', 'configuration_digests'):
            toolchain = copy.deepcopy(self.b.toolchain)
            toolchain[field] = str(toolchain[field]) + '-changed'
            head = ts.measurement_series(toolchain, 'node-jsdom', 'production-ts')
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'explicit migration'):
                evidence.require_compatible_series(base, head)
        for kwargs in ({'target': 'browser'}, {'boundary': 'tests'}, {'mapping': 'v2'}, {'normalization': 'v2'}):
            args = {'target': 'node-jsdom', 'boundary': 'production-ts', **kwargs}
            with self.subTest(args=args), self.assertRaisesRegex(ValueError, 'explicit migration'):
                evidence.require_compatible_series(base, ts.measurement_series(self.b.toolchain, **args))
        rust = json.loads((FIXTURE.parents[1] / 'fixtures/harness-evidence/polyglot.json').read_text())[0]['series']
        with self.assertRaisesRegex(ValueError, 'explicit migration'):
            evidence.require_compatible_series(rust, base)


if __name__ == '__main__':
    unittest.main()
