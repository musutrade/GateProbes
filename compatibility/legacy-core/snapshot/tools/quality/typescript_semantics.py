#!/usr/bin/env python3
"""TypeScript identity/measurement primitives; not a collector or policy engine."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import PurePosixPath
import tarfile

import harness_evidence as evidence
import project_model as model

require = evidence.require
IDENTITY = 'typescript-original-source/v1'
MAPPING = 'typescript-sourcemap-v3/v1'
NORMALIZATION = 'istanbul-start-line-max-innermost/v1'
METRICS = ('complexity.cognitive', 'complexity.cyclomatic', 'coverage.branch', 'coverage.function',
           'coverage.line', 'risk.crap')
BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(value):
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def decode_json(data):
    def unique_fields(items):
        result = {}
        for key, value in items:
            require(key not in result, 'ambiguous duplicate JSON field')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique_fields,
                      parse_constant=lambda value: require(False, 'nonfinite JSON value'))


def point(value):
    return value['line'], value['column']


def utf16_width(text):
    return len(text.encode('utf-16-le')) // 2


def position(value, source, nullable=False):
    lines = source.split('\n')
    line, column = point(value)
    require(type(line) is int and 1 <= line <= len(lines), 'invalid original line')
    require((nullable and column is None) or
            (type(column) is int and 0 <= column <= utf16_width(lines[line - 1])),
            'invalid original UTF-16 column')


def vlq(segment):
    values, value, shift = [], 0, 0
    for char in segment:
        require(char in BASE64, 'invalid source-map VLQ')
        digit = BASE64.index(char)
        value |= (digit & 31) << shift
        require(shift < 35, 'source-map VLQ overflow')
        if digit & 32:
            shift += 5
        else:
            values.append(-(value >> 1) if value & 1 else value >> 1)
            value, shift = 0, 0
    require(shift == 0 and len(values) in (1, 4, 5), 'incomplete source-map segment')
    return values


def validate_map(mapping, emitted, sources):
    """Validate regular v3 maps, including every mapped coordinate and source byte."""
    require(mapping.get('version') == 3 and 'sections' not in mapping and
            not mapping.get('sourceRoot'), 'unsupported source-map structure')
    paths, contents = mapping.get('sources'), mapping.get('sourcesContent')
    require(isinstance(paths, list) and paths and isinstance(contents, list) and
            len(paths) == len(contents) and len(set(paths)) == len(paths),
            'incomplete or ambiguous source-map sources')
    for path, content in zip(paths, contents):
        model.canonical_path(path)
        require(path.startswith('src/') and path in sources, 'unbound source-map path')
        require(isinstance(content, str) and content.encode() == sources[path],
                'stale source-map source content')
    names = mapping.get('names')
    require(isinstance(names, list) and all(isinstance(n, str) for n in names),
            'missing source-map names')
    mappings = mapping.get('mappings')
    require(isinstance(mappings, str) and mappings, 'missing source-map mappings')
    generated_lines = emitted.split('\n')
    source_index = original_line = original_column = name_index = 0
    mapped = {path: set() for path in paths}
    for line, encoded in enumerate(mappings.split(';')):
        require(line < len(generated_lines), 'source-map generated line outside emitted output')
        generated_column, previous = 0, -1
        for segment in encoded.split(',') if encoded else []:
            fields = vlq(segment)
            generated_column += fields[0]
            require(previous < generated_column <= utf16_width(generated_lines[line]),
                    'ambiguous or invalid generated coordinate')
            previous = generated_column
            if len(fields) == 1:
                continue
            source_index += fields[1]
            original_line += fields[2]
            original_column += fields[3]
            require(0 <= source_index < len(paths), 'invalid source-map source index')
            position({'line': original_line + 1, 'column': original_column}, contents[source_index])
            if len(fields) == 5:
                name_index += fields[4]
                require(0 <= name_index < len(names), 'invalid source-map name index')
            mapped[paths[source_index]].add((original_line + 1, original_column))
    require(all(mapped.values()), 'incomplete source-map provenance')
    return mapped


def read_bundle(archive_bytes, index_bytes, receipt, current_sources):
    """Receipt is caller-owned trust input, never read from the measured archive.

    Current source bytes must be supplied from the requested revision. The replay
    receipt pins the complete native archive and the separately collected AST index.
    A live caller must bind equivalent digests to its request in task 3.1.
    """
    require(digest(archive_bytes) == receipt['native_sha256'], 'native artifact integrity mismatch')
    require(digest(index_bytes) == receipt['index_sha256'], 'parser index integrity mismatch')
    artifacts = {}
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r:gz') as archive:
        for member in archive.getmembers():
            require(member.isfile(), 'non-file native artifact')
            model.canonical_path(member.name)
            require(member.name not in artifacts, 'duplicate native artifact')
            artifacts[member.name] = archive.extractfile(member).read()
    manifest = decode_json(artifacts.pop('manifest.json'))
    require(manifest['schema'] == 'angular-native-fixture/v1' and manifest['status'] == 'complete',
            'incomplete native collection')
    require(manifest['commands'] and all(c['exit_status'] == 0 for c in manifest['commands']),
            'failed native command')
    require(artifacts.keys() == manifest['artifacts'].keys(), 'incomplete native artifact inventory')
    for name, data in artifacts.items():
        ref = manifest['artifacts'][name]
        require(len(data) == ref['bytes'] and digest(data) == ref['sha256'],
                'native inventory integrity mismatch')
    for name, sha in manifest['configuration_digests'].items():
        require(digest(artifacts['sources/' + name]) == sha, 'configuration integrity mismatch')
    sources = {name.removeprefix('sources/app/'): data for name, data in artifacts.items()
               if name.startswith('sources/app/src/')}
    require(sources == current_sources, 'stale or incomplete requested source snapshot')
    index = decode_json(index_bytes)
    require(index['schema'] == 'typescript-source-index/v1' and index['compiler'] == '6.0.2',
            'unsupported source identity parser')
    expected_files = {p for p in sources if p.endswith('.ts') and not p.endswith('.spec.ts')}
    require(set(index['files']) == expected_files, 'incomplete parser source inventory')
    for path, info in index['files'].items():
        require(info['sha256'] == digest(sources[path]), 'stale parser identity')
    coverage_names = [n for n in artifacts if n.endswith('/coverage-final.json')]
    require(len(coverage_names) == 1, 'ambiguous native coverage')
    coverage = decode_json(artifacts[coverage_names[0]])
    prefix = receipt['coverage_root'].rstrip('/') + '/'
    native = {}
    for path, row in coverage.items():
        require(path == row['path'] and path.startswith(prefix), 'unbound coverage path; no basename joins')
        relative = path[len(prefix):]
        model.canonical_path(relative)
        require(relative in index['files'] and relative not in native, 'unknown or ambiguous original source')
        native[relative] = row
    toolchain = decode_json(artifacts['sources/toolchain.json'])
    require(index['compiler'] == toolchain['typescript'] and
            manifest['runtime']['node'] == 'v' + toolchain['node'], 'compiler/runtime mismatch')
    toolchain['configuration_digests'] = manifest['configuration_digests']
    return Bundle(artifacts, sources, index['files'], native, toolchain)


class Bundle:
    def __init__(self, artifacts, sources, index, native, toolchain):
        self.artifacts, self.sources, self.index = artifacts, sources, index
        self.native, self.toolchain = native, toolchain

    def maps_for(self, path):
        matches = []
        for name, data in self.artifacts.items():
            if not name.startswith('test-build/') or not name.endswith('.js.map'):
                continue
            mapping = decode_json(data)
            if path not in mapping.get('sources', []):
                continue
            emitted_name = name.removesuffix('.map')
            require(emitted_name in self.artifacts, 'missing emitted source-map artifact')
            emitted = self.artifacts[emitted_name].decode()
            require(emitted.rstrip().endswith('//# sourceMappingURL=' + PurePosixPath(name).name),
                    'emitted source-map linkage mismatch')
            coordinates = validate_map(mapping, emitted, self.sources)
            require(path in self.native, 'coverage not collected')
            row = self.native[path]
            required = {point(span['start']) for span in row['statementMap'].values()}
            required.update(point(fn['decl']['start']) for fn in row['fnMap'].values())
            require(required <= coordinates[path], 'incomplete measured source-map coordinates')
            matches.append(name)
        require(len(matches) == 1, 'missing or ambiguous original source-map provenance')
        return matches

    def measure(self, path, project='typescript-reference', target='node-jsdom', boundary='production-ts'):
        """Return atomic semantic rows only after validation; no favorable partial batch."""
        model.canonical_path(path)
        require(path in self.index, 'unknown original source; no basename joins')
        info = self.index[path]
        if info['template'] or info['generated']:
            return [{'path': path, 'states': {m: 'unsupported' for m in METRICS}, 'values': {}}]
        maps = self.maps_for(path)
        require(path in self.native, 'coverage not collected')
        source, row = self.sources[path].decode(), self.native[path]
        validate_counters(row, source)
        functions = info['functions']
        joined = {}
        for key, native in row['fnMap'].items():
            candidates = [f for f in functions if f['declaration'] == native['decl']['start'] and
                          point(f['declaration']) <= point(native['loc']['start']) <= point(f['body']) and
                          f['end']['line'] == native['loc']['end']['line'] and
                          (native['loc']['end']['column'] is None or
                           f['end']['column'] == native['loc']['end']['column'])]
            require(len(candidates) == 1, 'ambiguous or fabricated function identity')
            function = candidates[0]
            require(function not in joined.values(), 'duplicate native function identity')
            joined[key] = function
        require(len(joined) == len(functions), 'incomplete native function coverage')
        scopes = [(None, list(row['s']), list(row['f']))]
        for key, function in joined.items():
            statements = []
            for sid, span in row['statementMap'].items():
                start = point(span['start'])
                owners = [f for f in functions if point(f['body']) <= start < point(f['end'])]
                # Nested function statements belong only to the innermost function.
                if owners and max(owners, key=lambda f: point(f['start'])) == function:
                    statements.append(sid)
            scopes.append((function, statements, [key]))
        results = []
        for function, statements, keys in scopes:
            subject = source_subject(project, path, info, function, target, boundary)
            lines = {}
            for key in statements:
                line = row['statementMap'][key]['start']['line']
                lines[line] = max(lines.get(line, 0), row['s'][key])
            values, states = {}, {m: 'unsupported' for m in METRICS}
            for metric, counters in [('coverage.line', list(lines.values())),
                                     ('coverage.function', [row['f'][k] for k in keys])]:
                state, value = ratio(counters)
                states[metric] = state
                if value is not None:
                    values[metric] = value
            results.append({'subject': subject, 'values': values, 'states': states,
                            'maps': maps, 'series': measurement_series(self.toolchain, target, boundary)})
        return results


def validate_counters(row, source):
    for mapping, counters in [('statementMap', 's'), ('fnMap', 'f'), ('branchMap', 'b')]:
        require(isinstance(row[mapping], dict) and row[mapping].keys() == row[counters].keys(),
                'incomplete native counters')
        for key, value in row[counters].items():
            values = value if counters == 'b' else [value]
            require(isinstance(values, list) and all(type(n) is int and n >= 0 for n in values),
                    'invalid native counter')
            if counters == 'b':
                require(len(values) == len(row[mapping][key]['locations']), 'incomplete branch counters')
    for span in row['statementMap'].values():
        # Istanbul line coverage uses start coordinates, not generated end spans.
        position(span['start'], source)
    for fn in row['fnMap'].values():
        for span in (fn['decl'], fn['loc']):
            position(span['start'], source)
            position(span['end'], source, nullable=True)
            require(span['start']['line'] <= span['end']['line'], 'reversed native function range')


def ratio(counters):
    if not counters:
        return 'not_applicable', None
    return 'supported', {'type': 'ratio', 'covered': sum(n > 0 for n in counters), 'total': len(counters)}


def source_subject(project, path, info, function, target, boundary):
    discriminator = IDENTITY + ':file'
    subject = {'id': 'subject-identity/v1:' + '0' * 64, 'identity_version': 'subject-identity/v1',
               'component': 'typescript', 'target': target, 'boundary': boundary,
               'kind': 'file/v1', 'path': 'app/' + path, 'source_sha256': info['sha256'],
               'metadata': {}}
    if function:
        start, end = function['start'], function['end']
        discriminator = f"{IDENTITY}:{function['name']}:{point(start)}:{point(end)}"
        subject.update(kind=function['kind'], span={'start_line': start['line'],
                       'start_column': start['column'] + 1, 'end_line': end['line'],
                       'end_column': end['column'] + 1})
    subject['discriminator'] = discriminator
    subject['id'] = model.subject_id(project, subject)
    return subject


def measurement_series(toolchain, target, boundary, mapping=MAPPING, normalization=NORMALIZATION):
    semantics = {'ecosystem': 'typescript', 'compiler': toolchain['typescript'],
                 'builder': toolchain['builder'], 'test_builder': toolchain['test_builder'],
                 'runner': toolchain['runner'], 'provider': toolchain['coverage_provider'],
                 'angular': toolchain['angular'], 'cli': toolchain['cli'], 'npm': toolchain['npm'],
                 'runtime': toolchain['node'], 'dom': toolchain['dom'],
                 'environment': toolchain['measured_environment'],
                 'configuration_digests': toolchain['configuration_digests'], 'target': target,
                 'boundary': boundary, 'mapping': mapping, 'identity': IDENTITY,
                 'normalization': normalization,
                 'rules': 'named-and-anonymous-ast;no-template-generated-branch-risk/v1'}
    series = {'name': 'typescript-source-coverage',
              'collector': {'name': 'typescript-reference', 'version': '1'},
              'tool': {'name': 'typescript-toolchain', 'version': fingerprint(semantics)},
              'rule': {'name': 'typescript-source-coverage', 'version': fingerprint(semantics)},
              'runtime': {'name': 'node-jsdom', 'version': toolchain['node'] + '/' + toolchain['dom']},
              'target': target, 'source_identity': {'name': IDENTITY, 'version': '1'},
              'normalization': {'name': normalization, 'version': '1'},
              'metrics': [{'name': m, 'type': evidence.METRIC_TYPES[m]} for m in METRICS]}
    series['id'] = evidence.series_id(series)
    return evidence.validate_series(series)
