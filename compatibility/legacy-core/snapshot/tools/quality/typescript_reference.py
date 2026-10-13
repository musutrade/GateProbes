#!/usr/bin/env python3
"""Version 1 retained TypeScript/Angular collector; no policy decisions."""
from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tarfile

import harness_evidence as evidence
import project_model as model
import typescript_semantics as ts

COLLECTOR = {'name': 'typescript-reference', 'version': '1'}
require = evidence.require


def binding(request):
    """Caller receipt binds replay identity and scope, independent of native time."""
    return {**{key: request[key] for key in ('project', 'component', 'collector',
                                           'context', 'requested_capabilities')},
            'subjects': request['parameters']['subjects']}


def read_input(root, relative):
    model.canonical_path(relative)
    path = root / relative
    require(path.resolve(strict=True).is_relative_to(root), 'input escapes workspace')
    require(path.is_file() and not path.is_symlink(), 'input must be a regular file')
    return path.read_bytes()


def project(request):
    require(request['collector'] == COLLECTOR and request['component'] == 'typescript',
            'unsupported collector/component')
    parameters = request['parameters']
    require(set(parameters) == {'native', 'index', 'receipt', 'subjects'},
            'unknown or missing TypeScript collection parameter')
    receipt = parameters['receipt']
    require(set(receipt) == {'schema', 'request', 'native_revision', 'native_sha256',
                             'index_sha256', 'coverage_root'}, 'invalid replay receipt')
    require(receipt['schema'] == 'typescript-collector-replay/v1' and
            receipt['request'] == binding(request), 'replay request provenance mismatch')
    subjects = parameters['subjects']
    require(isinstance(subjects, list) and subjects, 'empty subject scope')
    require(len({s['id'] for s in subjects}) == len(subjects), 'duplicate requested subject')
    root, output = Path(request['workspace_root']), Path(request['output_root'])
    native = read_input(root, parameters['native'])
    index = read_input(root, parameters['index'])
    sources = {p.relative_to(root / 'app').as_posix(): read_input(root, p.relative_to(root).as_posix())
               for p in (root / 'app/src').rglob('*') if p.is_file()}
    bundle = ts.read_bundle(native, index, receipt, sources)
    # A retained run predates the replay. Preserve and verify its revision instead
    # of relabeling its manifest as a new live tool execution.
    with tarfile.open(fileobj=io.BytesIO(native), mode='r:gz') as archive:
        manifest = ts.decode_json(archive.extractfile('manifest.json').read())
    require(manifest['revision'] == receipt['native_revision'], 'native revision provenance mismatch')
    for path, digest in manifest['configuration_digests'].items():
        require(ts.digest(read_input(root, path)) == digest, 'stale requested configuration')

    records, artifacts, retained = [], [], {}
    for subject in subjects:
        require(subject['id'] == model.subject_id(request['project'], subject) and
                subject['component'] == request['component'] and
                subject['target'] == request['context']['target'], 'subject provenance mismatch')
        path = subject['path']
        require(path.startswith('app/src/'), 'subject outside TypeScript source snapshot')
        relative = path.removeprefix('app/')
        require(relative in sources and ts.digest(sources[relative]) == subject['source_sha256'],
                'stale requested subject')
        info = bundle.index.get(relative)
        reason = 'outside measured TypeScript capability matrix'
        values, states = {}, {}
        if subject['kind'] == 'route/v1':
            reason = 'route execution is not measured by source coverage'
        elif relative.endswith('.html') or (info and (info['template'] or info['generated'])):
            reason = 'template/generated source mapping is unsupported'
        else:
            require(info is not None, 'source has no parser identity')
            rows = bundle.measure(relative, project=request['project'],
                                  target=subject['target'], boundary=subject['boundary'])
            matches = [row for row in rows if row['subject']['id'] == subject['id']]
            require(len(matches) == 1, 'unknown or ambiguous requested source identity')
            values, states = matches[0]['values'], matches[0]['states']
        # v1 has one capability set per request, applied to EVERY returned subject.
        # Extend the series contract for requested generic metrics we cannot measure.
        series = ts.measurement_series(bundle.toolchain, subject['target'], subject['boundary'])
        metrics = sorted(set(ts.METRICS) | set(request['requested_capabilities']))
        series['metrics'] = [{'name': m, 'type': evidence.METRIC_TYPES[m]} for m in metrics]
        series['id'] = evidence.series_id(series)
        source = {'path': path, 'sha256': subject['source_sha256']}
        if path not in retained:
            refs = []
            prefix = 'source-' + ts.fingerprint(source)
            for name, data, media in [('native.tar.gz', native, 'application/gzip'),
                                      ('source-index.json', index, 'application/json'),
                                      ('receipt.json', evidence._canonical(receipt), 'application/json')]:
                destination = prefix + '/' + name
                (output / prefix).mkdir(exist_ok=True)
                (output / destination).write_bytes(data)
                refs.append({'id': prefix + '.' + name, 'kind': 'raw', 'media_type': media,
                             'path': destination, 'sha256': ts.digest(data), 'bytes': len(data),
                             'context': request['context'], 'source': source})
            retained[path] = refs
            artifacts.extend(refs)
        refs = retained[path]
        links = [ref['id'] for ref in refs]
        capabilities = []
        for metric in metrics:
            state = states.get(metric, 'unsupported')
            explanation = ('native Istanbul original-source counters' if state == 'supported' else
                           'native denominator is zero' if state == 'not_applicable' else reason)
            capabilities.append({'metric': metric, 'state': state, 'reason': explanation,
                                 'artifacts': links})
        records.append({'schema': 'harness-evidence/v1',
                        'id': 'typescript-' + subject['id'].split(':')[1],
                        'project': request['project'], 'component': request['component'],
                        'collector': COLLECTOR, 'series': series, 'subject': subject,
                        'context': request['context'], 'source': source,
                        'metrics': [{'name': m, 'value': v, 'artifacts': links}
                                    for m, v in sorted(values.items())],
                        'capabilities': capabilities, 'artifacts': refs,
                        'status': 'measured' if values else 'unavailable'})
    return {'schema': 'harness-collector-response/v1', 'evidence': records,
            'artifacts': artifacts, 'error': None}


def collect(request):
    """Use via collector_runner; both transports share its validation boundary."""
    try:
        return project(request)
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, OSError,
            RuntimeError, tarfile.TarError) as error:
        return {'schema': 'harness-collector-response/v1', 'evidence': [], 'artifacts': [],
                'error': {'code': 'measurement_error', 'message': str(error) or type(error).__name__}}


if __name__ == '__main__':
    json.dump(collect(ts.decode_json(sys.stdin.buffer.read())), sys.stdout, allow_nan=False)
    sys.stdout.write('\n')
