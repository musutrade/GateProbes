#!/usr/bin/env python3
"""Non-authoritative Python oracle replay of the GH-146 frozen corpus."""
import argparse
from datetime import datetime
import hashlib
import gzip
import json
from pathlib import Path
import sys
import tarfile
import tempfile

QUALITY = Path(__file__).resolve().parents[2]
REPO = QUALITY.parents[1]
sys.path.insert(0, str(QUALITY))
import harness_evidence as evidence
import policy_engine as engine
import project_model as model
import project_report

ROOT = Path(__file__).resolve().parent


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')


def same_json(expected, actual):
    """Compare exact JSON types without pretty-printing transient strings.

    Keep canonical() unchanged for persisted evidence. Compact encoding uses
    the C encoder where available, while retaining its JSON and UTF-8 errors
    and distinctions such as True/1 and 1/1.0 that Python equality loses.
    Neither an oracle result nor a mutable input is cached.
    """
    def encoded(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False).encode('utf-8')
    return encoded(expected) == encoded(actual)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def payload(path):
    """Compression is storage only; compare exact canonical uncompressed bytes."""
    return gzip.decompress(path.read_bytes()) if path.suffix == '.gz' else path.read_bytes()


def missing_file_source(value):
    """Identify only native ENOENT/file-or-path-not-found diagnostics."""
    if not isinstance(value, str) or not value.startswith('artifact/source '):
        return None
    source, separator, reason = value.partition(': ')
    prefixes = ('[Errno 2] No such file or directory', 'No such file or directory',
                '[WinError 2] The system cannot find the file specified',
                '[WinError 3] The system cannot find the path specified',
                'The system cannot find the file specified. (os error 2)',
                'The system cannot find the path specified. (os error 3)')
    return source if separator and reason.startswith(prefixes) else None


def oracle_matches(expected, actual, path=''):
    """Preserve every semantic field; allow only known OS missing-file wording."""
    if same_json(expected, actual):
        return True
    if isinstance(expected, dict) and isinstance(actual, dict):
        return expected.keys() == actual.keys() and all(
            oracle_matches(value, actual[key], path + '/' + key)
            for key, value in expected.items())
    if isinstance(expected, list) and isinstance(actual, list):
        return len(expected) == len(actual) and all(
            oracle_matches(a, b, path + '/' + str(i))
            for i, (a, b) in enumerate(zip(expected, actual)))
    source = missing_file_source(expected)
    return path.endswith('/reason') and source is not None and source == missing_file_source(actual)


def portable_errors(value, work):
    """Remove only the replay-owned temporary prefix from OS error reasons."""
    if isinstance(value, dict):
        return {key: (item.replace(str(work), '$CASE_ROOT')
                      if key == 'reason' and isinstance(item, str)
                      else portable_errors(item, work)) for key, item in value.items()}
    if isinstance(value, list):
        return [portable_errors(item, work) for item in value]
    return value


def materialize(value, blobs, root):
    roots = {}
    for kind in ('source', 'artifact'):
        destination = root / kind
        destination.mkdir(parents=True)
        for name, sha in value['files'][kind].items():
            model.canonical_path(name)
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(blobs[sha])
        roots[kind + '_root'] = destination
    return dict(project=value['project'], expected=value['expected'], **roots)


def evaluate(case, blobs, work):
    def context(side):
        return materialize(case[side], blobs, work / side)

    head = context('head')
    result = {}
    try:
        evidence.validate_evidence(case['head']['records'], **head)
        result['validation'] = dict(accepted=True)
    except (evidence.MeasurementError, model.ModelError) as error:
        result['validation'] = dict(accepted=False, reason_class=type(error).__name__,
                                    reason=str(error))
    options = {key: case[key] for key in ('selection', 'mappings', 'exceptions', 'now')
               if key in case}
    if 'now' in options:
        options['now'] = datetime.fromisoformat(options['now'].replace('Z', '+00:00'))
    if 'base' in case:
        options.update(base_records=case['base']['records'], base_context=context('base'))
    try:
        policy_result = engine.evaluate(case['policy'], case['head']['records'], **head, **options)
        result['policy_result'] = policy_result
        result['project_report'] = project_report.report(policy_result, head['project'], case['policy'])
    except (evidence.MeasurementError, model.ModelError) as error:
        result['evaluation_error'] = dict(reason_class=type(error).__name__, reason=str(error))
    return portable_errors(result, work)


def load_corpus(root=ROOT):
    manifest = evidence.load_json(root / 'manifest.json')
    if manifest['schema'] != 'generic-core-corpus/v1':
        raise ValueError('unknown corpus schema')
    for name, sha in manifest['files'].items():
        if digest((root / name).read_bytes()) != sha:
            raise ValueError('changed corpus file: ' + name)
    for name, sha in manifest['schemas'].items():
        if digest((REPO / name).read_bytes()) != sha:
            raise ValueError('changed external schema: ' + name)
    with tarfile.open(root / 'artifacts.tar.gz') as archive:
        blobs = {}
        for member in archive.getmembers():
            if not member.isfile() or member.name in blobs:
                raise ValueError('invalid corpus blob member')
            data = archive.extractfile(member).read()
            if digest(data) != member.name:
                raise ValueError('changed corpus blob: ' + member.name)
            blobs[member.name] = data
    return manifest, blobs


def replay(root=ROOT):
    manifest, blobs = load_corpus(root)
    results = []
    with tempfile.TemporaryDirectory() as directory:
        for item in manifest['cases']:
            case = json.loads(payload(root / item['input']))
            actual = evaluate(case, blobs, Path(directory) / item['id'])
            expected = payload(root / item['expected'])
            if not oracle_matches(json.loads(expected), actual):
                raise ValueError('oracle mismatch: ' + item['id'])
            results.append(dict(id=item['id'], state=actual.get('policy_result', {}).get(
                'aggregate', {}).get('state', 'rejected')))
    return dict(schema='generic-core-corpus-replay/v1', authoritative=False,
                cases=results, passed=len(results))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = replay()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical(result))
    print(f"Passed {result['passed']} frozen Python oracle cases (non-authoritative)")
