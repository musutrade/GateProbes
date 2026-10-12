#!/usr/bin/env python3
"""Independent Harness-Gate Rust source-risk collector, adapter protocol v2."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from measure import measure, strict_json

HERE = Path(__file__).resolve().parent
COLLECTOR = {'name': 'rust-source-risk', 'version': '0.1.0-rc.7'}
TYPES = {'complexity.cyclomatic': 'count', 'coverage.function': 'ratio',
         'coverage.line': 'ratio', 'coverage.region': 'ratio', 'risk.crap': 'rational'}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def sha(value):
    return hashlib.sha256(value).hexdigest()

def require(condition, message):
    if not condition:
        raise ValueError(message)

def relative(value):
    p = Path(value)
    require(not p.is_absolute() and str(p) == value and '..' not in p.parts and value not in ('', '.')
            and not any(c in value for c in '\\:\x00\n\r'), 'noncanonical relative path')
    return p

def file(root, name):
    p = Path(root)
    for part in relative(name).parts:
        p = p / part
        require(not p.is_symlink(), 'symlink input')
    require(p.is_file(), 'missing input file')
    return p

def inventory(request):
    root = Path(request['workspace_root'])
    require(root.is_absolute() and root.resolve() == root, 'noncanonical workspace root')
    roots = request['parameters']['source_roots']
    require(roots and len(roots) == len(set(roots)), 'invalid source roots')
    sources = {}
    for name in roots:
        current = root
        for part in relative(name).parts:
            current /= part
            require(current.is_dir() and not current.is_symlink(), 'invalid source root')
        for p in sorted(current.rglob('*')):
            require(not p.is_symlink(), 'symlink in source inventory')
            if p.is_file() and p.suffix == '.rs':
                key = p.relative_to(root).as_posix()
                require(key not in sources, 'overlapping source roots')
                sources[key] = sha(p.read_bytes())
    require(sources, 'empty production inventory')
    return dict(sorted(sources.items()))

def subject(request, row):
    value = {'identity_version': 'subject-identity/v1', 'component': request['component'],
             'target': request['context']['target'], 'boundary': request['parameters']['boundary'],
             'kind': 'function/v1', 'path': row['source'],
             'discriminator': 'rust-source-ast/v1:' + row['kind'] + ':' + ':'.join(map(str, row['start'] + row['end'])),
             'span': dict(zip(('start_line', 'start_column', 'end_line', 'end_column'), row['start'] + row['end'])),
             'source_sha256': row['source_sha256']}
    return {'id': 'subject-identity/v1:' + sha(canonical({'project': request['project'], **value}).encode()), **value, 'metadata': {}}

def series(request):
    receipt = request['parameters']['receipt']
    implementation = {name: sha((HERE / name).read_bytes()) for name in ('plugin.py', 'measure.py', 'inventory', 'ast/Cargo.lock', 'capture.py')}
    pipeline = json.loads(canonical(receipt['pipeline']))
    for tool in pipeline['tools'].values():
        if isinstance(tool, dict):
            tool.pop('path', None)
    value = {'name': 'rust-source-function-risk', 'collector': COLLECTOR,
             'tool': {'name': 'rust-llvm-source-coverage', 'version': sha(canonical(pipeline).encode())},
             'rule': {'name': 'rust-explicit-decisions', 'version': sha(canonical(implementation).encode())},
             'runtime': {'name': 'python', 'version': platform.python_version()},
             'target': request['context']['target'],
             'source_identity': {'name': 'rust-source-ast/v1', 'version': '1'},
             'normalization': {'name': 'llvm-source-innermost-lines/v1', 'version': '1'},
             'metrics': [{'name': k, 'type': v} for k, v in sorted(TYPES.items())]}
    return {'id': 'measurement-series/v1:' + sha(canonical(value).encode()), **value}

def reexport(request, destination):
    receipt = request['parameters']['receipt']
    require(receipt['schema'] == 'rust-source-capture/v1', 'invalid capture receipt')
    root = Path(request['workspace_root'])
    sources = inventory(request)
    require(receipt['sources'] == sources, 'stale/incomplete source inventory')
    require(receipt['context'] == request['context'], 'capture context mismatch')
    for name, digest in receipt['inputs'].items():
        require(sha(file(root, name).read_bytes()) == digest, 'capture input changed: ' + name)
    for name, digest in receipt['pipeline']['files'].items():
        require(sha(file(root, name).read_bytes()) == digest, 'pipeline configuration changed: ' + name)
    raw = Path(receipt['raw_root'])
    require(raw.is_absolute() and raw.resolve() == raw, 'invalid raw capture root')
    for name, digest in receipt['raw'].items():
        require(sha(file(raw, name).read_bytes()) == digest, 'raw capture changed: ' + name)
    for kind in ('llvm-cov', 'llvm-profdata'):
        tool = receipt['pipeline']['tools'][kind]
        p = Path(tool['path'])
        require(p.is_absolute() and sha(p.read_bytes()) == tool['sha256'], 'LLVM tool changed')
    profiles = receipt['profiles']
    objects = receipt['objects']
    require(profiles and objects and len(set(profiles)) == len(profiles) and len(set(objects)) == len(objects), 'empty/duplicate capture objects')
    require(set(profiles + objects) == set(receipt['raw']), 'incomplete raw capture inventory')
    with tempfile.TemporaryDirectory(prefix='rust-source-reexport-') as tmp:
        profdata = Path(tmp) / 'merged.profdata'
        subprocess.run([receipt['pipeline']['tools']['llvm-profdata']['path'], 'merge', '-sparse',
                        *[str(file(raw, n)) for n in profiles], '-o', str(profdata)], check=True, capture_output=True)
        command = [receipt['pipeline']['tools']['llvm-cov']['path'], 'export', '-format=text', '-instr-profile=' + str(profdata)]
        for name in objects:
            command += ['-object', str(file(raw, name))]
        with open(destination, 'xb') as output:
            subprocess.run(command, check=True, stdout=output, stderr=subprocess.PIPE)
    return measure(root, list(sources), destination, HERE / 'inventory', receipt['coverage_root'])

def discover(request):
    with tempfile.TemporaryDirectory(prefix='rust-source-discovery-') as tmp:
        rows = reexport(request, Path(tmp) / 'coverage.json')['functions']
    return [subject(request, row) for row in rows]

def collect(request):
    require(request['schema'] == 'harness-collector-request/v1' and request['collector'] == COLLECTOR, 'collector mismatch')
    require(sorted(request['requested_capabilities']) == sorted(TYPES), 'incomplete measurement series capabilities')
    output = Path(request['output_root'])
    require(output.is_absolute() and output.resolve() == output and output.is_dir(), 'invalid artifact root')
    prefix = relative(request['parameters']['artifact_subdir'])
    require(len(prefix.parts) == 1, 'artifact subdirectory must be one component')
    target = output / prefix
    require(not target.exists() and not target.is_symlink(), 'artifact subdirectory must be fresh')
    require(not Path(request['workspace_root']).is_relative_to(target), 'output contains sources')
    # Compute first; failed validation cannot leave seemingly usable evidence.
    with tempfile.TemporaryDirectory(prefix='rust-source-collect-') as tmp:
        llvm = Path(tmp) / 'coverage.json'
        result = reexport(request, llvm)
        subjects = [subject(request, row) for row in result['functions']]
        require(subjects == request['parameters']['subjects'], 'incomplete host subject inventory')
        identity = series(request)
        target.mkdir(mode=0o700)
        coverage = gzip.compress(llvm.read_bytes(), mtime=0)
        measured_sources = {row['source'] for row in result['functions']}
        refs_by_source = {}
        all_refs = []
        for path, digest in inventory(request).items():
            if path not in measured_sources:
                continue
            refs = []
            for name, data in [('coverage.json.gz', coverage), ('receipt.json', canonical(request['parameters']['receipt']).encode())]:
                artifact_name = sha(path.encode()) + '-' + name
                (target / artifact_name).write_bytes(data)
                refs.append({'id': 'rust-source-' + sha((path + name).encode()), 'kind': 'raw', 'media_type': 'application/gzip' if name.endswith('.gz') else 'application/json',
                             'path': str(prefix / artifact_name), 'sha256': sha(data), 'bytes': len(data), 'context': request['context'],
                             'source': {'path': path, 'sha256': digest}})
            refs_by_source[path] = refs
            all_refs.extend(refs)
    evidence = []
    for row, owner in zip(result['functions'], subjects, strict=True):
        refs = refs_by_source[row['source']]
        links = [r['id'] for r in refs]
        values = {'complexity.cyclomatic': {'type': 'count', 'value': row['complexity']}}
        for name, kind in TYPES.items():
            if name == 'complexity.cyclomatic' or row[name] is None:
                continue
            n, d = row[name]['numerator'], row[name]['denominator']
            values[name] = {'type': kind, **({'covered': n, 'total': d} if kind == 'ratio' else {'numerator': n, 'denominator': d})}
        evidence.append({'schema': 'harness-evidence/v1', 'id': 'rust-source-' + owner['id'].split(':')[1],
                         'project': request['project'], 'component': request['component'], 'collector': COLLECTOR,
                         'series': identity, 'subject': owner, 'context': request['context'],
                         'source': {'path': row['source'], 'sha256': row['source_sha256']},
                         'metrics': [{'name': name, 'value': value, 'artifacts': links} for name, value in sorted(values.items())],
                         'capabilities': [{'metric': name, 'state': 'supported' if name in values else 'not_applicable',
                                           'reason': 'source-owned LLVM counters' if name in values else 'no source denominator', 'artifacts': links} for name in sorted(TYPES)],
                         'artifacts': refs, 'status': 'measured'})
    return {'schema': 'harness-collector-response/v1', 'evidence': evidence, 'artifacts': all_refs, 'error': None}

def project(invocation, args):
    require(invocation['protocol_version'] == 2 and invocation['result_schema_version'] == '1', 'adapter protocol mismatch')
    require(args == invocation['args'] and len(args) == 5 and args[0] == 'project' and args[1] == '--binding' and args[3] == '--binding-sha256', 'signed arguments mismatch')
    for env, field in [('HARNESS_GATE_INVOCATION_ID', 'invocation_id'), ('HARNESS_GATE_STEP_ID', 'step_id'), ('HARNESS_GATE_ARTIFACT_ROOT', 'artifact_root')]:
        require(os.environ.get(env) == invocation[field], 'Core invocation environment mismatch')
    require(sha(Path(args[2]).read_bytes()) == args[4], 'binding digest mismatch')
    binding = strict_json(args[2])
    require(binding['schema'] == 'rust-source-project-binding/v1', 'binding schema mismatch')
    require(binding['input'] == invocation['input'] and binding['config_digest'] == invocation['config_digest'], 'project binding mismatch')
    request = binding['request']
    inner = invocation['input']
    require(inner['schema'] == 'harness-project-collector-request/v1', 'project input schema mismatch')
    require({k: invocation['adapter'][k] for k in ('name', 'version')} == COLLECTOR, 'adapter identity mismatch')
    for name in ('project', 'collector', 'context', 'workspace_root', 'output_root'):
        require(inner[name] == request[name], 'measurement context mismatch: ' + name)
    require(inner['output_root'] == invocation['artifact_root'] and inner['context']['run'] == invocation['invocation_id'], 'invocation identity mismatch')
    identity = series(request)
    claims = sorted([{'subject': s['id'], 'capability': m, 'series': identity['id']} for s in request['parameters']['subjects'] for m in TYPES], key=lambda c: (c['subject'], c['capability']))
    require(inner['bindings'] == claims, 'incomplete project capability bindings')
    result = collect(request)
    return {'schema_version': '1', 'status': 'PASS', 'invocation_id': invocation['invocation_id'], 'artifacts': result['artifacts'],
            'collection': {'schema': 'harness-project-collector-response/v1', 'evidence': result['evidence'], 'error': None}}

def main():
    if sys.argv[1:2] == ['project']:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as incoming:
            incoming.write(sys.stdin.read()); incoming.flush()
            result = project(strict_json(incoming.name), sys.argv[1:])
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument('command', choices=['discover', 'collect'])
        parser.add_argument('--request', required=True)
        args = parser.parse_args()
        request = strict_json(args.request)
        result = {'subjects': discover(request), 'series': series(request)} if args.command == 'discover' else collect(request)
    print(canonical(result))

if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
