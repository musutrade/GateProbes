#!/usr/bin/env python3
"""Development-only native contract adapter; tool parsing stays outside policy.

Replay is caller-pinned by the receipt digest. Receipts bind every native file,
including commands, source snapshots and generated trees. This is not a signature
or a new collector protocol, and does not grant required-gate authority.
"""
import argparse
import hashlib
import json
from pathlib import Path

import harness_evidence as evidence
import policy_engine as engine
import project_model as model
import project_report

OASDIFF_SHA256 = '0f3f70ea55dc50b8cae7e495f26f1bfc7e9eded1114990241f0b00f89950ba55'
METRICS = ['contract.breaking_changes', 'contract.client_drift', 'contract.compatible']
require = evidence.require


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def inventory(root, exclude=frozenset()):
    result = {}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'symlink in native artifacts')
        relative = path.relative_to(root).as_posix()
        if path.is_file() and relative not in exclude:
            result[relative] = dict(sha256=digest(path), bytes=path.stat().st_size)
    return result


def load_native(root, receipt_sha256):
    require(digest(root / 'receipt.json') == receipt_sha256, 'receipt provenance mismatch')
    receipt = evidence.load_json(root / 'receipt.json')
    require(receipt['schema'] == 'typescript-contract-receipt/v1', 'unknown receipt')
    require(receipt['files'] == inventory(root, exclude={'receipt.json'}),
            'missing, extra or tampered native artifact')
    manifest = evidence.load_json(root / 'manifest.json')
    require(manifest['schema'] == 'typescript-contract-native/v1' and
            manifest['status'] == 'measured', 'contract measurement failed')
    require(manifest['provider'] == 'api' and manifest['consumer'] == 'frontend',
            'native participants mismatch')
    require(manifest['oasdiff_sha256'] == OASDIFF_SHA256 and
            manifest['tools']['oasdiff'] == 'oasdiff version 1.11.7' and
            manifest['tools']['generator'] == '0.29.0' and
            manifest['tools']['node'] == 'v24.18.0' and
            manifest['tools']['npm'] == '11.16.0' and
            manifest['tools']['llvm-cov'] == 'cargo-llvm-cov 0.9.0',
            'native tool provenance mismatch')
    commands = manifest['commands']
    by_name = {c['name']: c for c in commands}
    require(len(by_name) == len(commands), 'duplicate native invocation')
    for name in ('npm-ci', 'base-client', 'head-client', 'oasdiff', 'rust-coverage',
                 'rust-build', 'angular-build', 'angular-test', 'generator-version'):
        require(name in by_name, 'missing native invocation: ' + name)
    for command in commands:
        require(command['exit_status'] == 0, 'native command failed: ' + command['name'])
        for stream in ('stdout', 'stderr'):
            require(command[stream] in receipt['files'], 'missing invocation output')
    for name in ('node', 'npm', 'rustc', 'cargo', 'llvm-cov', 'oasdiff', 'generator'):
        require(name + '-version' in by_name, 'missing native tool version: ' + name)
        version = root / by_name[name + '-version']['stdout']
        require(version.read_text().strip() == manifest['tools'][name], 'tool version output mismatch')
    # Bind actual tool inputs/outputs, not merely a successful exit code.
    original = Path(by_name['oasdiff']['cwd']).parent
    expected_argv = {
        'oasdiff': ['breaking', original / 'baseline.json',
                    original / 'sources/provider/openapi.json', '--format', 'json'],
        'base-client': ['--input', original / 'baseline.json', '--output', original / 'base-client', '--client', 'fetch'],
        'head-client': ['--input', original / 'sources/provider/openapi.json', '--output', original / 'head-client', '--client', 'fetch'],
    }
    for name, argv in expected_argv.items():
        require(by_name[name]['argv'][1:] == [str(a) for a in argv],
                'contract invocation provenance mismatch: ' + name)
    generator = str(original / 'sources/app/node_modules/.bin/openapi')
    require(all(by_name[name]['argv'][0] == generator and
                by_name[name]['cwd'] == str(original / 'sources/app')
                for name in ('base-client', 'head-client', 'generator-version')),
            'generator executable provenance mismatch')
    require(by_name['oasdiff']['argv'][0] == by_name['oasdiff-version']['argv'][0],
            'oasdiff executable provenance mismatch')
    require(manifest['server']['argv'] == [str(original / 'cargo-target/debug/angular-reference-provider')] and
            manifest['server']['url'].startswith('http://127.0.0.1:') and
            by_name['angular-test']['env']['REFERENCE_PROVIDER_URL'] == manifest['server']['url'],
            'live provider invocation mismatch')
    native_argv = {
        'npm-ci': ['npm', 'ci', '--no-audit', '--no-fund'],
        'angular-build': ['npm', 'run', 'build'],
        'angular-test': ['npm', 'exec', '--', 'ng', 'test', '--watch=false', '--coverage'],
        'rust-build': ['cargo', 'build', '--locked'],
        'rust-coverage': ['cargo', 'llvm-cov', '--locked', '--json', '--output-path', str(original / 'rust-coverage.json')],
    }
    for name, argv in native_argv.items():
        component = 'provider' if name.startswith('rust-') else 'app'
        require(by_name[name]['argv'] == argv and by_name[name]['cwd'] == str(original / 'sources' / component),
                'component invocation provenance mismatch: ' + name)
    require(digest(root / 'served-openapi.json') == digest(root / 'sources/provider/openapi.json'),
            'served provider contract mismatch')
    require(inventory(root / 'base-client') and inventory(root / 'head-client'),
            'missing generated client artifacts')
    require(inventory(root / 'base-client') == inventory(root / 'sources/app/src/app/generated'),
            'consumer/generated-client provenance mismatch')
    changes = evidence.load_json(root / by_name['oasdiff']['stdout'])
    require(isinstance(changes, list) and all(isinstance(c, dict) and
            isinstance(c.get('id'), str) and type(c.get('level')) is int and c['level'] in (1, 2, 3) and
            isinstance(c.get('text'), str) and c.get('source') == str(original / 'sources/provider/openapi.json')
            for c in changes), 'invalid oasdiff result')
    return manifest, changes


def project(root, target):
    result = dict(schema='harness-project/v1', id='angular-rust-contract', metadata={},
                  components=[], subjects=[], relationships=[])
    for component, path in [('api', 'provider'), ('frontend', 'app')]:
        result['components'].append(dict(id=component, path=path, metadata={},
            targets=[dict(id=target, boundaries=['source'], metadata={})],
            source_boundaries=[dict(id='source', path=path, role='production', metadata={})]))
    for component, path, kind in [('api', 'provider/openapi.json', 'contract/v1'),
                                   ('api', 'provider/src/main.rs', 'file/v1'),
                                   ('frontend', 'app/src/app/quote-client.ts', 'file/v1')]:
        subject = dict(id='subject-identity/v1:' + '0' * 64, identity_version='subject-identity/v1', component=component,
                       target=target, boundary='source', path=path, kind=kind,
                       discriminator=path, source_sha256=digest(root / 'sources' / path),
                       span=dict(start_line=1, start_column=1,
                                 end_line=len((root / 'sources' / path).read_text().splitlines()), end_column=1),
                       metadata={})
        subject['id'] = model.subject_id(result['id'], subject)
        result['subjects'].append(subject)
    result['relationships'] = [dict(id='quote-client', kind='generated_from/v1', producer='api',
        consumer='frontend', subjects=[s['id'] for s in result['subjects']], metadata={})]
    model.validate_project(result)
    return result


def record(root, project, subject, context, values, tools):
    collector = dict(name='typescript-contract-reference', version='1')
    series = dict(name='native-quote-' + subject['kind'].split('/')[0] + '-' + subject['component'],
                  collector=collector, tool=dict(name='native-contract-toolchain', version=tools),
                  rule=dict(name='oasdiff-and-generated-bytes' if subject['kind'] == 'contract/v1'
                            else 'native-file-function-counters', version='1'),
                  runtime=dict(name='node-rust-linux-x86-64', version='reference-v1'),
                  target=context['target'], source_identity=dict(name='subject-identity', version='1'),
                  normalization=dict(name='typescript-contract-reference', version='1'),
                  metrics=[dict(name=m, type=v['type']) for m, v in sorted(values.items())])
    series['id'] = evidence.series_id(series)
    source = dict(path=subject['path'], sha256=subject['source_sha256'])
    artifacts = [dict(id='raw-' + str(n), kind='raw', media_type='application/octet-stream',
                      path=p, **info, context=context, source=source)
                 for n, (p, info) in enumerate(inventory(root).items())]
    links = [a['id'] for a in artifacts]
    return dict(schema='harness-evidence/v1', id=series['name'], project=project['id'],
                component=subject['component'], collector=collector, series=series, subject=subject,
                context=context, source=source, artifacts=artifacts, status='measured',
                metrics=[dict(name=m, value=v, artifacts=links) for m, v in sorted(values.items())],
                capabilities=[dict(metric=m, state='supported', reason='validated native output',
                                   artifacts=links) for m in sorted(values)])


def normalize(root, receipt_sha256, expected):
    manifest, changes = load_native(root, receipt_sha256)
    require(expected['commit'] == manifest['revision'] == expected['base_commit'] and
            expected['run'] == 'gh133-' + manifest['scenario'] and expected['target'] == 'native-contract',
            'native context provenance mismatch')
    p = project(root, expected['target'])
    base_digest, head_digest = digest(root / 'baseline.json'), digest(root / 'sources/provider/openapi.json')
    drift = inventory(root / 'base-client') != inventory(root / 'head-client')
    # v1 represents generation freshness through the input contract digest. Byte
    # drift without an input change is invalid provenance, never a numeric pass.
    require(drift == (base_digest != head_digest), 'client bytes/input digest provenance mismatch')
    values = {'contract.breaking_changes': dict(type='count', value=len(changes)),
              'contract.client_drift': dict(type='boolean', value=drift),
              'contract.compatible': dict(type='boolean', value=not changes)}
    tools = ';'.join(k + '=' + v for k, v in sorted(manifest['tools'].items()))
    contract = record(root, p, p['subjects'][0], expected, values, tools)
    refs = {a['path']: a['id'] for a in contract['artifacts']}
    contract['contract'] = dict(relationship='quote-client', producer='api', consumer='frontend',
        contract_artifact=refs['sources/provider/openapi.json'],
        baseline=dict(artifact=refs['baseline.json'], commit=expected['base_commit'], series_id=contract['series']['id']),
        consumer_artifact=refs['sources/app/src/app/quote-client.ts'],
        generated_client=dict(artifact=refs['sources/app/src/app/generated/models/Quote.ts'], contract_sha256=base_digest))
    # Bounded local diagnostics: raw original-file function counters only. Build
    # and all live-provider tests must also have succeeded before these exist.
    angular = evidence.load_json(root / 'angular-coverage.json')
    matches = [v for k, v in angular.items() if k == str(Path(next(c['cwd'] for c in manifest['commands']
                if c['name'] == 'angular-test')) / 'src/app/quote-client.ts')]
    require(len(matches) == 1, 'missing or ambiguous consumer coverage')
    counts = matches[0]['f']
    require(counts and set(counts) == set(matches[0]['fnMap']) and
            all(type(n) is int and n >= 0 for n in counts.values()), 'invalid consumer counters')
    frontend = dict(type='ratio', covered=sum(n > 0 for n in counts.values()), total=len(counts))
    llvm = evidence.load_json(root / 'rust-coverage.json')
    rust_path = str(Path(next(c['cwd'] for c in manifest['commands'] if c['name'] == 'rust-coverage')) / 'src/main.rs')
    files = [f for group in llvm['data'] for f in group['files'] if f['filename'] == rust_path]
    require(len(files) == 1, 'missing or ambiguous provider coverage')
    functions = files[0]['summary']['functions']
    require(type(functions['count']) is int and functions['count'] > 0 and
            type(functions['covered']) is int and 0 <= functions['covered'] <= functions['count'],
            'invalid provider counters')
    provider = dict(type='ratio', covered=functions['covered'], total=functions['count'])
    records = [contract, record(root, p, p['subjects'][1], expected, {'coverage.function': provider}, tools),
               record(root, p, p['subjects'][2], expected, {'coverage.function': frontend}, tools)]
    rules = []
    for metric, limit in [('contract.breaking_changes', dict(type='count', value=0)),
                          ('contract.client_drift', dict(type='boolean', value=False)),
                          ('contract.compatible', dict(type='boolean', value=True))]:
        rules.append(dict(id=metric, scope=dict(kind='relationship', relationship='quote-client'),
                          metric=metric, operator='eq', limit=limit, required=True,
                          on_violation='fail', remediation_classes=['repair_contract']))
    for subject in p['subjects'][1:]:
        rules.append(dict(id=subject['component'] + '.local', scope=dict(kind='subject', subject=subject['id']),
                          metric='coverage.function', operator='ge', limit=dict(type='ratio', covered=1, total=2),
                          required=True, on_violation='fail', remediation_classes=['increase_meaningful_coverage']))
    return p, dict(schema='harness-policy/v1', rules=rules), records


def evaluate(root, receipt_sha256, expected):
    p, policy, records = normalize(root, receipt_sha256, expected)
    result = engine.evaluate(policy, records, project=p, expected=expected,
                             source_root=root / 'sources', artifact_root=root)
    return p, policy, records, project_report.report(result, p, policy)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--receipt-sha256', required=True)
    parser.add_argument('--expected', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        _, _, _, report = evaluate(args.native, args.receipt_sha256, evidence.load_json(args.expected))
    except (evidence.MeasurementError, model.ModelError, OSError, ValueError, KeyError, TypeError) as error:
        report = dict(schema='harness-project-report/v1', mode='shadow',
                      aggregate=dict(state='measurement_error'), error=str(error))
    write_json(args.output, report)
    raise SystemExit(0 if report['aggregate']['state'] == 'pass' else 1)
