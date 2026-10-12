#!/usr/bin/env python3
"""Local, backend-only signed Core rehearsal. Not a production trust provisioner.

Consumes a fresh probe snapshot, pins its complete configuration, and keeps the
ephemeral signing key outside the measured workspace and collector environment.
Core owns signature verification, capability validation and quality decisions.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import tempfile
import sys
import tomllib


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--plugin', type=Path, required=True)
    args = parser.parse_args()
    bundle = json.loads(args.bundle.read_text())
    measurement, series = bundle['request'], bundle['series']
    root = Path(measurement['workspace_root']).resolve(strict=True)
    assert (root / '.local-capture-snapshot').read_text() == 'backend-source-only rehearsal\n'
    assert root.parent == args.bundle.resolve().parent and not (root / '.git').exists()
    host = Path(tempfile.mkdtemp(prefix='host-', dir=root.parent))
    core = Path(shutil.which('harness-gate')).resolve()
    plugin = args.plugin.resolve(strict=True)
    python = Path(sys.executable).resolve()

    def run(label, command, **kwargs):
        result = subprocess.run([str(p) for p in command], capture_output=True, text=True, **kwargs)
        (host / (label + '.stdout')).write_text(result.stdout)
        (host / (label + '.stderr')).write_text(result.stderr)
        return result

    if not (root / '.harness-gate/flow.toml').exists():
        assert run('init', [core, '--project-root', root, 'init', '--preset', 'rust-api']).returncode == 0
    config = root / '.harness-gate'
    flow_name = tomllib.loads((config / 'flow.toml').read_text())['project']['name']
    request_path = config / 'backend-request.json'
    write(request_path, {})
    groups = {'functions': measurement['parameters']['subjects']}
    metric_groups = [('functions', 'coverage.line'), ('functions', 'coverage.region'), ('functions', 'risk.crap')]
    declared = f'''version = 1
[project]
id = "codexsymphony"
name = {json.dumps(flow_name)}
[components.backend]
flow_components = ["app"]
source_roots = ["apps/server/src"]
artifact_root = "evidence"
'''
    for group in groups:
        declared += f'''[subjects.{group}]
component = "backend"
kind = "{group}"
selection = {{kind = "explicit", paths = {json.dumps(sorted({s['path'] for s in groups[group]}))}}}
'''
    declared += '''[collectors.backend]
protocol = "harness-collector-request/v1"
request = ".harness-gate/backend-request.json"
'''
    rules = []
    for group, metric in [(g, m) for g in groups for m in measurement['requested_capabilities']]:
        declared += f'''[[collectors.backend.produces]]
target = {{kind = "subject", id = "{group}"}}
capability = "{metric}"
series = "{series['id']}"
'''
    for group, metric in metric_groups:
        name = group + '.' + metric
        rules.append({'id': name, 'scope': {'kind': 'subject', 'subject': group},
                      'metric': metric, 'operator': 'le' if metric == 'risk.crap' else 'ge',
                      'limit': {'type': 'rational', 'numerator': 10, 'denominator': 1} if metric == 'risk.crap' else {'type': 'ratio', 'covered': 80, 'total': 100},
                      'required': True, 'on_violation': 'fail', 'remediation_classes': ['improve_tests']})
        declared += f'''[policies."{name}"]
policy_file = ".harness-gate/backend-policy.json"
rule = "{name}"
expectation = {{target = {{kind = "subject", id = "{group}"}}, capability = "{metric}", series = "{series['id']}"}}
'''
    declared += f'''[profiles.full]
assurance = "complete"
collectors = ["backend"]
policies = {json.dumps([r['id'] for r in rules])}
[profiles.hook]
assurance = "partial"
collectors = []
policies = []
[baseline]
required = false
provider = {{kind = "none"}}
[reporting]
output = "target/quality"
formats = ["human", "json"]
'''
    (config / 'quality.toml').write_text(declared)
    write(config / 'backend-policy.json', {'schema': 'harness-policy/v1', 'rules': rules})
    component = {'id': 'backend', 'path': 'apps/server/src', 'metadata': {},
                 'targets': [{'id': measurement['context']['target'], 'boundaries': ['production'], 'metadata': {}}],
                 'source_boundaries': [{'id': 'production', 'path': 'apps/server/src', 'role': 'production', 'metadata': {}}]}
    state = {'schema': 'quality-trusted-state/v1', 'profile': 'full', 'expected': measurement['context'],
             'components': {'backend': component}, 'subjects': groups,
             'subject_kinds': {name: 'function/v1' if name == 'functions' else 'file/v1' for name in groups}, 'relationship_kinds': {},
             'series': {'backend': series}, 'artifact_root': 'evidence', 'artifacts': {},
             'selection': {'changed_subject': sorted(groups), 'critical_subject': []}, 'mappings': None, 'exceptions': []}
    state_path = host / 'state.json'

    def pin():
        state['config_files'] = {'.harness-gate/' + name: digest((config / name).read_bytes())
                                 for name in ('flow.toml', 'quality.toml', 'backend-policy.json', 'backend-request.json')}
        write(state_path, state)

    pin()
    compiled_path = host / 'compiled.json'
    compiled_run = run('compile', [core, 'quality', 'compile', '--repository-root', root, '--state', state_path, '--output', compiled_path])
    assert compiled_run.returncode == 0, compiled_run.stderr
    compiled = json.loads(compiled_path.read_text())
    payload = {'schema': 'quality-collector-binding/v1', 'config_files': {p: d for p, d in state['config_files'].items() if p != '.harness-gate/backend-request.json'}, 'series': state['series'], 'profile': 'full'}
    payload.update({key: compiled[key] for key in ('project', 'policy', 'expected', 'selection', 'mappings', 'exceptions')})
    config_digest = digest(canonical(payload).encode())
    claims = sorted([{'subject': s['id'], 'capability': m, 'series': series['id']}
                     for g in groups for m in measurement['requested_capabilities'] for s in groups[g]], key=lambda v: (v['subject'], v['capability'], v['series']))
    inner = {'schema': 'harness-project-collector-request/v1', 'project': measurement['project'], 'collector': measurement['collector'],
             'context': measurement['context'], 'workspace_root': str(root), 'output_root': measurement['output_root'],
             'selection': compiled['selection'], 'bindings': claims}
    binding_path = host / 'binding.json'
    write(binding_path, {'schema': 'rust-source-project-binding/v1', 'input': inner, 'config_digest': config_digest, 'request': measurement})
    runtime = {str(plugin / name): digest((plugin / name).read_bytes())
               for name in ('plugin.py', 'measure.py', 'inventory', 'ast/Cargo.lock', 'capture.py')}
    runtime[str(python)] = digest(python.read_bytes())
    launcher = host / 'collector'
    launcher.write_text('#!/usr/bin/python3\nimport os, sys, hashlib\nfrom pathlib import Path\n'
                        + 'pins = ' + repr(runtime) + '\n'
                        + 'for name, expected in pins.items():\n    assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == expected, "runtime changed"\n'
                        + f'os.execv({str(python)!r}, [{str(python)!r}, {str(plugin / "plugin.py")!r}, *sys.argv[1:]])\n')
    launcher.chmod(0o700)
    key = host / 'private.pem'
    prior = os.umask(0o077)
    try:
        assert run('keygen', ['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', key]).returncode == 0
    finally:
        os.umask(prior)
    public = host / 'public.der'
    assert run('public', ['openssl', 'pkey', '-in', key, '-pubout', '-outform', 'DER', '-out', public]).returncode == 0
    keys = host / 'trusted-keys.json'
    write(keys, [{'key_id': 'local-backend-only', 'public_key': base64.b64encode(public.read_bytes()[12:]).decode()}])
    now = int(time.time() * 1000)
    request = {'protocol_version': 2, 'result_schema_version': '1', 'adapter': measurement['collector'] | {'executable': str(launcher), 'source_digest': digest(launcher.read_bytes()), 'signature': {'algorithm': 'ed25519', 'key_id': 'local-backend-only', 'value': ''}},
               'invocation_id': measurement['context']['run'], 'step_id': 'backend', 'timeout_ms': 120000,
               'config_digest': config_digest, 'artifact_root': inner['output_root'], 'nonce': os.urandom(16).hex(),
               'issued_at_ms': now, 'expires_at_ms': now + 300000,
               'args': ['project', '--binding', str(binding_path), '--binding-sha256', digest(binding_path.read_bytes())],
               'environment': {}, 'capabilities': {'network': [], 'resources': [], 'environment': []}, 'input': inner}
    def sign(value, label):
        signed = {'domain': 'harness-gate/adapter-request/v2', 'protocol_version': 2, 'result_schema_version': '1',
                  'adapter': {k: value['adapter'][k] for k in ('name', 'version', 'executable', 'source_digest')}}
        signed['adapter']['signature'] = {'algorithm': 'ed25519', 'key_id': 'local-backend-only'}
        for name in ('invocation_id', 'step_id', 'timeout_ms', 'config_digest', 'artifact_root', 'nonce', 'issued_at_ms', 'expires_at_ms', 'args', 'environment', 'capabilities', 'input'):
            signed[name] = json.loads(canonical(value[name])) if name in ('environment', 'input') else value[name]
        sign_input = host / (label + '-sign-input.json')
        sign_input.write_text(json.dumps(signed, separators=(',', ':'), ensure_ascii=False))
        signature = host / (label + '-signature.bin')
        assert run(label + '-sign', ['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', key, '-in', sign_input, '-out', signature]).returncode == 0
        value['adapter']['signature']['value'] = base64.b64encode(signature.read_bytes()).decode()

    expired = copy.deepcopy(request)
    expired.update(nonce=os.urandom(16).hex(), issued_at_ms=now - 120000, expires_at_ms=now - 60000)
    sign(expired, 'expired')
    sign(request, 'valid')
    # No subsequent test/collector operation needs the ephemeral private key.
    key.unlink()
    command = [core, 'quality', 'collect', '--repository-root', root, '--state', state_path, '--trusted-keys', keys, '--output', host / 'collection.json']

    def collect(label, value):
        write(request_path, value)
        pin()
        return run(label, command)

    stale = copy.deepcopy(request)
    stale['input']['context']['commit'] = 'f' * 40
    stale_result = collect('stale-context', stale)
    assert stale_result.returncode != 0 and 'mismatch' in stale_result.stderr, stale_result.stderr
    expired_result = collect('expired', expired)
    assert expired_result.returncode != 0 and 'expired' in expired_result.stderr, expired_result.stderr
    broken = copy.deepcopy(request)
    broken['nonce'] += '-tampered'
    rejected = collect('tampered-signature', broken)
    assert rejected.returncode != 0 and 'signature' in rejected.stderr, rejected.stderr
    collected = collect('collect', request)
    assert collected.returncode == 0, collected.stderr
    collection = json.loads((host / 'collection.json').read_text())
    write(host / 'accepted-collection.json', collection)
    write(host / 'evidence.json', collection['evidence'])
    for name in ('project', 'policy', 'expected'):
        write(host / (name + '.json'), compiled[name])
    evaluation = [core, 'quality', 'evaluate', '--source-root', root, '--artifact-root', inner['output_root'], '--output', host / 'report.json']
    for name in ('project', 'policy', 'expected', 'evidence'):
        evaluation += ['--' + name, host / (name + '.json')]
    assessed = run('evaluate', evaluation)
    assert assessed.returncode in (0, 1), assessed.stderr
    report = json.loads((host / 'report.json').read_text())
    # Synthetic values exercise Core's exact rational policy comparison only;
    # the independent native fixture tests certify source CC=10/11 measurement.
    threshold_cases = []
    for label, numerator, denominator, expected_exit in [('crap-10', 10, 1, 0), ('crap-11', 11, 1, 1), ('crap-10-plus-fraction', 100001, 10000, 1)]:
        boundary = copy.deepcopy(collection['evidence'])
        for record in boundary:
            for metric in record['metrics']:
                if metric['name'] == 'risk.crap':
                    metric['value'] = {'type': 'rational', 'numerator': numerator, 'denominator': denominator}
        evidence_path = host / (label + '-synthetic-evidence.json')
        write(evidence_path, boundary)
        checked = list(evaluation)
        checked[checked.index('--evidence') + 1] = evidence_path
        checked[checked.index('--output') + 1] = host / (label + '-report.json')
        result = run(label, checked)
        assert result.returncode == expected_exit, result.stderr
        threshold_cases.append({'name': label, 'exit': result.returncode, 'scope': 'synthetic-policy-comparison'})
    # A replay is checked against a fresh empty output directory; artifacts from
    # the accepted run are retained separately, not deleted or trusted as cache.
    evidence_root = Path(inner['output_root'])
    retained = evidence_root.with_name('accepted-evidence')
    evidence_root.rename(retained)
    evidence_root.mkdir()
    replay = collect('replay', request)
    assert replay.returncode != 0 and 'nonce has already been used' in replay.stderr, replay.stderr
    evidence_root.rmdir()
    retained.rename(evidence_root)
    artifact = evidence_root / collection['evidence'][0]['artifacts'][0]['path']
    original = artifact.read_bytes()
    try:
        artifact.write_bytes(original + b' ')
        tamper_command = list(evaluation)
        tamper_command[tamper_command.index('--output') + 1] = host / 'tampered-report.json'
        tampered = run('tampered-artifact', tamper_command)
        assert tampered.returncode != 0, 'Core accepted modified retained evidence'
    finally:
        artifact.write_bytes(original)
    result = {'scope': 'local-backend-only', 'host': str(host), 'collection': 'pass',
              'evaluation_exit': assessed.returncode, 'report': report['aggregate'],
              'negative_cases': ['stale-context', 'expired', 'tampered-signature', 'replay', 'tampered-artifact'],
              'source_functions': len(groups['functions']), 'threshold_cases': threshold_cases}
    write(host / 'acceptance.json', result)
    print(json.dumps(result))
    if assessed.returncode:
        raise SystemExit(assessed.returncode)


if __name__ == '__main__':
    main()
