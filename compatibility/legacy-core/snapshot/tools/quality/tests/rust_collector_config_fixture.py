"""Disposable generic host fixture; this does not certify a delivery combination."""
import base64
import copy
import json
from pathlib import Path
import shlex
import shutil
import time

import build_rust_collector as builder
import rust_collector_project as project
from test_rust_collector_project import binding_for, request_for


def write(path, value):
    path.write_text(json.dumps(value, indent=2))


def prepare(test, binary, output):
    """Compile real owner identities using the released generic configuration API."""
    quality = Path(__file__).resolve().parents[1]
    root = output / 'project'
    config = root / '.harness-gate'
    config.mkdir(parents=True)
    artifacts = root / 'target/evidence'
    artifacts.mkdir(parents=True)
    shutil.copyfile(test.work / 'head/fixture.rs', root / 'fixture.rs')
    binding = binding_for(test.measurement('head'), root, artifacts,
                          getattr(test, 'collector_version', '0.0.0-test'))
    binding['capture']['path'] = str(test.work / 'head')
    source_project = binding['project']
    series = binding['series']
    shutil.copyfile(quality.parent / 'harness-gate/fixtures/preset-compat/rust-api.flow.toml', config / 'flow.toml')
    declared = '''version = 1
[project]
id = "native-test"
name = "rust-api"
[components.rust]
flow_components = ["app"]
source_roots = ["."]
artifact_root = "target/evidence"
[subjects.functions]
component = "rust"
kind = "function"
selection = { kind = "explicit", paths = ["fixture.rs"] }
[collectors.native]
protocol = "harness-collector-request/v1"
request = ".harness-gate/native-request.json"
'''
    for metric in series['metrics']:
        declared += ('[[collectors.native.produces]]\n'
                     'target = { kind = "component", id = "rust" }\n'
                     f'capability = {json.dumps(metric["name"])}\n'
                     f'series = {json.dumps(series["id"])}\n')
    declared += '''[policies]
[profiles.full]
collectors = ["native"]
policies = []
[profiles.hook]
assurance = "partial"
collectors = []
policies = []
[baseline]
required = false
provider = { kind = "none" }
[reporting]
output = "target/quality"
formats = ["human", "json"]
'''
    (config / 'quality.toml').write_text(declared)
    request_path = config / 'native-request.json'
    write(request_path, {})
    state = {
        'schema': 'quality-trusted-state/v1', 'profile': 'full',
        'expected': binding['input']['context'], 'config_files': {},
        'components': {c['id']: c for c in source_project['components']},
        'subject_kinds': {'function': 'function/v1'}, 'relationship_kinds': {},
        'subjects': {'functions': source_project['subjects']}, 'series': {'native': series},
        'artifact_root': 'target/evidence', 'artifacts': {},
        'selection': {'changed_subject': ['functions'], 'critical_subject': []},
        'mappings': None, 'exceptions': [],
    }
    state_path = output / 'state.json'
    pin(root, state, state_path)
    compiled_path = output / 'compiled.json'
    result = test.command('configured-compile', [binary, 'quality', 'compile',
        '--repository-root', str(root), '--state', str(state_path), '--output', str(compiled_path)])
    test.assertEqual(result.returncode, 0, result.stderr)
    compiled = json.loads(compiled_path.read_text())
    # This is request preparation, not a policy implementation. The Core must
    # independently recompute and verify this generic binding before launching.
    payload = {'schema': 'quality-collector-binding/v1',
               'config_files': {p: digest for p, digest in state['config_files'].items()
                                if p != '.harness-gate/native-request.json'},
               'series': state['series'], 'profile': state['profile']}
    payload.update({key: compiled[key] for key in
                    ('project', 'policy', 'expected', 'selection', 'mappings', 'exceptions')})
    binding['config_digest'] = project.fingerprint(payload)
    binding['project'] = compiled['project']
    binding['input'].update(selection=compiled['selection'], context=compiled['expected'])
    binding['input']['bindings'].sort(key=lambda c: (c['subject'], c['capability'], c['series']))
    request, _ = request_for(binding, output / 'binding.json')
    return root, state, state_path, request_path, request


def pin(root, state, state_path):
    state['config_files'] = {'.harness-gate/' + name: builder.sha(root / '.harness-gate' / name)
                             for name in ('flow.toml', 'quality.toml', 'native-request.json')}
    write(state_path, state)


def sign(test, output, request):
    openssl = shutil.which('openssl')
    if not openssl:
        test.skipTest('openssl required for the disposable configured-request signer')
    key = output / 'disposable-test-key.pem'
    public = output / 'disposable-test-key.der'
    for name, args in (
        ('generate', ['genpkey', '-algorithm', 'ED25519', '-out', str(key)]),
        ('public', ['pkey', '-in', str(key), '-pubout', '-outform', 'DER', '-out', str(public)]),
    ):
        result = test.command('configured-key-' + name, [openssl, *args])
        test.assertEqual(result.returncode, 0, result.stderr)
    public_bytes = public.read_bytes()
    test.assertEqual(public_bytes[:12], bytes.fromhex('302a300506032b6570032100'))
    test.assertEqual(len(public_bytes), 44)
    trusted = output / 'trusted-keys.json'
    write(trusted, [{'key_id': 'configured-test',
                    'public_key': base64.b64encode(public_bytes[12:]).decode()}])
    declaration = request['adapter']
    payload = {'domain': 'harness-gate/adapter-request/v2', 'protocol_version': 2,
               'result_schema_version': '1', 'adapter': {key: declaration[key] for key in
               ('name', 'version', 'executable', 'source_digest')}}
    payload['adapter']['signature'] = {'algorithm': 'ed25519', 'key_id': 'configured-test'}
    for name in ('invocation_id', 'step_id', 'timeout_ms', 'config_digest', 'artifact_root',
                 'nonce', 'issued_at_ms', 'expires_at_ms', 'args', 'environment', 'capabilities', 'input'):
        payload[name] = request[name]
    # Match Core's BTreeMap serialization regardless of request insertion order.
    payload['environment'] = dict(sorted(payload['environment'].items()))
    payload['input'] = json.loads(json.dumps(payload['input'], sort_keys=True))
    payload_path = output / 'signed-payload.json'
    payload_path.write_bytes(json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode('utf-8'))
    signature = output / 'signature.bin'
    result = test.command('configured-key-sign', [openssl, 'pkeyutl', '-sign', '-rawin',
        '-inkey', str(key), '-in', str(payload_path), '-out', str(signature)])
    test.assertEqual(result.returncode, 0, result.stderr)
    test.assertEqual(len(signature.read_bytes()), 64)
    declaration['signature']['value'] = base64.b64encode(signature.read_bytes()).decode()
    return trusted


def configured_rejection(test, binary):
    output = test.work / 'configured-core'
    output.mkdir()
    root, state, state_path, request_path, request = prepare(test, binary, output)
    launches = output / 'collector-launches.txt'
    wrapper = output / 'counted-collector.sh'
    # Observe configured collector invocations outside its implementation. This
    # wrapper does not count native descendants or establish clean-host costs.
    wrapper.write_text('#!/bin/sh\n'
        f'printf "collector\\n" >> {shlex.quote(str(launches))}\n'
        f'exec {shlex.quote(str(test.runtime / "bin/harness-gate-rust-collector"))} "$@"\n')
    wrapper.chmod(0o700)
    request['adapter'].update(executable=str(wrapper), source_digest=builder.sha(wrapper),
        signature={'algorithm': 'ed25519', 'key_id': 'configured-test', 'value': ''})
    request.update(nonce='configured-core-test', timeout_ms=30000, issued_at_ms=int(time.time() * 1000))
    request['expires_at_ms'] = request['issued_at_ms'] + 120000
    trusted = sign(test, output, request)
    command = [binary, 'quality', 'collect', '--repository-root', str(root),
               '--state', str(state_path), '--trusted-keys', str(trusted),
               '--output', str(output / 'collection.json')]

    def collect(name, candidate):
        write(request_path, candidate)
        pin(root, state, state_path)
        return test.command('configured-' + name, command)

    stale_config = copy.deepcopy(request)
    stale_config['config_digest'] = '0' * 64
    result = collect('stale-config', stale_config)
    test.assertNotEqual(result.returncode, 0)
    test.assertIn('stale collector config identity', result.stderr)
    test.assertFalse(launches.exists())
    stale = copy.deepcopy(request)
    stale['input']['context']['commit'] = 'f' * 40
    result = collect('stale-context', stale)
    test.assertNotEqual(result.returncode, 0)
    test.assertIn('collector roots/selection/capability request mismatch', result.stderr)
    test.assertFalse(launches.exists())
    tampered = copy.deepcopy(request)
    tampered['nonce'] += '-tampered'
    result = collect('tampered-signature', tampered)
    test.assertNotEqual(result.returncode, 0)
    test.assertIn('adapter signature verification failed', result.stderr)
    test.assertFalse(launches.exists())
    result = collect('unknown-combination', request)
    test.assertNotEqual(result.returncode, 0)
    test.assertIn('adapter exited with', result.stderr)
    test.assertEqual(launches.read_text().splitlines(), ['collector'])
    result = collect('replay', request)
    test.assertNotEqual(result.returncode, 0)
    test.assertIn('nonce has already been used', result.stderr)
    test.assertEqual(launches.read_text().splitlines(), ['collector'])
    test.assertFalse((output / 'collection.json').exists())
    test.assertEqual(list((root / 'target/evidence').iterdir()), [])
    # Preserve the installed entry's exact rejection, since Core rejects a
    # nonzero adapter exit before exposing its response as a collection.
    direct = test.entry('configured-direct-rejection', *request['args'], data=json.dumps(request))
    test.assertEqual(direct.returncode, 1, direct.stderr)
    response = json.loads(direct.stdout)
    test.assertIn('unknown tested Core/protocol/ABI', response['collection']['error'])
    test.assertEqual(response['collection']['evidence'], [])
    test.assertEqual(response['artifacts'], [])


def configured_malformed_rejection(test, binary):
    """A synthetic zero-exit producer cannot turn malformed stdout into evidence."""
    output = test.work / 'configured-malformed-core'
    output.mkdir()
    root, state, state_path, request_path, request = prepare(test, binary, output)
    launches = output / 'collector-launches.txt'
    wrapper = output / 'malformed-collector.sh'
    wrapper.write_text('#!/bin/sh\n'
        # Drain only the synthetic malformed producer's request before exiting.
        # The real collector wrapper above must preserve stdin for the collector.
        'while IFS= read -r line; do :; done\n'
        f'printf "collector\\n" >> {shlex.quote(str(launches))}\n'
        'printf "{\\n"\n'
        'exit 0\n')
    wrapper.chmod(0o700)
    request['adapter'].update(executable=str(wrapper), source_digest=builder.sha(wrapper),
        signature={'algorithm': 'ed25519', 'key_id': 'configured-test', 'value': ''})
    request.update(nonce='configured-malformed-test', timeout_ms=30000,
                   issued_at_ms=int(time.time() * 1000))
    request['expires_at_ms'] = request['issued_at_ms'] + 120000
    trusted = sign(test, output, request)
    write(request_path, request)
    pin(root, state, state_path)
    command = [binary, 'quality', 'collect', '--repository-root', str(root),
               '--state', str(state_path), '--trusted-keys', str(trusted),
               '--output', str(output / 'collection.json')]
    result = test.command('configured-malformed-response', command)
    test.assertNotEqual(result.returncode, 0)
    test.assertIn('malformed adapter response:', result.stderr)
    test.assertEqual(launches.read_text().splitlines(), ['collector'])
    test.assertFalse((output / 'collection.json').exists())
    test.assertEqual(list((root / 'target/evidence').iterdir()), [])
    result = test.command('configured-malformed-replay', command)
    test.assertNotEqual(result.returncode, 0)
    test.assertIn('nonce has already been used', result.stderr)
    test.assertEqual(launches.read_text().splitlines(), ['collector'])
    test.assertFalse((output / 'collection.json').exists())
    test.assertEqual(list((root / 'target/evidence').iterdir()), [])
