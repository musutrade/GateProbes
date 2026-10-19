"""Real Core fixtures for the independent result consumer tests.

The consumer must map an already-provisioned Check from an operator-pinned
exact result. These helpers build real saved Core reports through the shipped
CLI: a complete passing quality workflow and a failing quality workflow, both
produced by the same signed collector fixture the Rust tests use. The signing
key is the fixture key (seed 0x07) and only the adapter fixture is rebuilt;
Core sources are not modified.
"""
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent / 'fixtures'
CONSUMER = Path(os.environ.get('GATEPROBES_CONSUMER', Path(__file__).resolve().parents[1] / 'github_check.py'))
CORE = Path(os.environ.get('GATEHOUSE_CORE', REPO / 'tools/harness-gate/target/debug/harness-gate'))
WORKFLOW = REPO / 'tools/harness-gate/fixtures/workflow'
COLLECTOR = WORKFLOW / 'collectors/collector.py'
PRESET = REPO / 'tools/harness-gate/fixtures/preset-compat/rust-api.flow.toml'
SIGNING_DOMAIN = 'harness-gate/adapter-request/v2'
FIXTURE_SEED = bytes([7]) * 32
_KEY = {}

FLOW = """version = 2

[project]
name = "rust-api"
default_profile = "full"
hook_profile = "hook"

[paths]
reports = ".harness-gate/reports"
audit_config = ".harness-gate/audit.toml"
secrets_config = ".harness-gate/secrets.toml"

[paths.aliases.app]
path = "."

[policy]
required_steps = ["configured-check"]

[[steps]]
id = "configured-check"
label = "Configured execution check"
component = "app"
profiles = ["full", "ci", "hook"]
program = "python3"
args = ["{root}/execution.py"]
cwd = "{root}"
log = "execution.log"
timeout_secs = 30

[scope]
unmatched = "all"

[[scope.rules]]
patterns = ["src/**", ".harness-gate/**", "execution.py"]
components = ["app"]
"""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def _field(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False)


def _value(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def consumer():
    spec = importlib.util.spec_from_file_location('github_check', CONSUMER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(core, root, args, expect_failure=False):
    output = subprocess.run([str(core), *map(str, args)], cwd=root, capture_output=True)
    if (output.returncode != 0) is not expect_failure:
        raise AssertionError(
            f'Core {" ".join(map(str, args))} failed: {output.stderr.decode(errors="replace")}')
    return output


def _record(mode):
    direct = json.loads((WORKFLOW / 'compiler/direct.json').read_text())
    record = direct['records'][0]
    if mode == 'unsupported':
        record['capabilities'][0]['state'] = 'unsupported'
        record['metrics'] = []
        record['status'] = 'unavailable'
    return direct, record


def _signed_request(core, root, state, compiled, executable, nonce='fixture-nonce'):
    produces = []
    config_files = {path: digest((root / path).read_bytes()) for path in state['config_files']}
    requests = {'.harness-gate/coverage-request.json'}
    bound = {path: value for path, value in config_files.items() if path not in requests}
    quality = _toml_value(root / '.harness-gate/quality.toml', 'collectors', 'coverage', 'produces')
    for entry in quality:
        target = entry['target']
        subjects = sorted(subject['id'] for values in state['subjects'].values()
                          for subject in values if subject['component'] == target['id'])
        for subject in subjects:
            produces.append((subject, entry['capability'], entry['series']))
    request = {
        'protocol_version': 2,
        'result_schema_version': '1',
        'adapter': {
            'name': state['series']['coverage']['collector']['name'],
            'version': '1',
            'executable': str(executable),
            'source_digest': digest(executable.read_bytes()),
            'signature': {'algorithm': 'ed25519', 'key_id': 'fixture', 'value': ''},
        },
        'invocation_id': state['expected']['run'],
        'step_id': 'coverage',
        'timeout_ms': 30000,
        'config_digest': digest(canonical({
            'schema': 'quality-collector-binding/v1', 'config_files': bound,
            'project': compiled['project'], 'policy': compiled['policy'],
            'expected': compiled['expected'], 'selection': compiled['selection'],
            'series': state['series'], 'profile': state['profile'],
            'mappings': compiled['mappings'], 'exceptions': compiled['exceptions']})),
        'artifact_root': compiled['artifact_root'],
        'nonce': nonce,
        'issued_at_ms': int(time.time() * 1000),
        'expires_at_ms': int(time.time() * 1000) + 60000,
        'args': [],
        'environment': {},
        'capabilities': {'network': [], 'resources': [], 'environment': []},
        'input': {
            'schema': 'harness-project-collector-request/v1',
            'project': compiled['project']['id'],
            'collector': state['series']['coverage']['collector'],
            'context': compiled['expected'],
            'workspace_root': compiled['source_root'],
            'output_root': compiled['artifact_root'],
            'selection': compiled['selection'],
            'bindings': [{'subject': subject, 'capability': capability, 'series': series}
                         for subject, capability, series in sorted(set(produces))],
        },
    }
    signature = _signing_payload(request)
    _, public_key = _fixture_key()
    request['adapter']['signature']['value'] = base64.b64encode(_sign(signature)).decode()
    return request, public_key


def _toml_value(path, *tables):
    import tomllib
    value = tomllib.loads(path.read_text())
    for table in tables:
        value = value[table]
    return value


def _fixture_key():
    """Ed25519 fixture key via openssl: PEM bytes plus base64 raw public key.

    Uses only the openssl binary so the suite has no Python crypto dependency.
    """
    if 'pem' not in _KEY:
        with tempfile.TemporaryDirectory(prefix='gatehouse-fixture-key-') as work:
            work = Path(work)
            der, pem, spki = work / 'key.der', work / 'key.pem', work / 'public.der'
            der.write_bytes(bytes.fromhex('302e020100300506032b657004220420') + FIXTURE_SEED)
            subprocess.run(['openssl', 'pkey', '-inform', 'DER', '-in', der, '-out', pem],
                           check=True, capture_output=True)
            subprocess.run(['openssl', 'pkey', '-in', pem, '-pubout', '-outform', 'DER',
                            '-out', spki], check=True, capture_output=True)
            _KEY['pem'] = pem.read_bytes()
            _KEY['public'] = base64.b64encode(spki.read_bytes()[-32:]).decode()
    return _KEY['pem'], _KEY['public']


def _sign(payload):
    pem, _ = _fixture_key()
    with tempfile.TemporaryDirectory(prefix='gatehouse-fixture-sign-') as work:
        work = Path(work)
        key, data, out = work / 'key.pem', work / 'payload', work / 'signature'
        key.write_bytes(pem)
        data.write_bytes(payload)
        subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', key,
                        '-in', data, '-out', out], check=True, capture_output=True)
        return out.read_bytes()


def _signing_payload(request):
    adapter = request['adapter']
    text = ('{"domain":"%s","protocol_version":2,"result_schema_version":%s,"adapter":'
            '{"name":%s,"version":%s,"executable":%s,"source_digest":%s,"signature":'
            '{"algorithm":%s,"key_id":%s}},"invocation_id":%s,"step_id":%s,"timeout_ms":%d,'
            '"config_digest":%s,"artifact_root":%s,"nonce":%s,"issued_at_ms":%d,"expires_at_ms":%d,'
            '"args":[],"environment":%s,"capabilities":%s,"input":%s}') % (
        SIGNING_DOMAIN, _field(request['result_schema_version']), _field(adapter['name']),
        _field(adapter['version']), _field(adapter['executable']), _field(adapter['source_digest']),
        _field(adapter['signature']['algorithm']), _field(adapter['signature']['key_id']),
        _field(request['invocation_id']), _field(request['step_id']), request['timeout_ms'],
        _field(request['config_digest']), _field(request['artifact_root']), _field(request['nonce']),
        request['issued_at_ms'], request['expires_at_ms'], _value(request['environment']),
        '{"network":%s,"resources":%s,"environment":%s}' % (
            _field(request['capabilities']['network']), _field(request['capabilities']['resources']),
            _field(request['capabilities']['environment'])),
        _value(request['input']))
    return text.encode()


def build(root, mode='pass', execution_passes=True):
    """Build one real project and return the verified report-verify output."""
    core = CORE
    root = Path(root).resolve()
    fixtures = WORKFLOW
    (root / '.harness-gate').mkdir(parents=True)
    (root / '.harness-gate').chmod(0o700)
    (root / 'src').mkdir()
    (root / 'target/evidence').mkdir(parents=True)
    shutil.copyfile(fixtures / 'compiler/source.txt', root / 'src/lib.rs')
    (root / '.harness-gate/flow.toml').write_text(FLOW)
    (root / 'execution.py').write_text('raise SystemExit(0)\n' if execution_passes else 'raise SystemExit(7)\n')
    for name, dest in (('empty.audit.toml', 'audit.toml'), ('default.secrets.toml', 'secrets.toml')):
        shutil.copyfile(REPO / 'tools/harness-gate/presets' / name, root / '.harness-gate' / dest)
    state = json.loads((fixtures / 'compiler/state.json').read_text())
    state['artifacts'] = {}
    direct, record = _record(mode)
    quality = (fixtures / 'compiler/quality.toml').read_text()
    quality += ('\n[profiles.full.workflow]\nstate = ".harness-gate/workflow-state.json"\n'
                'trusted_keys = ".harness-gate/workflow-keys.json"\n')
    (root / '.harness-gate/quality.toml').write_text(quality)
    (root / '.harness-gate/policy.json').write_text(json.dumps(direct['policy'], indent=2))
    record['series'] = state['series']['coverage']
    record['collector'] = record['series']['collector']
    response = {'schema_version': '1', 'status': 'PASS', 'invocation_id': state['expected']['run'],
                'artifacts': record['artifacts'],
                'collection': {'schema': 'harness-project-collector-response/v1',
                               'evidence': [record], 'error': None}}
    payload = {'mode': mode, 'response': response,
               'raw': (fixtures / 'compiler/artifact.txt').read_text()}
    script = (COLLECTOR.read_text()
              .replace("'PAYLOAD_PLACEHOLDER'", json.dumps(json.dumps(payload, separators=(',', ':')))))
    executable = root / 'collector.py'
    executable.write_text(script)
    executable.chmod(0o700)
    (root / '.harness-gate/coverage-request.json').write_text('{}')
    state['config_files'] = {path: digest((root / path).read_bytes()) for path in (
        '.harness-gate/flow.toml', '.harness-gate/quality.toml',
        '.harness-gate/coverage-request.json', '.harness-gate/policy.json')}
    _write_state(root, state)
    _run(core, root, ['quality', 'compile', '--repository-root', root,
                      '--state', root / '.harness-gate/workflow-state.json',
                      '--output', root / 'compiled.json'])
    compiled = json.loads((root / 'compiled.json').read_text())
    request, public_key = _signed_request(core, root, state, compiled, executable)
    (root / '.harness-gate/coverage-request.json').write_text(json.dumps(request, indent=2) + '\n')
    state['config_files'] = {path: digest((root / path).read_bytes()) for path in state['config_files']}
    _write_state(root, state)
    (root / '.harness-gate/workflow-keys.json').write_text(
        json.dumps([{'key_id': 'fixture', 'public_key': public_key}]))
    for args in (['init', '-q'],
                 ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                  'commit', '--allow-empty', '-qm', 'fixture']):
        subprocess.run(['git', *args], cwd=root, check=True, capture_output=True)
    _run(core, root, ['--project-root', root, 'verify', '--all'], expect_failure=not execution_passes or mode != 'pass')
    machine_path = root / '.harness-gate/reports/test_result.json'
    machine_bytes = machine_path.read_bytes()
    machine = json.loads(machine_bytes)
    directory = Path(machine['report_directory']).resolve()
    index = root / 'history.json'
    index.write_text(json.dumps({
        'schema': 'harness-report-history/v1',
        'samples': [{
            'directory': directory.relative_to(root).as_posix(),
            'machine_sha256': digest(machine_bytes),
            'manifest_sha256': digest((directory / 'manifest.json').read_bytes()),
        }]}))
    output = _run(core, root, ['report-verify', '--input', index])
    verified = json.loads(output.stdout)
    if verified['historical_integrity'] != 'verified':
        raise AssertionError(verified)
    return root, verified


def variant(root, run_id, mutate=None, expect_failure=False):
    """Rebuild one paired variant in the same fixture root.

    Reuses the collector executable bytes of the original root so the
    collector-runtime settings binding stays comparable; re-pins trusted config
    bytes and re-signs the request with a fresh nonce after the mutation.
    """
    core = CORE
    root = Path(root).resolve()
    state_path = root / '.harness-gate/workflow-state.json'
    state = json.loads(state_path.read_text())
    if mutate:
        mutate(root)
    # Fresh artifact storage per the collector contract: stale evidence files
    # fail the freshness/pinned-retained check on the next collection.
    artifacts = root / state.get('artifact_root', 'target/evidence')
    for entry in sorted(artifacts.iterdir()):
        shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
    state['config_files'] = {path: digest((root / path).read_bytes())
                             for path in state['config_files']}
    _write_state(root, state)
    _run(core, root, ['quality', 'compile', '--repository-root', root,
                      '--state', state_path, '--output', root / 'compiled.json'])
    compiled = json.loads((root / 'compiled.json').read_text())
    request, public_key = _signed_request(core, root, state, compiled,
                                          root / 'collector.py', nonce=run_id)
    (root / '.harness-gate/coverage-request.json').write_text(
        json.dumps(request, indent=2) + '\n')
    state['config_files'] = {path: digest((root / path).read_bytes())
                             for path in state['config_files']}
    _write_state(root, state)
    (root / '.harness-gate/workflow-keys.json').write_text(
        json.dumps([{'key_id': 'fixture', 'public_key': public_key}]))
    for args in (['add', '-A'],
                 ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                  'commit', '--allow-empty', '-qm', 'variant ' + run_id]):
        subprocess.run(['git', *args], cwd=root, check=True, capture_output=True)
    _run(core, root, ['--project-root', root, 'verify', '--all'],
         expect_failure=expect_failure)
    machine_path = root / '.harness-gate/reports/test_result.json'
    machine_bytes = machine_path.read_bytes()
    machine = json.loads(machine_bytes)
    directory = Path(machine['report_directory']).resolve()
    index = root / ('history-' + run_id + '.json')
    index.write_text(json.dumps({
        'schema': 'harness-report-history/v1',
        'samples': [{
            'directory': directory.relative_to(root).as_posix(),
            'machine_sha256': digest(machine_bytes),
            'manifest_sha256': digest((directory / 'manifest.json').read_bytes()),
        }]}))
    output = _run(core, root, ['report-verify', '--input', index])
    verified = json.loads(output.stdout)
    if verified['historical_integrity'] != 'verified':
        raise AssertionError(verified)
    return verified, compiled


def _write_state(root, state):
    (root / '.harness-gate/workflow-state.json').write_text(json.dumps(state, indent=2) + '\n')


SHARED = {}


def shared(mode='pass'):
    """Build once per test process; returns (root, verified, config)."""
    if mode not in SHARED:
        directory = Path(tempfile.mkdtemp(prefix='gatehouse-consumer-'))
        SHARED[mode] = build(directory, mode)
    return SHARED[mode]


def config_for(verified, **overrides):
    result = verified['result']
    config = {
        'repository': 'musutrade/GateHouse',
        'target_sha': '0123456789abcdef0123456789abcdef01234567',
        'check_id': 501,
        'app_id': 502,
        'check_name': 'gatehouse/exact-result',
        'generation': 1,
        'expires_at': time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time() + 86400)),
        'machine_sha256': verified['machine_sha256'],
        'manifest_sha256': verified['manifest_sha256'],
        'invocation_id': verified['invocation_id'],
        'source_identity': result['source_identity'],
        'configuration_digest': result['configuration_digest'],
        'profile': result['profile'],
        'verification_policy_identity': result['identities']['verification_policy_identity'],
        'quality_policy_identity': result['identities']['quality_policy_identity'],
        'runtime_bundle_digest': result['identities']['runtime_bundle_digest'],
        'current_use_review': 'approved-exact-result',
        'verifier_sha256': digest(CORE.read_bytes()),
    }
    config.update(overrides)
    return config


def remote_for(config):
    return {'id': config['check_id'], 'head_sha': config['target_sha'],
            'name': config['check_name'], 'app': {'id': config['app_id']},
            'status': 'in_progress', 'conclusion': None, 'external_id': None}


class FakeAPI:
    """Fake GitHub Check transport; never performs a network write."""

    def __init__(self, remote):
        self.remote = dict(remote)
        self.calls = []
        self.get_error = None
        self.patch_error = None

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if method == 'GET':
            if self.get_error:
                raise self.get_error
            return dict(self.remote)
        if self.patch_error:
            raise self.patch_error
        confirmed = {'id': self.remote['id'], 'head_sha': self.remote['head_sha'],
                     'name': self.remote['name'], 'app': dict(self.remote['app']),
                     'status': 'completed', 'conclusion': payload['conclusion'],
                     'external_id': payload['external_id']}
        self.remote.update(confirmed)
        return confirmed
