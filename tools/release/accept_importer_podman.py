#!/usr/bin/env python3
"""Extract the externally verified importer; Core consumes its installed descriptor."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from verify_importer_archive import extract, LIMIT
from importer_core_podman import EXPECTED, runtime_contract
from verify_podman_acceptance import PARSE_ERRORS

ROOT = Path(__file__).resolve().parents[2]
IMPORTER_VERSION = '0.5.0'
MANIFEST = json.loads((ROOT / 'plugins/runtime-importer/plugin.json').read_text())
if MANIFEST.get('version') != IMPORTER_VERSION:
    raise ValueError('unexpected importer distribution version')
FIXTURES = {
    '0.1.0': {
        'path': ROOT / 'plugins/podman-lifecycle/tests_historical/accept_0_1.py',
        'sha256': '902b64dba081bf85032a7d58d947cffe06f0444c6107c20e1a4a1584d6dff981',
        'prefix': 'gateprobes-podman-lifecycle-0.1.0-linux-amd64',
        'core_version': '0.11.0',
        'core_sha256': '912a65b17353226becf955de8e74a9c4b7389bf5b273c9a935c6fd68797b18f2',
    },
    '0.2.0': {
        'path': ROOT / 'plugins/podman-lifecycle/tests_historical/accept_0_2.py',
        'sha256': '49c1cb00d94dadff9f4846aa6eea4ee872a9ee5ac4579b91eb41b9b376e28630',
        'prefix': 'gateprobes-podman-lifecycle-0.2.0-linux-amd64',
        'core_version': '0.12.0',
        'core_sha256': '6890e4465c9d86f53cffe8c58103a650babd03db895e27ae99928659c4f1d1d6',
    },
}


def load_fixture(version):
    record = FIXTURES.get(version)
    if record is None:
        raise ValueError('unsupported Podman importer fixture version')
    data = record['path'].read_bytes()
    if hashlib.sha256(data).hexdigest() != record['sha256']:
        raise ValueError('historical Podman acceptance fixture digest mismatch')
    spec = importlib.util.spec_from_file_location('podman_fixture_' + version.replace('.', '_'), record['path'])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if module.PREFIX != record['prefix'] or module.CORE_SHA != record['core_sha256']:
        raise ValueError('historical Podman acceptance fixture identity mismatch')
    return record, module


FIXTURE_VERSION = '0.2.0'
FIXTURE_RECORD, fixture = load_fixture(FIXTURE_VERSION)
FIXTURE_PATH = FIXTURE_RECORD['path']
FIXTURE_SHA256 = FIXTURE_RECORD['sha256']
CORE_VERSION = FIXTURE_RECORD['core_version']
CASES = fixture.CASES
digest, canonical = fixture.digest, fixture.canonical


def install(root, bundle, assets, runtime, fixture_module):
    reviewed = bundle / 'tools/runtime_import/release-pin-podman.json'
    if json.loads(reviewed.read_bytes()) != runtime:
        raise ValueError('extracted importer runtime pin differs')
    pin = root / 'pin.json'
    pin.write_bytes(reviewed.read_bytes())
    pin.chmod(0o400)
    destination = root / 'installed'
    result = subprocess.run(['python3', '-I', '-B', str(bundle / 'tools/runtime_import/install.py'),
                             '--pin', str(pin), '--assets', str(assets), '--destination', str(destination)],
                            env={'PATH': os.environ['PATH'], 'HOME': str(root)}, cwd=root,
                            capture_output=True, text=True, timeout=30)
    if result.returncode != 0 or result.stderr:
        raise ValueError('extracted importer installation failed: ' + result.stderr)
    executable = destination / fixture_module.BINARY
    path = destination / 'installation.json'
    value = {'schema': 'gate-runtime/podman-installation-v1', 'product': 'podman-lifecycle',
             'version': runtime['version'], 'protocol': 'gate-runtime/lifecycle-v2',
             'executable_path': str(executable),
             'executable_sha256': runtime['executable_sha256'],
             'config_schema': 'gate-runtime/podman-context-v1'}
    if path.read_bytes() != fixture_module.canonical(value):
        raise ValueError('installed descriptor differs from importer output')
    if digest(executable.read_bytes()) != runtime['executable_sha256']:
        raise ValueError('installed executable digest mismatch')
    if len(list(destination.iterdir())) != 13:
        raise ValueError('installed importer member count mismatch')
    if not (destination / 'installation.json').exists() or (destination / 'context.json').exists() or (destination / 'host.json').exists():
        raise ValueError('importer created unexpected host/config state')
    for member in destination.iterdir():
        expected_mode = 0o500 if member == executable else 0o400
        if stat.S_IMODE(member.stat().st_mode) != expected_mode:
            raise ValueError('importer output mode mismatch')
    return value, path, executable


def descriptor_fixture(runtime, fixture_module, states):
    def descriptors(root, inputs, core):
        bundle, assets = inputs
        root.mkdir(mode=0o700)
        subprocess.run(['git', 'init', '--quiet', str(root)], check=True, capture_output=True)
        subprocess.run([str(core), '--project-root', str(root), 'init', '--preset', 'generic'],
                       check=True, capture_output=True, cwd='/', env={}, timeout=15)
        mapped = root / '.harness-gate/runtime/podman-capture-v1'
        mapped.mkdir(mode=0o700, parents=True)
        installation, installation_path, executable = install(root, bundle, assets, runtime, fixture_module)
        states.append({'path': str(installation_path),
                       'mode': stat.S_IMODE(installation_path.stat().st_mode),
                       'sha256': digest(installation_path.read_bytes())})
        fake = fixture_module.Fake(root / 'p.sock')
        try:
            st = (root / 'p.sock').stat()
            context = {'schema': 'gate-runtime/podman-context-v1', 'context': {
                'operator_epoch': 'a' * 32, 'principal_uid': os.geteuid(), 'observation': {
                    'engine': 'podman', 'api_surface': 'libpod', 'selected_api': '6.1.4', 'server_version': '6.1.4',
                    'hostname': 'fixture', 'rootless': os.geteuid() != 0, 'graph_root': '/var/lib/containers/storage',
                    'run_root': '/run/containers/storage', 'remote_socket': None,
                    'socket': {'path': str(root / 'p.sock'), 'device': st.st_dev, 'inode': st.st_ino,
                               'uid': st.st_uid, 'mode': st.st_mode}}}}
            config_path = root / 'context.json'
            host = {'schema': 'gate-runtime/podman-host-v1', 'installation_path': str(installation_path),
                    'installation_sha256': digest(installation_path.read_bytes()), 'config_path': str(config_path),
                    'config_sha256': fixture_module.write(config_path, context)}
            host_path = mapped / 'host.json'
            fixture_module.write(host_path, host)
            return fake, context, installation, host, host_path, executable
        except BaseException:
            fake.close()
            raise
    return descriptors


def verify_report(value, archive, sbom, runtime=None, fixture_module=None, core_version=None):
    if runtime is None:
        runtime = runtime_contract(ROOT)[0]
    if fixture_module is None:
        fixture_module = fixture
    if core_version is None:
        core_version = CORE_VERSION
    cases = fixture_module.CASES
    if (value.get('schema') != 'gateprobes-importer-podman-acceptance/v1'
            or value.get('runtime_tag') != runtime['tag']
            or value.get('runtime_version') != runtime['version']
            or value.get('core_version') != core_version
            or value.get('core_sha256') != fixture_module.CORE_SHA
            or value.get('importer_archive_sha256') != digest(archive)
            or value.get('importer_sbom_sha256') != digest(sbom)
            or value.get('passed') != len(cases)):
        raise ValueError('importer Podman acceptance identity mismatch')
    rows = value.get('cases', [])
    if [r.get('case') for r in rows] != cases:
        raise ValueError('importer Podman case inventory mismatch')
    for index, row in enumerate(rows):
        expected_exit = 0 if index < 2 else 2 if row['case'] in PARSE_ERRORS else 1
        routes = [['GET', '/v6.1.4/libpod/info'], ['GET', '/v6.1.4/libpod/images/' + 'b' * 64 + '/json'], ['GET', '/v6.1.4/libpod/info']] if index < 2 else []
        if (row.get('passed') is not True or row.get('exit') != expected_exit
                or row.get('connections') != (3 if index < 2 else 0)
                or row.get('routes') != routes or row.get('files_created') != []
                or row.get('descriptor_mode') != 0o400
                or not isinstance(row.get('descriptor_path'), str)
                or not row['descriptor_path'].endswith('/installed/installation.json')
                or not isinstance(row.get('descriptor_sha256'), str)
                or len(row['descriptor_sha256']) != 64
                or (index < 2 and row.get('stderr_empty') is not True)
                or (index >= 2 and row.get('stdout_sha256') != digest(b''))):
            raise ValueError('importer Podman acceptance effects mismatch')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'sbom', 'core', 'assets', 'report'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('archive-sha256', 'sbom-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    runtime, _ = runtime_contract(ROOT)
    record, module = load_fixture(runtime['version'])
    core = args.core.resolve(strict=True)
    if digest(core.read_bytes()) != record['core_sha256'] or record['core_sha256'] != EXPECTED['sha256']:
        raise ValueError('Core digest mismatch')
    version = subprocess.run([str(core), '--version'], capture_output=True, timeout=15, check=True)
    if version.stdout != ('harness-gate ' + record['core_version'] + '\n').encode() or version.stderr:
        raise ValueError('Core version mismatch')
    parent = Path.home() / '.cache'
    module.protected(parent)
    root = Path(tempfile.mkdtemp(prefix='ip151-', dir=parent))
    def bounded(path):
        with path.open('rb') as stream:
            return stream.read(LIMIT + 1)
    raw, sbom = bounded(args.archive), bounded(args.sbom)
    bundle = extract(raw, sbom, args.archive_sha256, args.sbom_sha256, root / 'verified', IMPORTER_VERSION)
    if json.loads((bundle / 'plugins/runtime-importer/core-pin-podman.json').read_bytes()) != EXPECTED:
        raise ValueError('extracted importer Core pin differs')
    states = []
    module.fixture = descriptor_fixture(runtime, module, states)
    original_write = module.write
    def writable_negative(path, value):
        if path.name == 'installation.json' and path.exists():
            path.chmod(0o600)
        return original_write(path, value)
    module.write = writable_negative
    report = {'schema': 'gateprobes-importer-podman-acceptance/v1', 'root': str(root),
              'runtime_tag': runtime['tag'], 'runtime_version': runtime['version'],
              'core_version': record['core_version'], 'core_sha256': EXPECTED['sha256'],
              'importer_archive_sha256': args.archive_sha256,
              'importer_sbom_sha256': args.sbom_sha256,
              'limits': 'fake socket only; operator supplies context/host; no real Podman or mutation', 'cases': []}
    try:
        for index, case in enumerate(module.CASES):
            row = module.run_case(case, index, root, (bundle, args.assets.resolve(strict=True)), core)
            state = states[index]
            row.update({'descriptor_path': state['path'], 'descriptor_mode': state['mode'],
                        'descriptor_sha256': state['sha256']})
            report['cases'].append(row)
        report['passed'] = len(report['cases'])
        verify_report(report, raw, sbom, runtime, module, record['core_version'])
    finally:
        with args.report.open('x') as output:
            output.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'root': str(root)}))


if __name__ == '__main__':
    main()
