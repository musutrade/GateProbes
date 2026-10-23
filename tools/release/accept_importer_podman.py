#!/usr/bin/env python3
"""Extract the externally verified importer; Core consumes its installed descriptor."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

from verify_importer_archive import extract, LIMIT
from importer_core_podman import EXPECTED, runtime_contract
from verify_podman_acceptance import CASES, PARSE_ERRORS

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('podman_fixture', ROOT / 'plugins/podman-lifecycle/accept.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
digest, canonical = fixture.digest, fixture.canonical


def install(root, bundle, assets):
    reviewed = bundle / 'tools/runtime_import/release-pin-podman.json'
    runtime, _ = runtime_contract(ROOT)
    assert json.loads(reviewed.read_bytes()) == runtime
    pin = root / 'pin.json'
    pin.write_bytes(reviewed.read_bytes()); pin.chmod(0o400)
    destination = root / 'installed'
    result = subprocess.run(['python3', '-I', '-B', str(bundle / 'tools/runtime_import/install.py'),
                             '--pin', str(pin), '--assets', str(assets), '--destination', str(destination)],
                            env={'PATH': os.environ['PATH'], 'HOME': str(root)}, cwd=root,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0 and not result.stderr, result
    executable = destination / fixture.BINARY
    path = destination / 'installation.json'
    value = {'schema': 'gate-runtime/podman-installation-v1', 'product': 'podman-lifecycle',
             'version': '0.1.0', 'protocol': 'gate-runtime/lifecycle-v2', 'executable_path': str(executable),
             'executable_sha256': runtime['executable_sha256'], 'config_schema': 'gate-runtime/podman-context-v1'}
    assert path.read_bytes() == canonical(value)
    assert digest(executable.read_bytes()) == runtime['executable_sha256']
    assert len(list(destination.iterdir())) == 13
    assert not (destination / 'context.json').exists() and not (destination / 'host.json').exists()
    for member in destination.iterdir():
        assert member.stat().st_mode & 0o777 == (0o500 if member == executable else 0o400)
    return value, path, executable


def descriptors(root, inputs, core):
    bundle, assets = inputs
    root.mkdir(mode=0o700)
    subprocess.run(['git', 'init', '--quiet', str(root)], check=True, capture_output=True)
    subprocess.run([str(core), '--project-root', str(root), 'init', '--preset', 'generic'],
                   check=True, capture_output=True, cwd='/', env={}, timeout=15)
    mapped = root / '.harness-gate/runtime/podman-capture-v1'
    mapped.mkdir(mode=0o700, parents=True)
    installation, installation_path, executable = install(root, bundle, assets)
    fake = fixture.Fake(root / 'p.sock')
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
                'config_sha256': fixture.write(config_path, context)}
        host_path = mapped / 'host.json'
        fixture.write(host_path, host)
        return fake, context, installation, host, host_path, executable
    except BaseException:
        fake.close()
        raise


def verify_report(value, archive, sbom):
    if (value.get('schema') != 'gateprobes-importer-podman-acceptance/v1'
            or value.get('core_sha256') != EXPECTED['sha256']
            or value.get('importer_archive_sha256') != digest(archive)
            or value.get('importer_sbom_sha256') != digest(sbom)
            or value.get('passed') != len(CASES)):
        raise ValueError('importer Podman acceptance identity mismatch')
    rows = value.get('cases', [])
    if [r.get('case') for r in rows] != CASES:
        raise ValueError('importer Podman case inventory mismatch')
    for index, row in enumerate(rows):
        expected_exit = 0 if index < 2 else 2 if row['case'] in PARSE_ERRORS else 1
        routes = [['GET', '/v6.1.4/libpod/info'], ['GET', '/v6.1.4/libpod/images/' + 'b' * 64 + '/json'], ['GET', '/v6.1.4/libpod/info']] if index < 2 else []
        if (row.get('passed') is not True or row.get('exit') != expected_exit
                or row.get('connections') != (3 if index < 2 else 0)
                or row.get('routes') != routes or row.get('files_created') != []
                or (index < 2 and row.get('stderr_empty') is not True)
                or (index >= 2 and row.get('stdout_sha256') != digest(b''))):
            raise ValueError('importer Podman acceptance effects mismatch')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'sbom', 'core', 'assets', 'report'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('archive-sha256', 'sbom-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    core = args.core.resolve(strict=True)
    assert digest(core.read_bytes()) == EXPECTED['sha256']
    version = subprocess.run([str(core), '--version'], capture_output=True, timeout=15, check=True)
    assert version.stdout == b'harness-gate 0.11.0\n' and not version.stderr
    parent = Path.home() / '.cache'
    fixture.protected(parent)
    root = Path(tempfile.mkdtemp(prefix='ip144-', dir=parent))
    def bounded(path):
        with path.open('rb') as stream: return stream.read(LIMIT + 1)
    raw, sbom = bounded(args.archive), bounded(args.sbom)
    bundle = extract(raw, sbom, args.archive_sha256, args.sbom_sha256, root / 'verified', '0.4.0')
    assert json.loads((bundle / 'plugins/runtime-importer/core-pin-podman.json').read_bytes()) == EXPECTED
    fixture.fixture = descriptors
    original_write = fixture.write
    def writable_negative(path, value):
        if path.name == 'installation.json' and path.exists():
            path.chmod(0o600)
        return original_write(path, value)
    fixture.write = writable_negative
    report = {'schema': 'gateprobes-importer-podman-acceptance/v1', 'root': str(root),
              'core_sha256': EXPECTED['sha256'], 'importer_archive_sha256': args.archive_sha256,
              'importer_sbom_sha256': args.sbom_sha256,
              'limits': 'fake socket only; operator supplies context/host; no real Podman or mutation', 'cases': []}
    try:
        for index, case in enumerate(CASES):
            report['cases'].append(fixture.run_case(case, index, root, (bundle, args.assets.resolve(strict=True)), core))
        report['passed'] = len(report['cases'])
        verify_report(report, raw, sbom)
    finally:
        with args.report.open('x') as output: output.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'root': str(root)}))


if __name__ == '__main__':
    main()
