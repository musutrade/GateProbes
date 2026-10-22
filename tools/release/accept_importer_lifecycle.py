#!/usr/bin/env python3
"""Trusted-checkout acceptance of extracted importer and installed lifecycle bytes."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

from verify_importer_archive import extract, LIMIT
from importer_core_lifecycle import EXPECTED, runtime_contract

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('lifecycle_fixture', ROOT / 'plugins/docker-lifecycle/accept.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
digest, canonical, write_json = fixture.digest, fixture.canonical, fixture.write_json


def descriptors(root, inputs, case):
    bundle, assets = inputs
    reviewed = bundle / 'tools/runtime_import/release-pin-lifecycle.json'
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
    executable = destination / 'gateprobes-docker-lifecycle'
    installation_path = destination / 'installation.json'
    installation = {'schema': 'gate-runtime/lifecycle-installation-v1', 'product': 'docker-lifecycle',
        'version': '0.1.0', 'protocol': 'gate-runtime/lifecycle-v1', 'executable_path': str(executable),
        'executable_sha256': runtime['executable_sha256'], 'config_schema': 'gate-runtime/lifecycle-config-v1'}
    assert installation_path.read_bytes() == canonical(installation)
    assert digest(executable.read_bytes()) == runtime['executable_sha256']
    assert len(list(destination.iterdir())) == 14
    assert not (destination / 'config.json').exists() and not (destination / 'host.json').exists()
    for file in destination.iterdir():
        assert file.stat().st_mode & 0o777 == (0o500 if file == executable else 0o400)
    # The operator fixture supplies engine authority independently of the installer.
    config = {'schema': 'gate-runtime/lifecycle-config-v1', 'engine_binding': {'engine': 'docker',
        'transport': 'unix-http', 'socket_path': str(root / 'fake.sock'), 'socket_uid': os.geteuid(),
        'principal_uid': os.geteuid(), 'rootless': False, 'api_version': '1.47', 'server_version': '27.0.1',
        'daemon_id': 'lifecycle-acceptance-daemon', 'scope': 'fake-only'}}
    if case.startswith('installation-'):
        field = case.removeprefix('installation-')
        installation[field] = {'product': 'docker-readiness', 'version': '0.1.1', 'protocol': 'gate-runtime/lifecycle-v2'}[field]
        installation_path.chmod(0o600)
        write_json(installation_path, installation)
    if case == 'config-schema': config['schema'] = 'gate-runtime/lifecycle-config-v2'
    if case == 'config-principal': config['engine_binding']['principal_uid'] += 1
    if case == 'config-engine': config['engine_binding']['engine'] = 'podman'
    host = {'schema': 'gate-runtime/lifecycle-host-v1', 'installation_path': str(installation_path),
        'installation_sha256': digest(installation_path.read_bytes()),
        'config_path': str(root / 'config.json'), 'config_sha256': write_json(root / 'config.json', config)}
    if case == 'host-digest': host['installation_sha256'] = '0' * 64
    path = root / 'host.json'; write_json(path, host)
    if case == 'host-mode': path.chmod(0o644)
    if case == 'executable-digest':
        executable.chmod(0o700); executable.write_bytes(executable.read_bytes() + b'tampered'); executable.chmod(0o500)
    if case == 'executable-mode': executable.chmod(0o644)
    if case in ('descriptor-symlink', 'host-symlink'):
        link = root / ('config.json' if case == 'descriptor-symlink' else 'host.json')
        target = root / 'original.json'; link.rename(target); link.symlink_to(target)
    return path


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
    version = subprocess.run([str(core), '--version'], capture_output=True, text=True, check=True)
    assert version.stdout.strip() == 'harness-gate 0.10.0' and not version.stderr
    parent = Path.home() / '.cache'
    for path in [parent, *parent.parents]:
        st = path.lstat()
        assert path.is_dir() and not path.is_symlink() and st.st_uid in (0, os.geteuid()) and not st.st_mode & 0o022
    root = Path(tempfile.mkdtemp(prefix='il85-', dir=parent))
    def bounded(path):
        with path.open('rb') as stream: return stream.read(LIMIT + 1)
    bundle = extract(bounded(args.archive), bounded(args.sbom), args.archive_sha256,
                     args.sbom_sha256, root / 'verified', '0.3.0')
    assert json.loads((bundle / 'plugins/runtime-importer/core-pin-lifecycle.json').read_bytes()) == EXPECTED
    fixture.descriptors = descriptors
    report = {'root': str(root), 'core_sha256': EXPECTED['sha256'],
              'importer_archive_sha256': args.archive_sha256, 'importer_sbom_sha256': args.sbom_sha256,
              'limits': 'fake socket only; operator fixture supplies config/host; no daemon', 'cases': []}
    try:
        for case in ('normal', 'health-failure', *fixture.NEGATIVES):
            report['cases'].append(fixture.run_case(root, core, (bundle, args.assets.resolve(strict=True)), case))
        report['passed'] = len(report['cases'])
    finally:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'root': str(root)}))


if __name__ == '__main__':
    main()
