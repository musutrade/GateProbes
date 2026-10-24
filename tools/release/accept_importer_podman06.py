#!/usr/bin/env python3
"""Install released Podman0.3 through the extracted importer0.6 and verify its descriptor.

The installer is executed from the extracted importer archive with the official
Core0.13/Podman0.3 pins. This is an offline fake/installer acceptance: it does not
execute the adapter or contact Podman. The operator-owned config/host are absent.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/runtime_import'))

from verify_importer_archive import extract, LIMIT
import preflight
from importer_core_podman import EXPECTED_0_6, runtime_contract
IMPORTER_VERSION = '0.6.0'
BINARY = 'gateprobes-podman-lifecycle'
RUNTIME = {'schema': 'gateprobes-runtime-release-pin/v1',
           'repository': 'https://github.com/musutrade/GateProbes',
           'tag': 'podman-lifecycle-v0.3.0', 'version': '0.3.0',
           'source_commit': 'c802fffaee9fdbea1ce9d4642ac14cb998882b20',
           'executable_sha256': 'efca5ba3b8e8bbbf0d7cce0efdce12b3f58fba190e01ba790bac81650c972d9d',
           'archive_sha256': '044a1e9d6d7be82ca8e83b8f810ce6c266825a793d77f418d14efd13a69d69a0',
           'sbom_sha256': 'f66dbe03e8c7b1f8cc20f93b1ad3857ec908b6f4158073965a2b515a64bbf262',
           'inventory_sha256': '8713afa1cb1fa52509d36541ffc8d0098a6defc00f2ba1bc4e5beb8793a5bc4b',
           'checksums_sha256': '389c309ec6deb477815e25c6919616f17cbcbdfd27acfc9c27dba76a902bf12c'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def protected(path):
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        raise ValueError('unprotected importer acceptance directory')


def expected_descriptor(destination):
    return {'schema': 'gate-runtime/lifecycle-installation-v1',
            'product': 'podman-lifecycle', 'version': '0.3.0',
            'protocol': 'gate-runtime/lifecycle-v1',
            'executable_path': str(destination / BINARY),
            'executable_sha256': RUNTIME['executable_sha256'],
            'config_schema': 'gate-runtime/lifecycle-config-v1'}


def install(bundle, assets, root):
    reviewed = bundle / 'tools/runtime_import/release-pin-podman.json'
    if json.loads(reviewed.read_bytes()) != RUNTIME:
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
    path = destination / 'installation.json'
    if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) != 0o400:
        raise ValueError('installed descriptor is not a regular 0400 file')
    value = expected_descriptor(destination)
    if path.read_bytes() != json.dumps(value, sort_keys=True, separators=(',', ':')).encode():
        raise ValueError('installed descriptor differs from importer output')
    executable = destination / BINARY
    if digest(executable.read_bytes()) != RUNTIME['executable_sha256']:
        raise ValueError('installed executable digest mismatch')
    if stat.S_IMODE(executable.stat().st_mode) != 0o500:
        raise ValueError('installed executable mode mismatch')
    if len(list(destination.iterdir())) != 13:
        raise ValueError('installed member count mismatch')
    if (destination / 'config.json').exists() or (destination / 'host.json').exists():
        raise ValueError('importer created operator-owned state')
    for member in destination.iterdir():
        expected = 0o500 if member == executable else 0o400
        if stat.S_IMODE(member.stat().st_mode) != expected:
            raise ValueError('installed output mode mismatch')
    return path, value


def verify_report(value, archive, sbom, core):
    if (value.get('schema') != 'gateprobes-importer-podman06-install-acceptance/v1'
            or value.get('importer_version') != IMPORTER_VERSION
            or value.get('core_version') != '0.13.0'
            or value.get('core_sha256') != EXPECTED_0_6['sha256']
            or value.get('runtime_tag') != RUNTIME['tag']
            or value.get('runtime_version') != RUNTIME['version']
            or value.get('importer_archive_sha256') != digest(archive)
            or value.get('importer_sbom_sha256') != digest(sbom)
            or value.get('passed') != 7):
        raise ValueError('importer0.6 acceptance identity mismatch')
    rows = value.get('cases', [])
    names = ['extract', 'install', 'descriptor-0400', 'executable-0500',
             'no-operator-state', 'capture-profile-refused', 'historical-0.5-pins']
    if [row.get('case') for row in rows] != names or not all(row.get('passed') is True for row in rows):
        raise ValueError('importer0.6 acceptance cases differ')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'sbom', 'core', 'assets', 'report'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('archive-sha256', 'sbom-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    core = args.core.resolve(strict=True)
    if digest(core.read_bytes()) != EXPECTED_0_6['sha256']:
        raise ValueError('Core digest mismatch')
    core_version = subprocess.run([str(core), '--version'], capture_output=True, text=True, timeout=15, check=True)
    if core_version.stdout != 'harness-gate 0.13.0\n' or core_version.stderr:
        raise ValueError('Core version mismatch')
    runtime, _ = runtime_contract(ROOT, '0.6.0')
    if runtime != RUNTIME:
        raise ValueError('current importer runtime pin differs')
    parent = Path.home() / '.cache'
    protected(parent)
    root = Path(tempfile.mkdtemp(prefix='ip06-', dir=parent))
    raw, sbom = args.archive.read_bytes(), args.sbom.read_bytes()
    if len(raw) > LIMIT or len(sbom) > LIMIT:
        raise ValueError('importer asset too large')
    bundle = extract(raw, sbom, args.archive_sha256, args.sbom_sha256, root / 'verified', IMPORTER_VERSION)
    if json.loads((bundle / 'plugins/runtime-importer/core-pin-podman.json').read_bytes()) != EXPECTED_0_6:
        raise ValueError('extracted importer Core pin differs')
    manifest = json.loads((bundle / 'plugins/runtime-importer/plugin.json').read_bytes())
    if (manifest.get('version'), manifest.get('core_versions'), manifest.get('runtime_tag')) != (
            IMPORTER_VERSION, ['0.13.0'], RUNTIME['tag']):
        raise ValueError('extracted importer manifest differs')
    path, descriptor = install(bundle, args.assets.resolve(strict=True), root)
    try:
        preflight.profile({'tag': 'podman-lifecycle-v0.2.0', 'version': '0.3.0'})
    except preflight.InvalidRelease:
        capture_refused = True
    else:
        capture_refused = False
    if not capture_refused:
        raise ValueError('capture-only profile was not refused for the 0.3 lifecycle pin')
    # The historical 0.5 constants remain fixed; they are not reinterpreted by 0.6.
    from importer_core_podman import EXPECTED
    historical = EXPECTED
    if (historical['version'], historical['source_commit'], historical['sha256']) != (
            '0.12.0', '84a306e8f35674b79aaafa0a0fecd05d6087ac24',
            '6890e4465c9d86f53cffe8c58103a650babd03db895e27ae99928659c4f1d1d6'):
        raise ValueError('historical 0.5 Core pin changed')
    report = {
        'schema': 'gateprobes-importer-podman06-install-acceptance/v1',
        'importer_version': IMPORTER_VERSION,
        'importer_archive_sha256': args.archive_sha256,
        'importer_sbom_sha256': args.sbom_sha256,
        'core_version': '0.13.0', 'core_sha256': EXPECTED_0_6['sha256'],
        'runtime_tag': RUNTIME['tag'], 'runtime_version': RUNTIME['version'],
        'descriptor': {'path': str(path), 'mode': stat.S_IMODE(path.stat().st_mode),
                       'sha256': digest(path.read_bytes()), 'value': descriptor},
        'passed': 7,
        'cases': [
            {'case': 'extract', 'passed': True},
            {'case': 'install', 'passed': True},
            {'case': 'descriptor-0400', 'passed': True},
            {'case': 'executable-0500', 'passed': True},
            {'case': 'no-operator-state', 'passed': True},
            {'case': 'capture-profile-refused', 'passed': capture_refused},
            {'case': 'historical-0.5-pins', 'passed': True},
        ],
        'limits': 'offline installer/fake acceptance only; no adapter execution or engine I/O',
    }
    verify_report(report, raw, sbom, core)
    with args.report.open('x') as output:
        output.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'descriptor': str(path)}))


if __name__ == '__main__':
    main()
