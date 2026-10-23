#!/usr/bin/env python3
"""Install official Podman0.2 through the extracted importer, then run read-only Core."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess

from verify_importer_archive import extract, LIMIT
from importer_core_podman import EXPECTED, runtime_contract

ROOT = Path(__file__).resolve().parents[2]
IMPORTER_VERSION = '0.5.0'
REAL_HELPER_PATH = ROOT / 'plugins/podman-lifecycle/accept_real.py'
REAL_HELPER_SHA256 = '7897e70f82a00cb621274b410a303f2cb8f650f1be24abd489e0769601cf8bd4'

def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_real():
    if digest(REAL_HELPER_PATH.read_bytes()) != REAL_HELPER_SHA256:
        raise ValueError('reviewed real acceptance helper digest mismatch')
    spec = importlib.util.spec_from_file_location('podman_accept_real_0_2', REAL_HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def protected(path):
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        raise ValueError('unprotected real acceptance directory')


def install(bundle, assets, work, runtime):
    reviewed = bundle / 'tools/runtime_import/release-pin-podman.json'
    if json.loads(reviewed.read_bytes()) != runtime:
        raise ValueError('extracted importer runtime pin differs')
    pin = work / 'pin.json'
    pin.write_bytes(reviewed.read_bytes())
    pin.chmod(0o400)
    destination = work / 'installed'
    result = subprocess.run(['python3', '-I', '-B', str(bundle / 'tools/runtime_import/install.py'),
                             '--pin', str(pin), '--assets', str(assets), '--destination', str(destination)],
                            env={'PATH': os.environ['PATH'], 'HOME': str(work)}, cwd=work,
                            capture_output=True, text=True, timeout=30)
    if result.returncode != 0 or result.stderr:
        raise ValueError('extracted importer installation failed: ' + result.stderr)
    path = destination / 'installation.json'
    mode = stat.S_IMODE(path.stat().st_mode)
    if path.is_symlink() or mode != 0o400:
        raise ValueError('installed descriptor is not a regular 0400 file')
    value = json.loads(path.read_bytes())
    if (value.get('product'), value.get('version'), value.get('protocol')) != (
            'podman-lifecycle', runtime['version'], 'gate-runtime/lifecycle-v2'):
        raise ValueError('installed descriptor identity mismatch')
    if value.get('executable_sha256') != runtime['executable_sha256']:
        raise ValueError('installed descriptor executable binding mismatch')
    if path.read_bytes() != json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode():
        raise ValueError('installed descriptor is not canonical importer output')
    if len(list(destination.iterdir())) != 13:
        raise ValueError('installed importer member count mismatch')
    executable = destination / 'gateprobes-podman-lifecycle'
    for member in destination.iterdir():
        expected_mode = 0o500 if member == executable else 0o400
        if stat.S_IMODE(member.stat().st_mode) != expected_mode:
            raise ValueError('installed importer output mode mismatch')
    if (destination / 'context.json').exists() or (destination / 'host.json').exists():
        raise ValueError('importer created operator-owned context/host')
    return path, value, executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'sbom', 'core', 'assets', 'socket', 'work', 'report'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('archive-sha256', 'sbom-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    work = args.work.absolute()
    protected(work.parent)
    if work.exists():
        raise ValueError('real acceptance work directory already exists')
    work.mkdir(mode=0o700)
    runtime, _ = runtime_contract(ROOT)
    if runtime['version'] != '0.2.0':
        raise ValueError('this acceptance requires Podman0.2')
    core = args.core.resolve(strict=True)
    if digest(core.read_bytes()) != EXPECTED['sha256']:
        raise ValueError('Core digest mismatch')
    version = subprocess.run([str(core), '--version'], capture_output=True, timeout=15, check=True)
    if version.stdout != b'harness-gate 0.12.0\n' or version.stderr:
        raise ValueError('Core version mismatch')
    raw = args.archive.read_bytes()
    sbom = args.sbom.read_bytes()
    if len(raw) > LIMIT or len(sbom) > LIMIT:
        raise ValueError('importer asset too large')
    bundle = extract(raw, sbom, args.archive_sha256, args.sbom_sha256, work / 'verified', IMPORTER_VERSION)
    if json.loads((bundle / 'plugins/runtime-importer/core-pin-podman.json').read_bytes()) != EXPECTED:
        raise ValueError('extracted importer Core pin differs')
    manifest = json.loads((bundle / 'plugins/runtime-importer/plugin.json').read_bytes())
    if (manifest.get('version'), manifest.get('core_versions'), manifest.get('runtime_tag')) != (
            IMPORTER_VERSION, ['0.12.0'], runtime['tag']):
        raise ValueError('extracted importer manifest differs')
    real = load_real()
    socket_path = args.socket.resolve(strict=True)
    socket_stat = socket_path.lstat()
    if not stat.S_ISSOCK(socket_stat.st_mode) or socket_stat.st_uid != os.geteuid():
        raise ValueError('rootless user Unix socket required')
    info_status, info_bytes = real.http_get(socket_path, f'/v{real.API}/libpod/info')
    if info_status != 200:
        raise ValueError('Podman info unavailable')
    info = json.loads(info_bytes)
    if (info['version']['APIVersion'] != real.API or info['version']['Version'] != real.API
            or info['host']['security']['rootless'] is not True):
        raise ValueError('real Podman does not match read-only 5.7 profile')
    image_status, image_bytes = real.http_get(socket_path, f'/v{real.API}/libpod/images/{real.IMAGE_ID}/json')
    if image_status != 200 or json.loads(image_bytes).get('Id') != real.IMAGE_ID:
        raise ValueError('pinned image unavailable or mismatched')
    subprocess.run([str(core), '--project-root', str(work), 'init', '--preset', 'generic'],
                   cwd='/', env={}, check=True, capture_output=True, timeout=15)
    descriptor_path, descriptor, executable = install(bundle, args.assets.resolve(strict=True), work, runtime)
    context_path, context = real.context(work, socket_path, socket_stat, info)
    host = {'schema': 'gate-runtime/podman-host-v1',
            'installation_path': str(descriptor_path),
            'installation_sha256': digest(descriptor_path.read_bytes()),
            'config_path': str(context_path),
            'config_sha256': digest(context_path.read_bytes())}
    host_path = work / '.harness-gate/runtime/podman-capture-v1/host.json'
    real.write(host_path, host)
    argv = [str(core), '--project-root', str(work), 'podman-capture', '--trust-host',
            '--image-id', real.IMAGE_ID, '--name', 'fixture', '--label', 'owner=fixture',
            '--timeout-ms', '30000']
    result = subprocess.run(argv, cwd='/', env={}, capture_output=True, timeout=15)
    if result.returncode != 0 or result.stderr:
        raise ValueError(f'capture failed: exit={result.returncode} stderr={result.stderr[:200]!r}')
    record = json.loads(result.stdout)
    if (record.get('profile') != {'protocol': 'gate-runtime/lifecycle-v2', 'product': 'podman-lifecycle',
                                  'version': runtime['version'], 'engine': 'podman'}
            or record.get('image_id') != real.IMAGE_ID
            or record.get('asserted_installation_sha256') != digest(descriptor_path.read_bytes())
            or record.get('asserted_executable_sha256') != digest(executable.read_bytes())):
        raise ValueError('Core did not consume the importer installation descriptor')
    after_status, after_bytes = real.http_get(socket_path, f'/v{real.API}/libpod/info')
    if after_status != 200:
        raise ValueError('post-capture Podman info unavailable')
    after_info = json.loads(after_bytes)
    before_counts = (info['store']['imageStore']['number'], info['store']['containerStore']['number'])
    after_counts = (after_info['store']['imageStore']['number'], after_info['store']['containerStore']['number'])
    if before_counts != after_counts:
        raise ValueError('read-only capture changed image/container counts')
    report = {
        'schema': 'gateprobes-importer-podman-real-acceptance/v1',
        'importer_version': IMPORTER_VERSION,
        'importer_archive_sha256': args.archive_sha256,
        'importer_sbom_sha256': args.sbom_sha256,
        'runtime_tag': runtime['tag'], 'runtime_version': runtime['version'],
        'runtime_assets': {name: {'sha256': digest((args.assets / name).read_bytes()),
                                  'size_bytes': (args.assets / name).stat().st_size}
                           for name in ('gateprobes-podman-lifecycle-0.2.0-linux-amd64.tar.gz',
                                       'gateprobes-podman-lifecycle-0.2.0-linux-amd64.tar.gz.sbom.cdx.json',
                                       'release-inventory.json', 'SHA256SUMS')},
        'core_version': version.stdout.decode().strip(), 'core_sha256': digest(core.read_bytes()),
        'descriptor': {'path': str(descriptor_path), 'mode': stat.S_IMODE(descriptor_path.stat().st_mode),
                       'mode_octal': '0400', 'sha256': digest(descriptor_path.read_bytes()),
                       'value': descriptor},
        'executable_sha256': digest(executable.read_bytes()),
        'executable_mode': stat.S_IMODE(executable.stat().st_mode),
        'host_sha256': digest(host_path.read_bytes()),
        'context_sha256': digest(context_path.read_bytes()),
        'socket': {'path': str(socket_path), 'device': socket_stat.st_dev, 'inode': socket_stat.st_ino,
                   'uid': socket_stat.st_uid, 'mode': socket_stat.st_mode},
        'image_id': real.IMAGE_ID, 'image_count': before_counts[0], 'container_count': before_counts[1],
        'record_sha256': digest(result.stdout),
        'record_sanitized': {key: record[key] for key in ('profile', 'image_id', 'image_sha256',
                                                          'plan_sha256', 'plan_json',
                                                          'asserted_installation_sha256',
                                                          'asserted_executable_sha256',
                                                          'config_sha256', 'operator_epoch')},
        'cases': {'importer_install': True, 'descriptor_0400': True,
                  'core_consumed_descriptor': True, 'real_info': True,
                  'pinned_image': True, 'capture': True, 'counts_unchanged': True},
        'limits': 'real rootless Unix socket; read-only GET/capture only; no pull/run/restart; '
                  'counts are corroborating evidence, not a no-mutation proof',
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'report': str(args.report), 'work': str(work)}))


if __name__ == '__main__':
    main()
