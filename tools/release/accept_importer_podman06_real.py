#!/usr/bin/env python3
"""Install official Podman0.3 through importer0.6, then run full real lifecycle.

The importer's actual 0400 lifecycle installation descriptor is consumed directly
by official Core0.13.0; no descriptor is rewritten. Only a fresh Core-owned
container from the pinned Alpine image is created and removed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/release'))
from verify_importer_archive import extract
from importer_core_podman import EXPECTED_0_6, runtime_contract

IMPORTER_VERSION = '0.6.0'
BINARY = 'gateprobes-podman-lifecycle'
IMAGE_ID = 'b92841763c5c2140a20eeb2a44e94ebb0e80fd51d9d6b5895ea72fa999525d68'
IMAGE_REF = 'alpine:latest'
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


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def write(path, value, mode=0o400):
    path.write_bytes(canonical(value))
    path.chmod(mode)
    return digest(path.read_bytes())


def protected(path):
    for item in (path, *path.parents):
        st = item.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o022:
            raise ValueError('unprotected imported acceptance directory')


def podman(*args, check=True):
    return subprocess.run(['podman', *args], check=check, capture_output=True, text=True, timeout=300)


def install(bundle, assets, work):
    reviewed = bundle / 'tools/runtime_import/release-pin-podman.json'
    if json.loads(reviewed.read_bytes()) != RUNTIME:
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
    descriptor = destination / 'installation.json'
    if descriptor.is_symlink() or stat.S_IMODE(descriptor.stat().st_mode) != 0o400:
        raise ValueError('installed descriptor is not 0400')
    expected = {'schema': 'gate-runtime/lifecycle-installation-v1',
                'product': 'podman-lifecycle', 'version': '0.3.0',
                'protocol': 'gate-runtime/lifecycle-v1',
                'executable_path': str(destination / BINARY),
                'executable_sha256': RUNTIME['executable_sha256'],
                'config_schema': 'gate-runtime/lifecycle-config-v1'}
    if descriptor.read_bytes() != canonical(expected):
        raise ValueError('installed descriptor differs from importer output')
    executable = destination / BINARY
    if digest(executable.read_bytes()) != RUNTIME['executable_sha256'] or stat.S_IMODE(executable.stat().st_mode) != 0o500:
        raise ValueError('installed executable mismatch')
    if len(list(destination.iterdir())) != 13:
        raise ValueError('installed member count mismatch')
    if (destination / 'config.json').exists() or (destination / 'host.json').exists():
        raise ValueError('importer created operator-owned state')
    return descriptor, executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'sbom', 'assets', 'work', 'report'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('archive-sha256', 'sbom-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--core', required=True, type=Path)
    parser.add_argument('--socket', default=f'/run/user/{os.geteuid()}/podman/podman.sock')
    args = parser.parse_args()
    core = args.core.resolve(strict=True)
    if digest(core.read_bytes()) != EXPECTED_0_6['sha256']:
        raise ValueError('official Core digest mismatch')
    version = subprocess.run([str(core), '--version'], check=True, capture_output=True, text=True, timeout=15)
    if version.stdout != 'harness-gate 0.13.0\n' or version.stderr:
        raise ValueError('official Core version mismatch')
    runtime, _ = runtime_contract(ROOT, '0.6.0')
    if runtime != RUNTIME:
        raise ValueError('current importer runtime pin differs')
    info = json.loads(podman('info', '--format', 'json').stdout)
    if (info['host']['security']['rootless'] is not True or info['version']['APIVersion'] != '5.7.0'
            or info['version']['Version'] != '5.7.0'):
        raise ValueError('Podman rootless 5.7 profile unavailable')
    if podman('image', 'inspect', IMAGE_REF, '--format', '{{.Id}}').stdout.strip() != IMAGE_ID:
        raise ValueError('pinned image digest mismatch')
    sock = Path(args.socket)
    st = sock.stat()
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.geteuid():
        raise ValueError('untrusted Podman socket')
    work = args.work.absolute()
    protected(work.parent)
    if work.exists() or args.report.exists():
        raise ValueError('refuse existing real acceptance output')
    work.mkdir(mode=0o700)
    raw, sbom = args.archive.read_bytes(), args.sbom.read_bytes()
    bundle = extract(raw, sbom, args.archive_sha256, args.sbom_sha256, work / 'verified', IMPORTER_VERSION)
    if json.loads((bundle / 'plugins/runtime-importer/core-pin-podman.json').read_bytes()) != EXPECTED_0_6:
        raise ValueError('extracted importer Core pin differs')
    manifest = json.loads((bundle / 'plugins/runtime-importer/plugin.json').read_bytes())
    if (manifest.get('version'), manifest.get('core_versions'), manifest.get('runtime_tag')) != (
            IMPORTER_VERSION, ['0.13.0'], RUNTIME['tag']):
        raise ValueError('extracted importer manifest differs')
    descriptor, executable = install(bundle, args.assets.resolve(strict=True), work)
    project = work / 'project'
    project.mkdir(mode=0o700)
    subprocess.run(['git', 'init', '--quiet', str(project)], check=True, capture_output=True)
    subprocess.run([str(core), '--project-root', str(project), 'init', '--preset', 'generic'],
                   check=True, capture_output=True, text=True, timeout=60, cwd='/')
    runtime_dir = project / '.harness-gate/runtime/podman-lifecycle-v1'
    runtime_dir.mkdir(parents=True, mode=0o700)
    (project / '.harness-gate/runtime').chmod(0o700)
    runtime_dir.chmod(0o700)
    engine = {'engine': 'podman', 'transport': 'unix-http', 'socket_path': str(sock),
              'socket_uid': st.st_uid, 'principal_uid': os.geteuid(), 'rootless': True,
              'api_version': '5.7.0', 'server_version': '5.7.0',
              'daemon_id': info['host']['hostname'], 'scope': info['store']['graphRoot']}
    config_path = runtime_dir / 'config.json'
    config_sha = write(config_path, {'schema': 'gate-runtime/lifecycle-config-v1', 'engine_binding': engine})
    host_path = runtime_dir / 'host.json'
    write(host_path, {'schema': 'gate-runtime/lifecycle-host-v1',
                      'installation_path': str(descriptor), 'installation_sha256': digest(descriptor.read_bytes()),
                      'config_path': str(config_path), 'config_sha256': config_sha})
    command = ['sh', '-c', 'while true; do { printf \'HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nOK\'; } | nc -l -p 8080; done']
    healthcheck = ['wget', '-q', '-O', '/dev/null', 'http://127.0.0.1:8080/']
    flow = project / '.harness-gate/flow.toml'
    flow.write_text(flow.read_text() + f'''

[services.fixture]
kind = "docker"
runtime = "podman"
image = "{IMAGE_REF}"
lifecycle_host = "{host_path}"
inject_env = "FIXTURE_URL"
startup_timeout_secs = 20
container_port = 8080
environment = {{}}
healthcheck = {json.dumps(healthcheck)}
command = {json.dumps(command)}
connection = "http://127.0.0.1:{{host_port}}"

[[steps]]
id = "service.probe"
label = "Importer-installed Podman lifecycle HTTP probe"
component = "project"
profiles = ["full"]
program = "python3"
args = ["-c", "import os,urllib.request; urllib.request.urlopen(os.environ['FIXTURE_URL'], timeout=10).read()"]
cwd = "{{root}}"
log = "service_probe.log"
timeout_secs = 60
services = ["fixture"]
remove_env = []
depends_on = []
input = "repository"
''')
    result = subprocess.run([str(core), '--project-root', str(project), 'verify', '--all'],
                            capture_output=True, text=True, timeout=300)
    if result.returncode != 0 or 'TEST_SUMMARY: PASS' not in result.stdout:
        raise ValueError('real lifecycle verification failed: ' + result.stdout + result.stderr)
    records = list((project / '.harness-gate/lifecycle-services').glob('*/service.json'))
    if len(records) != 1:
        raise ValueError('unexpected lifecycle service records')
    service = json.loads(records[0].read_text())
    if service.get('released') is not True:
        raise ValueError('lifecycle service was not released')
    name = service['plan']['name']
    if not name.startswith('gatehouse-'):
        raise ValueError('unexpected lifecycle container name')
    if podman('container', 'exists', name, check=False).returncode == 0:
        raise ValueError('lifecycle container was not removed')
    report = {
        'schema': 'gateprobes-importer-podman06-real-acceptance/v1',
        'importer_version': IMPORTER_VERSION,
        'importer_archive_sha256': args.archive_sha256, 'importer_sbom_sha256': args.sbom_sha256,
        'core_sha256': EXPECTED_0_6['sha256'], 'core_version': '0.13.0',
        'runtime_tag': RUNTIME['tag'], 'runtime_version': RUNTIME['version'],
        'descriptor': {'path': str(descriptor), 'mode': stat.S_IMODE(descriptor.stat().st_mode),
                       'sha256': digest(descriptor.read_bytes())},
        'executable_sha256': digest(executable.read_bytes()), 'executable_mode': stat.S_IMODE(executable.stat().st_mode),
        'image_id': IMAGE_ID, 'podman_version': info['version']['Version'],
        'container_name': name, 'service_released': True, 'container_absent': True,
        'verification': 'PASS'
    }
    with args.report.open('x') as output:
        output.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print('real pass', name)


if __name__ == '__main__':
    main()
