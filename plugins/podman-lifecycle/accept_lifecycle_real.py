#!/usr/bin/env python3
"""Exercise the extracted Podman 0.3.0 archive through official Core on real Podman.

The project uses the pinned Alpine image, a unique Core-owned container name and
a real rootless Podman 5.7 socket. A successful run proves the extracted binary
survives create -> start -> health -> stop -> remove and leaves no container.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import tarfile

BINARY = 'gateprobes-podman-lifecycle'
PREFIX = 'gateprobes-podman-lifecycle-0.3.0-linux-amd64'
CORE_SHA = '1800325ea2f541dd9b011c03dc93c3dac341e839ece6289ebe778275dcaacf75'
IMAGE_ID = 'b92841763c5c2140a20eeb2a44e94ebb0e80fd51d9d6b5895ea72fa999525d68'
IMAGE_REF = 'alpine:latest'
MEMBERS = {BINARY, 'plugin.json', 'README.md', 'Cargo.toml', 'Cargo.lock', 'LICENSE',
           'THIRD_PARTY_NOTICES.txt', 'rust-toolchain.toml', 'build-inputs.json',
           'accept_lifecycle.py', 'core-pin.json', 'protocol-LICENSE'}


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
            raise ValueError('unprotected real acceptance directory')


def extract(archive, expected, work):
    if digest(archive.read_bytes()) != expected:
        raise ValueError('archive digest mismatch')
    with tarfile.open(archive, 'r:gz') as stream:
        members = stream.getmembers()
        if len(members) != len(MEMBERS) or {m.name for m in members} != {PREFIX + '/' + n for n in MEMBERS}:
            raise ValueError('archive member mismatch')
        for member in members:
            name = member.name.removeprefix(PREFIX + '/')
            if (not member.isfile() or member.pax_headers or member.uid or member.gid
                    or member.mtime or member.size <= 0
                    or member.mode != (0o755 if name == BINARY else 0o644)):
                raise ValueError('archive metadata mismatch')
        work.mkdir(mode=0o700)
        stream.extractall(work, filter='data')
    installed = work / PREFIX
    installed.chmod(0o700)
    return installed


def podman(*args, check=True):
    return subprocess.run(['podman', *args], check=check, capture_output=True, text=True, timeout=300)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('archive', 'core', 'work', 'report'):
        parser.add_argument('--' + key, required=True, type=Path)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--core-sha256', required=True)
    parser.add_argument('--socket', default=f'/run/user/{os.geteuid()}/podman/podman.sock')
    args = parser.parse_args()
    core = args.core.resolve(strict=True)
    if args.core_sha256 != CORE_SHA or digest(core.read_bytes()) != CORE_SHA:
        raise ValueError('official Core digest mismatch')
    version = subprocess.run([str(core), '--version'], check=True, capture_output=True, text=True, timeout=15)
    if version.stdout != 'harness-gate 0.13.0\n' or version.stderr:
        raise ValueError('official Core version mismatch')
    info = json.loads(podman('info', '--format', 'json').stdout)
    if (info['host']['hostname'], info['host']['security']['rootless'],
            info['version']['APIVersion'], info['version']['Version']) != (
            info['host']['hostname'], True, '5.7.0', '5.7.0'):
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
    installed = extract(args.archive, args.archive_sha256, work)
    project = work / 'project'
    project.mkdir(mode=0o700)
    subprocess.run(['git', 'init', '--quiet', str(project)], check=True, capture_output=True)
    subprocess.run([str(core), '--project-root', str(project), 'init', '--preset', 'generic'],
                   check=True, capture_output=True, text=True, timeout=60, cwd='/')
    runtime = project / '.harness-gate/runtime/podman-lifecycle-v1'
    runtime.mkdir(parents=True, mode=0o700)
    (project / '.harness-gate/runtime').chmod(0o700)
    runtime.chmod(0o700)
    executable = runtime / BINARY
    shutil.copyfile(installed / BINARY, executable)
    executable.chmod(0o755)
    engine = {'engine': 'podman', 'transport': 'unix-http', 'socket_path': str(sock),
              'socket_uid': st.st_uid, 'principal_uid': os.geteuid(), 'rootless': True,
              'api_version': '5.7.0', 'server_version': '5.7.0',
              'daemon_id': info['host']['hostname'], 'scope': info['store']['graphRoot']}
    config_path = runtime / 'config.json'
    config_sha = write(config_path, {'schema': 'gate-runtime/lifecycle-config-v1', 'engine_binding': engine})
    installation_path = runtime / 'installation.json'
    installation_sha = write(installation_path, {
        'schema': 'gate-runtime/lifecycle-installation-v1', 'product': 'podman-lifecycle',
        'version': '0.3.0', 'protocol': 'gate-runtime/lifecycle-v1',
        'executable_path': str(executable), 'executable_sha256': digest(executable.read_bytes()),
        'config_schema': 'gate-runtime/lifecycle-config-v1'})
    host_path = runtime / 'host.json'
    write(host_path, {'schema': 'gate-runtime/lifecycle-host-v1',
                      'installation_path': str(installation_path), 'installation_sha256': installation_sha,
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
label = "Podman lifecycle HTTP probe"
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
    check = subprocess.run([str(core), '--project-root', str(project), 'config', 'check'],
                           capture_output=True, text=True, timeout=60)
    if check.returncode != 0:
        raise ValueError('real project configuration rejected: ' + check.stdout + check.stderr)
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
        'schema': 'gateprobes-podman-lifecycle-real-acceptance/v1',
        'product': 'podman-lifecycle', 'version': '0.3.0',
        'archive_sha256': args.archive_sha256, 'core_sha256': CORE_SHA, 'core_version': '0.13.0',
        'adapter_sha256': digest(executable.read_bytes()), 'image_reference': IMAGE_REF,
        'image_id': IMAGE_ID, 'podman_version': info['version']['Version'],
        'container_name': name, 'service_released': True, 'container_absent': True,
        'verification': 'PASS', 'verify_stdout_sha256': digest(result.stdout.encode()),
        'project': str(project), 'steps': ['project.diff-check', 'service.probe'],
    }
    with args.report.open('x') as output:
        output.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print('real pass', name)


if __name__ == '__main__':
    main()
