#!/usr/bin/env python3
"""Installed lifecycle acceptance using the pinned released Core and fake Unix HTTP."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import threading

CORE_SHA = 'fa7a3a355d136267765c017f48b59acf0a6e1bcc581cc57cac67107beb8c6ab8'
OBJECT = 'a' * 64
EXEC = 'b' * 64
IMAGE = 'sha256:' + 'e' * 64
NEGATIVES = ('host-digest', 'host-symlink', 'host-mode', 'installation-product',
             'installation-version', 'installation-protocol', 'config-schema',
             'config-principal', 'config-engine', 'executable-digest',
             'executable-mode', 'descriptor-symlink')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def write_json(path, value):
    path.write_bytes(canonical(value))
    path.chmod(0o400)
    return digest(path.read_bytes())


class Fake:
    def __init__(self, path, health):
        self.health, self.calls, self.errors = health, [], []
        self.state, self.name, self.labels = None, None, None
        self.stopping = threading.Event()
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(str(path))
        self.sock.listen(8)
        self.sock.settimeout(0.05)
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def route(self, method, route, body):
        self.calls.append([method, route])
        if (method, route) == ('GET', '/version'):
            return 200, {'Version': '27.0.1', 'MinAPIVersion': '1.40', 'ApiVersion': '1.47'}
        if (method, route) == ('GET', '/v1.47/info'):
            return 200, {'ID': 'lifecycle-acceptance-daemon', 'SecurityOptions': []}
        if (method, route) == ('GET', '/v1.47/images/example%3Alatest/json'):
            return 200, {'Id': IMAGE, 'RepoDigests': []}
        if method == 'POST' and route.startswith('/v1.47/containers/create?name='):
            assert self.state is None, 'Create replay'
            self.name = route.split('=', 1)[1]
            assert re.fullmatch(r'gatehouse-[a-f0-9]{32}', self.name)
            self.labels = body['Labels']
            assert self.labels and all(isinstance(v, str) for v in self.labels.values())
            assert body == {'Image': IMAGE, 'Labels': self.labels, 'Env': [],
                'ExposedPorts': {'1234/tcp': {}}, 'AttachStdin': False, 'AttachStdout': False,
                'AttachStderr': False, 'OpenStdin': False, 'StdinOnce': False, 'Tty': False,
                'HostConfig': {'AutoRemove': False, 'Privileged': False, 'PublishAllPorts': False,
                    'NetworkMode': 'bridge', 'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                    'PortBindings': {'1234/tcp': [{'HostIp': '127.0.0.1', 'HostPort': ''}]}}}
            self.state = 'created'
            return 201, {'Id': OBJECT, 'Warnings': []}
        target = '/v1.47/containers/' + OBJECT
        if (method, route) == ('GET', target + '/json'):
            if self.state == 'absent':
                return 404, {'message': 'No such container: ' + OBJECT}
            assert self.state in ('created', 'running', 'exited')
            return 200, {'Id': OBJECT, 'Name': '/' + self.name, 'Image': IMAGE,
                'Config': {'Labels': self.labels}, 'State': {'Status': self.state},
                'NetworkSettings': {'Ports': {'1234/tcp': None if self.state == 'created' else
                    [{'HostIp': '127.0.0.1', 'HostPort': '49152'}]}}}
        if (method, route) == ('POST', target + '/start'):
            assert self.state == 'created'
            self.state = 'running'
            return 204, None
        if (method, route) == ('POST', target + '/exec'):
            assert self.state == 'running'
            assert body == {'AttachStdin': False, 'AttachStdout': False, 'AttachStderr': False,
                            'Tty': False, 'Privileged': False, 'Cmd': ['check']}
            return 201, {'Id': EXEC}
        if (method, route) == ('POST', '/v1.47/exec/' + EXEC + '/start'):
            assert body == {'Detach': True, 'Tty': False}
            return 200, None
        if (method, route) == ('GET', '/v1.47/exec/' + EXEC + '/json'):
            return 200, {'ID': EXEC, 'ContainerID': OBJECT, 'Running': False, 'ExitCode': self.health}
        if (method, route) == ('POST', target + '/stop?t=5'):
            assert self.state == 'running'
            self.state = 'exited'
            return 204, None
        if (method, route) == ('DELETE', target + '?force=false&v=false'):
            assert self.state == 'exited'
            self.state = 'absent'
            return 204, None
        raise AssertionError(('unexpected exact-ID route', method, route))

    def serve(self):
        while not self.stopping.is_set():
            try:
                connection, _ = self.sock.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(3)
                try:
                    raw = b''
                    while b'\r\n\r\n' not in raw:
                        chunk = connection.recv(4096)
                        assert chunk and len(raw) < 65536
                        raw += chunk
                    header, data = raw.split(b'\r\n\r\n', 1)
                    method, route, _ = header.split(b'\r\n')[0].decode().split(' ')
                    headers = dict(line.decode().split(': ', 1) for line in header.split(b'\r\n')[1:])
                    size = int(next((v for k, v in headers.items() if k.lower() == 'content-length'), '0'))
                    assert 0 <= size <= 65536
                    while len(data) < size:
                        chunk = connection.recv(4096)
                        assert chunk
                        data += chunk
                    assert len(data) == size
                    status, value = self.route(method, route, json.loads(data) if data else None)
                    response = b'' if value is None else canonical(value)
                    connection.sendall(f'HTTP/1.1 {status} OK\r\nContent-Length: {len(response)}\r\nConnection: close\r\n\r\n'.encode() + response)
                except Exception as error:
                    self.errors.append(repr(error))

    def close(self):
        self.stopping.set()
        self.thread.join(5)
        self.sock.close()
        assert not self.thread.is_alive()
        assert not self.errors, self.errors


def descriptors(root, adapter, case):
    executable = root / 'adapter'
    shutil.copyfile(adapter, executable)
    executable.chmod(0o500)
    installation = {'schema': 'gate-runtime/lifecycle-installation-v1', 'product': 'docker-lifecycle',
        'version': '0.1.0', 'protocol': 'gate-runtime/lifecycle-v1', 'executable_path': str(executable),
        'executable_sha256': digest(executable.read_bytes()), 'config_schema': 'gate-runtime/lifecycle-config-v1'}
    config = {'schema': 'gate-runtime/lifecycle-config-v1', 'engine_binding': {'engine': 'docker',
        'transport': 'unix-http', 'socket_path': str(root / 'fake.sock'), 'socket_uid': os.geteuid(),
        'principal_uid': os.geteuid(), 'rootless': False, 'api_version': '1.47', 'server_version': '27.0.1',
        'daemon_id': 'lifecycle-acceptance-daemon', 'scope': 'fake-only'}}
    if case.startswith('installation-'):
        field = case.removeprefix('installation-')
        installation[field] = {'product': 'docker-readiness', 'version': '0.1.1', 'protocol': 'gate-runtime/lifecycle-v2'}[field]
    if case == 'config-schema': config['schema'] = 'gate-runtime/lifecycle-config-v2'
    if case == 'config-principal': config['engine_binding']['principal_uid'] += 1
    if case == 'config-engine': config['engine_binding']['engine'] = 'podman'
    host = {'schema': 'gate-runtime/lifecycle-host-v1', 'installation_path': str(root / 'installation.json'),
        'installation_sha256': write_json(root / 'installation.json', installation),
        'config_path': str(root / 'config.json'), 'config_sha256': write_json(root / 'config.json', config)}
    if case == 'host-digest': host['installation_sha256'] = '0' * 64
    path = root / 'host.json'
    write_json(path, host)
    if case == 'host-mode': path.chmod(0o644)
    if case == 'executable-digest':
        executable.chmod(0o700)
        executable.write_bytes(executable.read_bytes() + b'tampered')
        executable.chmod(0o500)
    if case == 'executable-mode': executable.chmod(0o644)
    if case in ('descriptor-symlink', 'host-symlink'):
        link = root / ('config.json' if case == 'descriptor-symlink' else 'host.json')
        target = root / 'original.json'
        link.rename(target)
        link.symlink_to(target)
    return path


def run_case(base, core, adapter, case):
    root = base / case
    root.mkdir(mode=0o700)
    host = descriptors(root, adapter, case)
    project = root / 'project'
    project.mkdir(mode=0o700)
    home = root / 'home'
    home.mkdir(mode=0o700)
    env = {'HOME': str(home), 'TMPDIR': str(root), 'PATH': os.environ.get('PATH', ''),
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'LANG': 'C.UTF-8'}
    fakebin = root / 'fakebin'
    fakebin.mkdir(mode=0o700)
    marker = root / 'legacy-called'
    for name in ('docker', 'podman'):
        script = fakebin / name
        script.write_text(f'#!/bin/sh\nprintf called >> "{marker}"\nexit 77\n')
        script.chmod(0o700)
    env['PATH'] = str(fakebin) + ':' + env['PATH']
    def run(args):
        result = subprocess.run([str(core), '--project-root', str(project), *args], env=env,
                                capture_output=True, text=True, timeout=45)
        return {'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
    subprocess.run(['git', 'init', '-q', str(project)], env=env, check=True)
    initialized = run(['init', '--preset', 'generic'])
    assert initialized['exit'] == 0, initialized
    step_marker = root / 'step-ran'
    script = root / 'step.sh'
    script.write_text('test "$FIXTURE_URL" = "tcp://127.0.0.1:49152" && printf ran > "$1"\n')
    flow = project / 'flow.toml' 
    flow.write_text('''version = 2
[project]
name = "lifecycle-acceptance"
default_profile = "full"
hook_profile = "full"
[paths]
reports = ".harness-gate/reports"
audit_config = ".harness-gate/audit.toml"
[policy]
required_steps = ["fixture.smoke"]
[scope]
unmatched = "all"
[[scope.rules]]
patterns = ["**"]
components = ["app"]
[services.fixture]
kind = "docker"
runtime = "docker"
image = "example:latest"
lifecycle_host = HOST
inject_env = "FIXTURE_URL"
startup_timeout_secs = 20
container_port = 1234
environment = {}
healthcheck = ["check"]
connection = "tcp://127.0.0.1:{host_port}"
[[steps]]
id = "fixture.smoke"
label = "fixture smoke"
component = "app"
profiles = ["full"]
program = "sh"
args = ARGS
cwd = "{root}"
log = "fixture.log"
timeout_secs = 5
services = ["fixture"]
input = "snapshot"
'''.replace('HOST', json.dumps(str(host))).replace('ARGS', json.dumps([str(script), str(step_marker)])))
    fake = Fake(root / 'fake.sock', 7 if case == 'health-failure' else 0)
    results = []
    try:
        first = run(['--config', str(flow), 'verify', '--profile', 'full', '--components', 'app'])
        results.append(first)
        slots = list(project.glob('.harness-gate/lifecycle-services/**/service.json'))
        if case in NEGATIVES:
            assert first['exit'] == 1 and not step_marker.exists(), first
            assert not slots and not fake.calls, (slots, fake.calls, first)
        else:
            assert len(slots) == 1, (slots, first)
            slot = json.loads(slots[0].read_bytes())
            if case == 'health-failure':
                assert first['exit'] == 1 and not slot['released'] and not step_marker.exists(), first
                cleanup = ['--config', str(flow), 'lifecycle-cleanup', '--service', 'fixture',
                    '--fence', str(slot['fence']), '--lease-invocation', slot['resolve']['binding']['lease_invocation']]
                result = run(cleanup)
                results.append(result)
                assert result['exit'] == 0 and 'Lifecycle service released' in result['stdout'], result
                assert list(slots[0].parent.glob('operator-*.proof.json'))
                before = list(fake.calls)
                replay = run(cleanup)
                results.append(replay)
                assert replay['exit'] == 1 and fake.calls == before, replay
            else:
                assert first['exit'] == 0 and step_marker.read_text() == 'ran', first
            assert json.loads(slots[0].read_bytes())['released'] and fake.state == 'absent'
            assert not list(slots[0].parent.glob('**/active'))
            tombstones = list(slots[0].parent.glob('journal-*/tombstone.json'))
            assert len(tombstones) == 1
            tombstone = tombstones[0]
            assert tombstone.read_bytes() == (tombstone.parent / 'lease.json').read_bytes()
            released = json.loads(tombstone.read_bytes())
            assert released['state'] == {'phase': 'verified-absent', 'object_id': OBJECT}
            assert released['pending'] is None
            assert released['absence']['reason'] == 'post-remove-absence'
            assert released['absence']['response']['outcome']['evidence']['http_status'] == 404
            # Resolve/Create/Status/Start/Status/Health and five cleanup operations.
            assert sum(route == '/version' for _, route in fake.calls) == 22
            assert sum(route == '/v1.47/info' for _, route in fake.calls) == 22

            assert sum(route.startswith('/v1.47/containers/create?') for _, route in fake.calls) == 1
            assert sum(route == '/v1.47/containers/' + OBJECT + '/exec' for _, route in fake.calls) == 1
        assert not marker.exists(), 'legacy CLI fallback'
    finally:
        fake.close()
    return {'case': case, 'commands': results, 'requests': fake.calls, 'passed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', required=True, type=Path)
    parser.add_argument('--core-sha256', required=True)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--version', choices=['0.1.0'], required=True)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    core, adapter = args.core.resolve(strict=True), args.binary.resolve(strict=True)
    assert args.core_sha256 == CORE_SHA == digest(core.read_bytes()), 'exact released Core digest required'
    version = subprocess.run([str(core), '--version'], capture_output=True, text=True, check=True)
    assert version.stdout.strip() == 'harness-gate 0.10.0' and not version.stderr
    parent = Path.home() / '.cache'
    parent.mkdir(exist_ok=True)
    for path in [parent, *parent.parents]:
        st = path.lstat()
        assert not path.is_symlink() and path.is_dir() and st.st_uid in (0, os.geteuid()) and not st.st_mode & 0o022
    root = Path(tempfile.mkdtemp(prefix='lc84-', dir=parent))
    report = {'root': str(root), 'core_sha256': CORE_SHA, 'adapter_sha256': digest(adapter.read_bytes()),
              'limits': 'fake Unix socket only; rootless/restart/daemon authentication/OS containment unproven', 'cases': []}
    try:
        for case in ('normal', 'health-failure', *NEGATIVES):
            report['cases'].append(run_case(root, core, adapter, case))
        report['passed'] = len(report['cases'])
    finally:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'root': str(root)}))


if __name__ == '__main__':
    main()
