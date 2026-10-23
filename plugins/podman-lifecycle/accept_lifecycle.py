#!/usr/bin/env python3
"""Extracted Podman 0.3 lifecycle acceptance with a fake Libpod socket.

The capture test proves a capture-only protected descriptor cannot authorize a
lifecycle mutation. The mutation tests exercise resolve/create/status/start/
stop/remove/health against a fake Unix socket. This accepts no real daemon.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tarfile
import threading
import time

BINARY = 'gateprobes-podman-lifecycle'
PREFIX = 'gateprobes-podman-lifecycle-0.3.0-linux-amd64'
CORE_SHA = '1800325ea2f541dd9b011c03dc93c3dac341e839ece6289ebe778275dcaacf75'
MEMBERS = {BINARY, 'plugin.json', 'README.md', 'Cargo.toml', 'Cargo.lock', 'LICENSE',
           'THIRD_PARTY_NOTICES.txt', 'rust-toolchain.toml', 'build-inputs.json',
           'accept_lifecycle.py', 'core-pin.json', 'protocol-LICENSE'}
IMAGE = 'b' * 64
OBJECT = 'c' * 64
EXEC = 'd' * 64
API = '5.7.0'
DOMAIN = b'gate-runtime/lifecycle-v1/request\0'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def write(path, value):
    path.write_bytes(canonical(value))
    path.chmod(0o600)
    return digest(path.read_bytes())


def protected(path):
    for item in (path, *path.parents):
        st = item.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o022:
            raise ValueError('unprotected acceptance directory')


def extract(archive, expected, work):
    if archive.stat().st_size > 128 * 1024 * 1024 or digest(archive.read_bytes()) != expected:
        raise ValueError('archive digest/size mismatch')
    with tarfile.open(archive, 'r:gz') as stream:
        members = stream.getmembers()
        if len(members) != len(MEMBERS) or {m.name for m in members} != {PREFIX + '/' + n for n in MEMBERS}:
            raise ValueError('archive member mismatch')
        if sum(m.size for m in members) > 128 * 1024 * 1024:
            raise ValueError('archive expanded size')
        for m in members:
            name = m.name.removeprefix(PREFIX + '/')
            if (not m.isfile() or m.pax_headers or m.size <= 0 or m.uid != 0 or m.gid != 0 or m.mtime != 0
                    or m.mode != (0o755 if name == BINARY else 0o644)):
                raise ValueError('archive metadata mismatch')
        work.mkdir(mode=0o700)
        stream.extractall(work, filter='data')
    directory = work / PREFIX
    directory.chmod(0o700)
    return directory


def labels():
    return [
        {'key': 'gatehouse.lifecycle.authority', 'value': 'container-lifecycle/mutate'},
        {'key': 'gatehouse.lifecycle.invocation', 'value': '1' * 32},
        {'key': 'gatehouse.lifecycle.project', 'value': 'project'},
        {'key': 'gatehouse.lifecycle.resource', 'value': 'service:fixture'},
    ]


def engine(socket_path):
    return {'engine': 'podman', 'transport': 'unix-http', 'socket_path': str(socket_path),
            'socket_uid': os.geteuid(), 'principal_uid': os.geteuid(), 'rootless': True,
            'api_version': API, 'server_version': API, 'daemon_id': 'fixture', 'scope': '/fixture/storage'}


def lifecycle_config(socket_path):
    return {'schema': 'gate-runtime/lifecycle-config-v1', 'engine_binding': engine(socket_path)}


def capture_config(socket_path):
    return {'schema': 'gate-runtime/podman-context-v1', 'context': {
        'operator_epoch': 'a' * 32, 'principal_uid': os.geteuid(),
        'observation': {'engine': 'podman', 'api_surface': 'libpod', 'selected_api': '6.1.4',
                        'server_version': '6.1.4', 'hostname': 'fixture', 'rootless': True,
                        'graph_root': '/fixture/storage', 'run_root': '/run/containers/storage',
                        'remote_socket': None, 'socket': {'path': str(socket_path)}}}}


def target():
    return {'container_port': 8080, 'object_id': OBJECT, 'name': 'fixture', 'labels': labels()}


def operation(kind):
    if kind == 'resolve-image':
        return {'kind': 'resolve-image', 'image': 'sha256:' + IMAGE}
    if kind == 'create':
        return {'kind': 'create', 'name': 'fixture', 'image_id': 'sha256:' + IMAGE,
                'labels': labels(), 'environment': [], 'container_port': 8080,
                'command': ['sleep', '60']}
    if kind == 'status':
        return {'kind': 'status', 'target': target()}
    if kind == 'start':
        return {'kind': 'start', 'target': target()}
    if kind == 'stop':
        return {'kind': 'stop', 'target': target(), 'grace_seconds': 10}
    if kind == 'remove':
        return {'kind': 'remove', 'target': target()}
    if kind == 'health':
        return {'kind': 'health-exec', 'target': target(), 'argv': ['/bin/true'], 'timeout_ms': 5000}
    raise ValueError('unknown operation')


def request(kind, config, engine_binding=None):
    binding = {'installation_sha256': 'a' * 64, 'executable_sha256': 'b' * 64,
               'config_sha256': digest(config),
               'engine_binding': engine_binding or json.loads(config)['engine_binding'],
               'project_id': 'project', 'resource_id': 'service:fixture',
               'lease_invocation': '1' * 32, 'invocation': '2' * 32,
               'generation': 2 if kind == 'create' else 1}
    value = {'protocol': 'gate-runtime/lifecycle-v1', 'binding': binding, 'operation': operation(kind)}
    binding['operation_key'] = digest(DOMAIN + canonical(value))
    return canonical(value)


def sealed(bytes_):
    fd = os.memfd_create('podman-accept-input', 0x0001 | 0x0002)
    os.fchmod(fd, 0o600)
    os.write(fd, bytes_)
    os.lseek(fd, 0, 0)
    import fcntl
    fcntl.fcntl(fd, 1033, 0x000F)  # F_ADD_SEALS, all four seals
    return fd


def run_binary(binary, config, expected):
    config_fd, expected_fd = sealed(config), sealed(expected)

    def child():
        os.dup2(config_fd, 3)
        os.set_inheritable(3, True)
        os.dup2(expected_fd, 4)
        os.set_inheritable(4, True)

    try:
        return subprocess.run([str(binary)], input=expected, capture_output=True, timeout=20,
                              cwd='/', env={}, close_fds=False, preexec_fn=child)
    finally:
        os.close(config_fd)
        os.close(expected_fd)


class Counter:
    def __init__(self, path):
        self.connections = 0
        self.stop = threading.Event()
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(str(path))
        path.chmod(0o600)
        self.sock.listen(4)
        self.sock.settimeout(0.05)
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                client, _ = self.sock.accept()
            except socket.timeout:
                continue
            self.connections += 1
            client.close()

    def close(self):
        self.stop.set()
        self.thread.join(3)
        self.sock.close()
        if self.thread.is_alive():
            raise ValueError('counter server did not stop')


class Libpod:
    def __init__(self, path, mode, request_value):
        self.mode, self.request_value = mode, request_value
        self.calls, self.errors = [], []
        self.connections = 0
        self.stop = threading.Event()
        self.state = 'running' if mode in ('stop', 'health') else 'created'
        self.object_id = OBJECT
        self.name = 'fixture'
        self.labels = {e['key']: e['value'] for e in request_value['operation'].get('target', {}).get('labels', labels())}
        self.image = IMAGE
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(str(path))
        path.chmod(0o600)
        self.sock.listen(16)
        self.sock.settimeout(0.05)
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                client, _ = self.sock.accept()
            except socket.timeout:
                continue
            self.connections += 1
            try:
                client.settimeout(3)
                data = b''
                while b'\r\n\r\n' not in data and len(data) < 65536:
                    part = client.recv(4096)
                    if not part:
                        raise ValueError('short request')
                    data += part
                head, body = data.split(b'\r\n\r\n', 1)
                line = head.split(b'\r\n', 1)[0].decode()
                method, route = line.split(' ')[:2]
                self.calls.append([method, route])
                length = 0
                for item in head.split(b'\r\n')[1:]:
                    if item.lower().startswith(b'content-length:'):
                        length = int(item.split(b':', 1)[1])
                while len(body) < length:
                    part = client.recv(4096)
                    if not part:
                        raise ValueError('short body')
                    body += part
                status, response = self.handle(method, route, body[:length])
                client.sendall(b'HTTP/1.1 ' + str(status).encode() + b' OK\r\nContent-Length: ' +
                               str(len(response)).encode() + b'\r\nConnection: close\r\n\r\n' + response)
            except Exception as error:
                self.errors.append(str(error))
            finally:
                client.close()

    def handle(self, method, route, body):
        if route == f'/v{API}/libpod/info':
            return 200, canonical({'host': {'hostname': 'fixture', 'security': {'rootless': True}},
                                   'store': {'graphRoot': '/fixture/storage', 'runRoot': '/run/containers/storage'},
                                   'version': {'APIVersion': API, 'Version': API}})
        if method == 'GET' and route.startswith(f'/v{API}/libpod/images/'):
            return 200, canonical({'Id': IMAGE, 'RepoDigests': []})
        if method == 'POST' and route == f'/v{API}/libpod/containers/create':
            created = json.loads(body)
            self.object_id, self.name = OBJECT, created['name']
            self.labels = created['labels']
            self.image = created['image']
            self.state = 'created'
            return 201, canonical({'Id': self.object_id, 'Warnings': []})
        if method == 'GET' and route == f'/v{API}/libpod/containers/{self.object_id}/json':
            status = {'created': ('created', False), 'running': ('running', True),
                      'exited': ('exited', False)}[self.state]
            ports = {} if self.state != 'running' else {
                '8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '32768'}]}
            return 200, canonical({
                'Id': self.object_id, 'Name': self.name, 'Image': self.image,
                'Config': {'Labels': self.labels},
                'State': {'Status': status[0], 'Running': status[1], 'Paused': False,
                          'Restarting': False, 'Dead': False},
                'HostConfig': {'PortBindings': ports}, 'NetworkSettings': {'Ports': ports}})
        if method == 'POST' and route == f'/v{API}/libpod/containers/{self.object_id}/start':
            self.state = 'running'
            return 204, b''
        if method == 'POST' and route.startswith(f'/v{API}/libpod/containers/{self.object_id}/stop'):
            self.state = 'exited'
            return 204, b''
        if method == 'DELETE' and route.startswith(f'/v{API}/libpod/containers/{self.object_id}'):
            self.state = 'removed'
            return 204, b''
        if method == 'POST' and route == f'/v{API}/libpod/containers/{self.object_id}/exec':
            return 201, canonical({'Id': EXEC})
        if method == 'POST' and route == f'/v{API}/libpod/exec/{EXEC}/start':
            return 200, b'\n'
        if method == 'GET' and route == f'/v{API}/libpod/exec/{EXEC}/json':
            return 200, canonical({
                'ID': EXEC, 'ContainerID': self.object_id, 'CanRemove': True, 'Running': False,
                'ExitCode': 0, 'OpenStdin': False, 'OpenStdout': False, 'OpenStderr': False,
                'ProcessConfig': {'entrypoint': '/bin/true', 'arguments': [], 'privileged': False,
                                  'tty': False, 'user': ''}})
        raise ValueError('unexpected route: ' + method + ' ' + route)

    def close(self):
        self.stop.set()
        self.thread.join(3)
        self.sock.close()
        if self.thread.is_alive() or self.errors:
            raise ValueError('fake Libpod server error: ' + repr(self.errors))


def run_case(case, work, binary):
    root = work / case
    root.mkdir(mode=0o700)
    socket_path = root / 'podman.sock'
    if case == 'capture-config-refuses-mutation':
        config = canonical(capture_config(socket_path))
        expected = request('status', config, engine(socket_path))
        counter = Counter(socket_path)
        try:
            result = run_binary(binary, config, expected)
        finally:
            counter.close()
        if result.returncode != 1 or result.stdout or counter.connections:
            raise ValueError('capture descriptor authorized lifecycle I/O')
        return {'case': case, 'passed': True, 'exit': 1, 'connections': 0, 'routes': [],
                'stdout_sha256': digest(result.stdout), 'mutation_attempts': 0}
    config = canonical(lifecycle_config(socket_path))
    expected = request(case, config)
    fake = Libpod(socket_path, case, json.loads(expected))
    try:
        result = run_binary(binary, config, expected)
    finally:
        fake.close()
    if result.returncode != 0 or result.stderr:
        raise ValueError(f'{case}: process failed: rc={result.returncode} stderr={result.stderr!r} stdout={result.stdout!r}')
    if canonical(json.loads(result.stdout)) != result.stdout:
        raise ValueError(f'{case}: response is not canonical')
    response = json.loads(result.stdout)
    kinds = {'resolve-image': 'image', 'create': 'created', 'status': 'status', 'start': 'started',
             'stop': 'stopped', 'remove': 'removed', 'health': 'health'}
    if response['protocol'] != 'gate-runtime/lifecycle-v1' or response['outcome']['kind'] != kinds[case]:
        raise ValueError(f'{case}: unexpected response')
    mutation = sum(1 for method, _ in fake.calls if method in ('POST', 'DELETE'))
    expected_routes = {
        'resolve-image': [['GET', f'/v{API}/libpod/info'], ['GET', f'/v{API}/libpod/images/sha256%3A{IMAGE}/json'],
                          ['GET', f'/v{API}/libpod/info']],
        'create': [['GET', f'/v{API}/libpod/info'], ['POST', f'/v{API}/libpod/containers/create'],
                   ['GET', f'/v{API}/libpod/containers/{OBJECT}/json'], ['GET', f'/v{API}/libpod/info']],
        'status': [['GET', f'/v{API}/libpod/info'], ['GET', f'/v{API}/libpod/containers/{OBJECT}/json'],
                   ['GET', f'/v{API}/libpod/info']],
        'start': [['GET', f'/v{API}/libpod/info'], ['GET', f'/v{API}/libpod/containers/{OBJECT}/json'],
                  ['POST', f'/v{API}/libpod/containers/{OBJECT}/start'],
                  ['GET', f'/v{API}/libpod/containers/{OBJECT}/json'], ['GET', f'/v{API}/libpod/info']],
        'stop': [['GET', f'/v{API}/libpod/info'], ['GET', f'/v{API}/libpod/containers/{OBJECT}/json'],
                 ['POST', f'/v{API}/libpod/containers/{OBJECT}/stop?t=10'],
                 ['GET', f'/v{API}/libpod/containers/{OBJECT}/json'], ['GET', f'/v{API}/libpod/info']],
        'remove': [['GET', f'/v{API}/libpod/info'], ['GET', f'/v{API}/libpod/containers/{OBJECT}/json'],
                   ['DELETE', f'/v{API}/libpod/containers/{OBJECT}?force=false&volumes=false'],
                   ['GET', f'/v{API}/libpod/info']],
        'health': [['GET', f'/v{API}/libpod/info'], ['GET', f'/v{API}/libpod/containers/{OBJECT}/json'],
                   ['POST', f'/v{API}/libpod/containers/{OBJECT}/exec'],
                   ['POST', f'/v{API}/libpod/exec/{EXEC}/start'],
                   ['GET', f'/v{API}/libpod/exec/{EXEC}/json'],
                   ['GET', f'/v{API}/libpod/containers/{OBJECT}/json'], ['GET', f'/v{API}/libpod/info']],
    }
    if fake.calls != expected_routes[case]:
        raise ValueError(f'{case}: routes differ: {fake.calls!r}')
    return {'case': case, 'passed': True, 'exit': 0, 'connections': fake.connections,
            'routes': fake.calls, 'stdout_sha256': digest(result.stdout), 'mutation_attempts': mutation}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('archive', 'work', 'report'):
        parser.add_argument('--' + key, required=True, type=Path)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--core-sha256', required=True)
    args = parser.parse_args()
    if args.core_sha256 != CORE_SHA:
        raise ValueError('Core digest binding mismatch')
    work = args.work.absolute()
    protected(work.parent)
    if work.exists() or args.report.exists():
        raise ValueError('refuse existing acceptance output')
    installed = extract(args.archive, args.archive_sha256, work)
    if (installed / 'accept_lifecycle.py').read_bytes() != Path(__file__).read_bytes():
        raise ValueError('lifecycle acceptance script/archive mismatch')
    cases = ['capture-config-refuses-mutation', 'resolve-image', 'create', 'status', 'start', 'stop', 'remove', 'health']
    rows = [run_case(case, work, installed / BINARY) for case in cases]
    report = {'schema': 'gateprobes-podman-lifecycle-mutation-acceptance/v1',
              'product': 'podman-lifecycle', 'version': '0.3.0',
              'archive_sha256': args.archive_sha256, 'core_sha256': CORE_SHA,
              'executable_sha256': digest((installed / BINARY).read_bytes()),
              'passed': len(rows), 'cases': rows,
              'socket_connections_total': sum(c['connections'] for c in rows),
              'mutation_attempts': sum(c['mutation_attempts'] for c in rows),
              'files_created': [],
              'limits': 'fake Unix socket only; capture descriptor boundary; no real Podman'}
    with args.report.open('x') as output:
        output.write(json.dumps(report, indent=2) + '\n')
    print('passed', len(rows))


if __name__ == '__main__':
    main()
