#!/usr/bin/env python3
"""Extracted read-only Podman acceptance. Fake Unix socket only; no importer."""
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
import threading

BINARY = 'gateprobes-podman-lifecycle'
PREFIX = 'gateprobes-podman-lifecycle-0.1.0-linux-amd64'
CORE_SHA = '912a65b17353226becf955de8e74a9c4b7389bf5b273c9a935c6fd68797b18f2'
MEMBERS = {BINARY, 'plugin.json', 'README.md', 'Cargo.toml', 'Cargo.lock', 'LICENSE',
           'THIRD_PARTY_NOTICES.txt', 'rust-toolchain.toml', 'build-inputs.json',
           'accept.py', 'core-pin.json', 'protocol-LICENSE'}
CASES = ['normal', 'no-persist', 'missing-trust', 'missing-mapped-host-with-valid-host-elsewhere',
         'host-digest', 'host-mode', 'host-symlink', 'installation-product-or-version',
         'installation-protocol-or-config-schema', 'config-digest-or-schema',
         'config-principal-or-socket-identity', 'executable-digest', 'executable-mode',
         'docker-or-mixed-profile', 'invalid-image-id', 'duplicate-label', 'incomplete-port-pair',
         'timeout-out-of-range', 'override-host', 'override-output', 'override-socket']
IMAGE = 'b' * 64


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def write(path, value):
    path.write_bytes(canonical(value))
    path.chmod(0o600)
    return digest(path.read_bytes())


def protected(path):
    for item in (path, *path.parents):
        st = item.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o022:
            raise ValueError('unprotected acceptance directory')


def snapshot(root):
    return {str(p.relative_to(root)): (p.lstat().st_mode, p.lstat().st_size,
            os.readlink(p) if p.is_symlink() else digest(p.read_bytes()) if p.is_file() else '')
            for p in root.rglob('*')}


class Fake:
    def __init__(self, path):
        self.calls, self.errors = [], []
        self.connections = 0
        self.stop = threading.Event()
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(str(path))
        path.chmod(0o600)
        self.sock.listen(8)
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
            with client:
                try:
                    client.settimeout(2)
                    data = b''
                    while b'\r\n\r\n' not in data and len(data) < 16384:
                        part = client.recv(4096)
                        if not part:
                            raise ValueError('short request')
                        data += part
                    method, route, version = data.split(b'\r\n', 1)[0].decode().split(' ')
                    self.calls.append([method, route])
                    if method != 'GET' or version != 'HTTP/1.1':
                        raise ValueError('unexpected mutation/request')
                    if route == '/v6.1.4/libpod/info':
                        body = {'host': {'hostname': 'fixture', 'security': {'rootless': os.geteuid() != 0}},
                                'store': {'graphRoot': '/var/lib/containers/storage', 'runRoot': '/run/containers/storage'},
                                'version': {'APIVersion': '6.1.4', 'Version': '6.1.4'}}
                    elif route == '/v6.1.4/libpod/images/' + IMAGE + '/json':
                        body = {'Id': IMAGE, 'Config': {}}
                    else:
                        raise ValueError('unexpected route')
                    body = canonical(body)
                    client.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() +
                                   b'\r\nConnection: close\r\n\r\n' + body)
                except Exception as error:
                    self.errors.append(str(error))

    def close(self):
        self.stop.set()
        self.thread.join(3)
        self.sock.close()
        if self.thread.is_alive() or self.errors:
            raise ValueError('fake server error: ' + repr(self.errors))


def extract(archive, expected, work):
    if archive.stat().st_size > 128 * 1024 * 1024 or digest(archive.read_bytes()) != expected:
        raise ValueError('archive digest/size mismatch')
    with tarfile.open(archive, 'r:gz') as stream:
        members = stream.getmembers()
        if len(members) != 12 or {m.name for m in members} != {PREFIX + '/' + n for n in MEMBERS}:
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


def fixture(root, binary, core):
    root.mkdir(mode=0o700)
    subprocess.run(['git', 'init', '--quiet', str(root)], check=True, capture_output=True)
    subprocess.run([str(core), '--project-root', str(root), 'init', '--preset', 'generic'],
                   check=True, capture_output=True, cwd='/', env={}, timeout=15)
    parent = root / '.harness-gate'
    parent.mkdir(mode=0o700, exist_ok=True)
    parent.chmod(0o700)
    (parent / 'runtime').mkdir(mode=0o700)
    mapped = parent / 'runtime/podman-capture-v1'
    mapped.mkdir(mode=0o700)
    # Each case owns a separate single-link ELF, including executable-mode negatives.
    exe = root / BINARY
    shutil.copyfile(binary, exe)
    exe.chmod(0o500)
    path = root / 'p.sock'
    fake = Fake(path)
    st = path.stat()
    context = {'schema': 'gate-runtime/podman-context-v1', 'context': {
        'operator_epoch': 'a' * 32, 'principal_uid': os.geteuid(), 'observation': {
            'engine': 'podman', 'api_surface': 'libpod', 'selected_api': '6.1.4', 'server_version': '6.1.4',
            'hostname': 'fixture', 'rootless': os.geteuid() != 0, 'graph_root': '/var/lib/containers/storage',
            'run_root': '/run/containers/storage', 'remote_socket': None,
            'socket': {'path': str(path), 'device': st.st_dev, 'inode': st.st_ino, 'uid': st.st_uid, 'mode': st.st_mode}}}}
    installation = {'schema': 'gate-runtime/podman-installation-v1', 'product': 'podman-lifecycle',
                    'version': '0.1.0', 'protocol': 'gate-runtime/lifecycle-v2', 'executable_path': str(exe),
                    'executable_sha256': digest(exe.read_bytes()), 'config_schema': 'gate-runtime/podman-context-v1'}
    config_path, install_path = root / 'context.json', root / 'installation.json'
    host = {'schema': 'gate-runtime/podman-host-v1', 'installation_path': str(install_path),
            'installation_sha256': write(install_path, installation), 'config_path': str(config_path),
            'config_sha256': write(config_path, context)}
    host_path = mapped / 'host.json'
    write(host_path, host)
    return fake, context, installation, host, host_path, exe


def run_case(case, index, work, binary, core):
    root = work / str(index)
    fake, context, installation, host, host_path, exe = fixture(root, binary, core)
    argv = [str(core), '--project-root', str(root), 'podman-capture', '--trust-host', '--image-id', IMAGE,
            '--name', 'fixture', '--label', 'owner=fixture', '--timeout-ms', '3000']
    expected_exit = 0 if index < 2 else 1
    try:
        if case == 'missing-trust':
            argv.remove('--trust-host'); expected_exit = 2
        elif case == 'missing-mapped-host-with-valid-host-elsewhere':
            host_path.rename(root / 'valid-host.json')
        elif case == 'host-digest':
            host['installation_sha256'] = '0' * 64; write(host_path, host)
        elif case == 'host-mode':
            host_path.chmod(0o666)
        elif case == 'host-symlink':
            host_path.rename(root / 'valid-host.json'); host_path.symlink_to(root / 'valid-host.json')
        elif case in ('installation-product-or-version', 'installation-protocol-or-config-schema', 'executable-digest', 'docker-or-mixed-profile'):
            if case == 'installation-product-or-version': installation['version'] = '9.0.0'
            if case == 'installation-protocol-or-config-schema': installation['protocol'] = 'gate-runtime/lifecycle-v1'
            if case == 'executable-digest': installation['executable_sha256'] = '0' * 64
            if case == 'docker-or-mixed-profile': installation['product'] = 'docker-lifecycle'
            host['installation_sha256'] = write(Path(host['installation_path']), installation); write(host_path, host)
        elif case in ('config-digest-or-schema', 'config-principal-or-socket-identity'):
            if case == 'config-digest-or-schema': context['schema'] = 'gate-runtime/wrong'
            else: context['context']['principal_uid'] = os.geteuid() + 1
            host['config_sha256'] = write(Path(host['config_path']), context); write(host_path, host)
        elif case == 'executable-mode': exe.chmod(0o777)
        elif case == 'invalid-image-id': argv[argv.index(IMAGE)] = 'short'
        elif case == 'duplicate-label': argv += ['--label', 'owner=duplicate']
        elif case == 'incomplete-port-pair': argv += ['--container-port', '80']; expected_exit = 2
        elif case == 'timeout-out-of-range': argv[-1] = '0'; expected_exit = 2
        elif case.startswith('override-'):
            argv += ['--' + case.removeprefix('override-'), str(root / 'override')]; expected_exit = 2
        before = snapshot(root)
        result = subprocess.run(argv, cwd='/', env={}, capture_output=True, timeout=10)
        fake.close()
        assert result.returncode == expected_exit, (case, result.returncode, result.stderr.decode(errors='replace'))
        assert snapshot(root) == before, (case, 'unexpected persistence')
        if index < 2:
            assert not result.stderr and result.stdout and not result.stdout.endswith(b'\n')
            record = json.loads(result.stdout)
            assert canonical(record) == result.stdout
            assert record['schema'] == 'gate-runtime/podman-plan-evidence-v1'
            assert record['profile'] == {'protocol': 'gate-runtime/lifecycle-v2', 'product': 'podman-lifecycle', 'version': '0.1.0', 'engine': 'podman'}
            assert record['image_id'] == IMAGE and record['inputs'] == {'name': 'fixture', 'labels': {'owner': 'fixture'}, 'port': None}
            assert record['config_json'].encode() == canonical(context)
            assert canonical(json.loads(record['plan_json'])) == record['plan_json'].encode()
            for name in ('config', 'image', 'plan'):
                assert digest(record[name + '_json'].encode()) == record[name + '_sha256']
            assert record['asserted_installation_sha256'] == host['installation_sha256']
            assert record['asserted_executable_sha256'] == digest(exe.read_bytes())
            assert fake.connections == 3
            assert fake.calls == [['GET', '/v6.1.4/libpod/info'], ['GET', '/v6.1.4/libpod/images/' + IMAGE + '/json'], ['GET', '/v6.1.4/libpod/info']]
        else:
            assert not result.stdout and not fake.calls and fake.connections == 0, (case, 'negative produced output or connection')
            assert canonical(context) not in result.stderr and IMAGE.encode() not in result.stderr
        return {'case': case, 'passed': True, 'exit': result.returncode, 'connections': fake.connections,
                'routes': fake.calls, 'stdout_sha256': digest(result.stdout), 'stderr_empty': not result.stderr,
                'files_created': []}
    finally:
        if fake.thread.is_alive(): fake.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('archive', 'core', 'work', 'report'): parser.add_argument('--' + key, required=True, type=Path)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--core-sha256', required=True)
    args = parser.parse_args()
    core = args.core.resolve(strict=True)
    if args.core_sha256 != CORE_SHA or digest(core.read_bytes()) != CORE_SHA:
        raise ValueError('Core digest mismatch')
    result = subprocess.run([str(core), '--version'], capture_output=True, timeout=15, check=True)
    if result.stdout != b'harness-gate 0.11.0\n' or result.stderr: raise ValueError('Core version mismatch')
    work = args.work.absolute()
    protected(work.parent)
    if work.exists() or args.report.exists(): raise ValueError('refuse existing acceptance output')
    installed = extract(args.archive, args.archive_sha256, work)
    # Run the code from this exact package after validation, never a different checkout script.
    if (installed / 'accept.py').read_bytes() != Path(__file__).read_bytes(): raise ValueError('acceptance script/archive mismatch')
    cases = [run_case(case, i, work, installed / BINARY, core) for i, case in enumerate(CASES)]
    report = {'schema': 'gateprobes-podman-lifecycle-acceptance/v1', 'product': 'podman-lifecycle', 'version': '0.1.0',
              'archive_sha256': args.archive_sha256, 'core_sha256': CORE_SHA, 'core_version': '0.11.0',
              'executable_sha256': digest((installed / BINARY).read_bytes()), 'passed': len(cases), 'cases': cases,
              'socket_connections_total': sum(c['connections'] for c in cases), 'mutation_attempts': 0,
              'files_created': [], 'limits': 'fake Unix socket only; no real Podman; saved evidence is not authority'}
    with args.report.open('x') as output: output.write(json.dumps(report, indent=2) + '\n')
    print('passed', len(cases))


if __name__ == '__main__': main()
