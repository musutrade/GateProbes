#!/usr/bin/env python3
"""Read-only real environment acceptance for Podman 5.7 and the fixed image."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import time

API = '5.7.0'
IMAGE_ID = 'b92841763c5c2140a20eeb2a44e94ebb0e80fd51d9d6b5895ea72fa999525d68'
PRODUCT = 'podman-lifecycle'
VERSION = '0.2.0'
BINARY = 'gateprobes-podman-lifecycle'
LIMIT = 16 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def write(path, value, mode=0o400):
    path.write_bytes(canonical(value))
    path.chmod(mode)
    return digest(path.read_bytes())


def http_get(socket_path, route):
    request = (f'GET {route} HTTP/1.1\r\nHost: localhost\r\n'
               'Connection: close\r\n\r\n').encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(15)
        stream.connect(str(socket_path))
        stream.sendall(request)
        data = b''
        while b'\r\n\r\n' not in data and len(data) < 65536:
            part = stream.recv(4096)
            if not part:
                raise ValueError('short HTTP header')
            data += part
        head, body = data.split(b'\r\n\r\n', 1)
        lines = head.split(b'\r\n')
        status = int(lines[0].split(b' ', 2)[1])
        headers = {}
        for line in lines[1:]:
            key, value = line.split(b':', 1)
            headers[key.strip().lower()] = value.strip()

        def read_more():
            nonlocal body
            part = stream.recv(65536)
            if not part:
                raise ValueError('short HTTP body')
            body += part

        chunked = headers.get(b'transfer-encoding', b'').lower() == b'chunked'
        if chunked:
            out = b''
            while True:
                while b'\r\n' not in body:
                    read_more()
                line, body = body.split(b'\r\n', 1)
                size = int(line.split(b';', 1)[0], 16)
                if size == 0:
                    while not body.startswith(b'\r\n'):
                        if len(body) > 65536:
                            raise ValueError('chunk trailer too large')
                        read_more()
                    break
                if size > LIMIT - len(out):
                    raise ValueError('response size rejected')
                while len(body) < size + 2:
                    read_more()
                out += body[:size]
                if body[size:size + 2] != b'\r\n':
                    raise ValueError('invalid chunk framing')
                body = body[size + 2:]
            return status, out
        length = int(headers[b'content-length'])
        if length < 0 or length > LIMIT:
            raise ValueError('response size rejected')
        while len(body) < length:
            read_more()
        if len(body) != length:
            raise ValueError('HTTP body length mismatch')
        return status, body


def normalize_socket_path(value):
    if value.startswith('unix://'):
        value = value[len('unix://'):]
    if (not value.startswith('/') or value == '/' or value.endswith('/')
            or '//' in value or any(c in value for c in '?#%\\\0')
            or any(part in ('', '.', '..') for part in value.split('/')[1:])):
        raise ValueError('remote socket path is not unambiguous local Unix path')
    return value


def protected_dir(path):
    path.mkdir(mode=0o700, parents=True)
    path.chmod(0o700)
    return path


def install(root, binary):
    source = Path(binary).resolve(strict=True)
    if not source.is_file() or source.is_symlink():
        raise ValueError('candidate binary missing')
    installed = protected_dir(root / 'installed')
    executable = installed / BINARY
    executable.write_bytes(source.read_bytes())
    executable.chmod(0o500)
    installation = {'schema': 'gate-runtime/podman-installation-v1',
                    'product': PRODUCT, 'version': VERSION,
                    'protocol': 'gate-runtime/lifecycle-v2',
                    'executable_path': str(executable),
                    'executable_sha256': digest(executable.read_bytes()),
                    'config_schema': 'gate-runtime/podman-context-v1'}
    path = installed / 'installation.json'
    write(path, installation)
    return executable, path, installation


def context(root, socket_path, socket_stat, info):
    for parent in (root / '.harness-gate', root / '.harness-gate/runtime'):
        parent.mkdir(mode=0o700, exist_ok=True)
        parent.chmod(0o700)
    mapped = protected_dir(root / '.harness-gate/runtime/podman-capture-v1')
    remote = normalize_socket_path(info['host']['remoteSocket']['path'])
    local = str(socket_path)
    if remote != local:
        raise ValueError('advertised socket differs from selected socket')
    value = {'schema': 'gate-runtime/podman-context-v1', 'context': {
        'operator_epoch': 'a' * 32,
        'principal_uid': os.geteuid(),
        'observation': {
            'engine': 'podman', 'api_surface': 'libpod',
            'selected_api': API, 'server_version': info['version']['Version'],
            'hostname': info['host']['hostname'], 'rootless': info['host']['security']['rootless'],
            'graph_root': info['store']['graphRoot'], 'run_root': info['store']['runRoot'],
            'remote_socket': {'path': remote, 'exists': True},
            'socket': {'path': local, 'device': socket_stat.st_dev,
                       'inode': socket_stat.st_ino, 'uid': socket_stat.st_uid,
                       'mode': socket_stat.st_mode}}}}
    path = root / 'context.json'
    write(path, value)
    return path, value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', required=True, type=Path)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--socket', required=True, type=Path)
    parser.add_argument('--image-id', default=IMAGE_ID)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    if args.image_id != IMAGE_ID:
        raise SystemExit('only the pinned image ID is accepted')
    socket_path = args.socket.resolve(strict=True)
    st = socket_path.lstat()
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.geteuid():
        raise SystemExit('rootless user Unix socket required')
    info_status, info_bytes = http_get(socket_path, f'/v{API}/libpod/info')
    if info_status != 200:
        raise SystemExit('Podman info unavailable')
    info = json.loads(info_bytes)
    if (info['version']['APIVersion'] != API or info['version']['Version'] != API
            or info['host']['security']['rootless'] is not True):
        raise SystemExit('real Podman does not match the read-only 5.7 profile')
    image_status, image_bytes = http_get(socket_path, f'/v{API}/libpod/images/{IMAGE_ID}/json')
    if image_status != 200:
        raise SystemExit('pinned image unavailable')
    image = json.loads(image_bytes)
    if image.get('Id') != IMAGE_ID:
        raise SystemExit('pinned image ID mismatch')
    core = args.core.resolve(strict=True)
    core_sha = digest(core.read_bytes())
    core_version = subprocess.run([str(core), '--version'], capture_output=True, timeout=15, check=True)
    if core_version.stderr or not core_version.stdout.strip():
        raise SystemExit('Core version unavailable')
    temp = tempfile.mkdtemp(prefix='podman57-real-', dir=Path.home())
    root = Path(temp)
    root.chmod(0o700)
    try:
        subprocess.run([str(core), '--project-root', str(root),
                        'init', '--preset', 'generic'], cwd='/', env={}, check=True,
                       capture_output=True, timeout=15)
        executable, installation_path, installation = install(root, args.binary)
        context_path, context_value = context(root, socket_path, st, info)
        host = {'schema': 'gate-runtime/podman-host-v1',
                'installation_path': str(installation_path),
                'installation_sha256': digest(installation_path.read_bytes()),
                'config_path': str(context_path),
                'config_sha256': digest(context_path.read_bytes())}
        host_path = root / '.harness-gate/runtime/podman-capture-v1/host.json'
        write(host_path, host)
        argv = [str(core), '--project-root', str(root),
                'podman-capture', '--trust-host', '--image-id', IMAGE_ID,
                '--name', 'fixture', '--label', 'owner=fixture', '--timeout-ms', '30000']
        started = time.monotonic()
        result = subprocess.run(argv, cwd='/', env={}, capture_output=True, timeout=15)
        elapsed = time.monotonic() - started
        if result.returncode != 0 or result.stderr:
            raise SystemExit(f'capture failed: exit={result.returncode} stderr={result.stderr[:200]!r}')
        record = json.loads(result.stdout)
        if (record.get('profile') != {'protocol': 'gate-runtime/lifecycle-v2',
                                      'product': PRODUCT, 'version': VERSION,
                                      'engine': 'podman'}
                or record.get('image_id') != IMAGE_ID
                or record.get('asserted_installation_sha256') != digest(installation_path.read_bytes())
                or record.get('config_sha256') != digest(context_path.read_bytes())):
            raise SystemExit('capture record identity mismatch')
        after_status, after_bytes = http_get(socket_path, f'/v{API}/libpod/info')
        if after_status != 200:
            raise SystemExit('post-capture info unavailable')
        after_info = json.loads(after_bytes)
        before_counts = (info['store']['imageStore']['number'], info['store']['containerStore']['number'])
        after_counts = (after_info['store']['imageStore']['number'], after_info['store']['containerStore']['number'])
        if before_counts != after_counts:
            raise SystemExit('read-only capture changed image/container counts')
        report = {
            'product': PRODUCT, 'version': VERSION, 'api': API,
            'image_id': IMAGE_ID, 'rootless': True,
            'socket': {'path': str(socket_path), 'device': st.st_dev,
                       'inode': st.st_ino, 'uid': st.st_uid, 'mode': st.st_mode},
            'core': str(args.core.resolve()), 'core_version': core_version.stdout.decode().strip(), 'core_sha256': core_sha,
            'binary_sha256': digest(executable.read_bytes()),
            'installation_sha256': digest(installation_path.read_bytes()),
            'context_sha256': digest(context_path.read_bytes()),
            'info_sha256': digest(info_bytes), 'image_sha256': digest(image_bytes),
            'record_sha256': digest(result.stdout),
            'elapsed_ms': round(elapsed * 1000),
            'cases': {'real_info': True, 'pinned_image': True, 'capture': True,
                      'image_container_counts_unchanged': True},
            'no_mutation_basis': 'The entrypoint performs only read-only GET info/image requests and Core podman-capture; unchanged image/container counts are corroborating evidence, not a proof of no mutation.',
            'record_sanitized': {'profile': record['profile'], 'image_id': record['image_id'],
                                 'image_sha256': record['image_sha256'], 'plan_sha256': record['plan_sha256'],
                                 'plan_json': record['plan_json'],
                                 'asserted_installation_sha256': record['asserted_installation_sha256'],
                                 'asserted_executable_sha256': record['asserted_executable_sha256'],
                                 'config_sha256': record['config_sha256'],
                                 'operator_epoch': context_value['context']['operator_epoch']},
            'context_sanitized': {'schema': context_value['schema'], 'principal_uid': os.geteuid(),
                                  'selected_api': API, 'server_version': info['version']['Version'],
                                  'rootless': info['host']['security']['rootless'],
                                  'hostname': info['host']['hostname'],
                                  'graph_root': info['store']['graphRoot'], 'run_root': info['store']['runRoot'],
                                  'remote_socket_path': normalize_socket_path(info['host']['remoteSocket']['path']),
                                  'socket': {'path': str(socket_path), 'device': st.st_dev,
                                             'inode': st.st_ino, 'uid': st.st_uid, 'mode': st.st_mode}},
            'image_count': before_counts[0], 'container_count': before_counts[1],
            'limits': 'real rootless Unix socket; read-only GET/capture only; no pull/run/restart'
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': True, 'report': str(args.report)}))
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    main()
