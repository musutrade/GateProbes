import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import sys
sys.dont_write_bytecode = True

PLUGIN = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, PLUGIN / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


config = module('docker_runtime_config', 'config.py')
http = module('docker_runtime_unix_http', 'unix_http.py')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def response(status=200, body=b'', *, reason=b'OK', headers=(), length=True):
    lines = [b'HTTP/1.1 %d %s' % (status, reason)]
    lines.extend(name + b': ' + value for name, value in headers)
    if length:
        lines.append(b'Content-Length: ' + str(len(body)).encode())
    return b'\r\n'.join(lines) + b'\r\n\r\n' + body


class Endpoint:
    def __init__(self, path, chunks=(), *, delay=0, stall=0, on_request=None, on_sent=None):
        self.path = Path(path)
        self.chunks = list(chunks)
        self.delay = delay
        self.stall = stall
        self.on_request = on_request
        self.on_sent = on_sent
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.path))
        self.listener.listen(1)
        os.chmod(self.path, 0o600)
        self.request = None
        self.accepted = False
        self.error = None
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        return self

    def run(self):
        connection = None
        try:
            connection, _ = self.listener.accept()
            self.accepted = True
            connection.settimeout(2)
            data = b''
            while b'\r\n\r\n' not in data:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:
                    break
            self.request = data
            if self.on_request is not None:
                self.on_request()
            for chunk in self.chunks:
                if self.delay:
                    time.sleep(self.delay)
                connection.sendall(chunk)
            if self.stall:
                time.sleep(self.stall)
            if self.on_sent is not None:
                self.on_sent()
        except OSError as error:
            self.error = error
        finally:
            if connection is not None:
                connection.close()

    def join(self, timeout=2):
        if self.thread is not None:
            self.thread.join(timeout)

    def close(self):
        self.listener.close()
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        self.join(0.2)


class UnixHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp(prefix='docker-runtime-http-', dir=Path.home()))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root)

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=self.root))
        os.chmod(self.dir, 0o700)
        self.config_path = self.dir / 'config.json'
        self.endpoints = []
        self.counter = 0

    def tearDown(self):
        for endpoint in self.endpoints:
            endpoint.close()
        shutil.rmtree(self.dir)

    def endpoint(self, sock=None, chunks=(), **kwargs):
        sock = sock or (self.dir / f'engine-{len(self.endpoints)}.sock')
        endpoint = Endpoint(sock, chunks, **kwargs)
        self.endpoints.append(endpoint)
        return endpoint

    def data(self, sock, **overrides):
        value = {
            'schema': 'gate-runtime-engine-config/v2',
            'engine': 'docker',
            'transport': 'unix-http',
            'socket_path': str(sock),
            'socket_uid': os.geteuid(),
            'principal_uid': os.geteuid(),
            'rootless': False,
            'api_version': '1.47',
            'server_version': '27.0.1',
            'daemon_id': 'daemon-1',
            'scope': 'scope-1',
        }
        value.update(overrides)
        return value

    def write_config(self, data=None, *, name='config.json', mode=0o600):
        self.counter += 1
        path = self.dir / f'{name}-{self.counter}'
        payload = json.dumps(data or self.data(self.endpoints[-1].path)).encode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, mode)
        return path, payload

    def loaded(self, endpoint, *, name='loaded', **overrides):
        path, payload = self.write_config(self.data(endpoint.path, **overrides), name=name)
        return config.load(str(path), digest(payload)), path, payload

    def assert_no_connect(self, endpoint):
        endpoint.listener.settimeout(0.1)
        with self.assertRaises(socket.timeout):
            connection, _ = endpoint.listener.accept()
            connection.close()
            self.fail('unexpected transport connection')

    def assert_transport_error(self, call, sentinel=None):
        with self.assertRaises(http.TransportError) as caught:
            call()
        if sentinel is not None:
            self.assertNotIn(sentinel, str(caught.exception))
        return caught.exception

    def test_exact_get_and_environment_is_ignored(self):
        sock = self.dir / 'exact.sock'
        endpoint = self.endpoint(sock, [response(200, b'{"ok":true}')]).start()
        cfg, _, _ = self.loaded(endpoint)
        with patch.dict(os.environ, {
            'HTTP_PROXY': 'http://127.0.0.1:1', 'http_proxy': 'http://127.0.0.1:1',
            'HTTPS_PROXY': 'http://127.0.0.1:1', 'DOCKER_HOST': 'tcp://127.0.0.1:1',
            'NO_PROXY': '*', 'GATE_RUNTIME_SOCKET': '/tmp/other',
        }, clear=False):
            reply = http.get(cfg, '/version', timeout=1)
        endpoint.join()
        expected = (b'GET /version HTTP/1.1\r\nHost: localhost\r\n'
                    b'Accept: application/json\r\nAccept-Encoding: identity\r\n'
                    b'Connection: close\r\n\r\n')
        self.assertEqual(endpoint.request, expected)
        self.assertEqual((reply.status, reply.body), (200, b'{"ok":true}'))

    def test_valid_statuses_and_fragmented_body(self):
        for status in (200, 201, 204, 299, 301, 404, 418, 500, 599):
            with self.subTest(status=status):
                body = b'' if status == 204 else b'{"status":%d}' % status
                raw = response(status, body)
                endpoint = self.endpoint(chunks=[raw[:1], raw[1:3], raw[3:]]).start()
                cfg, _, _ = self.loaded(endpoint, name=f'status-{status}')
                reply = http.get(cfg, '/version', timeout=1)
                endpoint.join()
                self.assertEqual(reply.status, status)
                self.assertEqual(reply.body, body)

    def test_info_route_is_exact(self):
        endpoint = self.endpoint(chunks=[response(200, b'ok')]).start()
        cfg, _, _ = self.loaded(endpoint)
        reply = http.get(cfg, '/v1.47/info', timeout=1)
        endpoint.join()
        self.assertEqual(reply.status, 200)
        self.assertIn(b'GET /v1.47/info HTTP/1.1\r\n', endpoint.request)

    def test_inspect_route_is_exact(self):
        object_id = 'a' * 64
        endpoint = self.endpoint(chunks=[response(200, b'ok')]).start()
        cfg, _, _ = self.loaded(endpoint)
        reply = http.get(cfg, f'/v1.47/containers/{object_id}/json', timeout=1)
        endpoint.join()
        self.assertEqual(reply.status, 200)
        self.assertIn(f'/v1.47/containers/{object_id}/json'.encode(), endpoint.request)

    def test_forbidden_routes_and_injection_never_connect(self):
        endpoint = self.endpoint()
        cfg, _, _ = self.loaded(endpoint)
        object_id = 'a' * 64
        for path in ('/v1.47/info/', f'/v1.47/containers/{object_id}',
                     f'/v1.47/containers/{object_id}/json?x=1',
                     f'/v1.47/containers/{object_id[:-1]}/json',
                     f'/v1.47/containers/{object_id.upper()}/json', '/version?x=1',
                     '/version HTTP/1.1', '//version', '/v1.47/containers/../json'):
            with self.subTest(path=path):
                self.assert_transport_error(lambda path=path: http.get(cfg, path, timeout=0.2))
        self.assert_no_connect(endpoint)

    def test_invalid_limits_and_path_types_never_connect(self):
        endpoint = self.endpoint()
        cfg, _, _ = self.loaded(endpoint)
        for timeout in (0, -1, 30.1, True, '1', None):
            with self.subTest(timeout=timeout):
                self.assert_transport_error(lambda timeout=timeout: http.get(cfg, '/version', timeout=timeout))
        for size in (0, -1, 1048577, True, 1.0, '1', None):
            with self.subTest(size=size):
                self.assert_transport_error(lambda size=size: http.get(cfg, '/version', max_body=size))
        for path in (None, b'/version', 1):
            with self.subTest(path=path):
                self.assert_transport_error(lambda path=path: http.get(cfg, path))
        self.assert_no_connect(endpoint)

    def test_invalid_config_and_pin_before_connect_never_connects(self):
        for raw in (b'{}', b'not-json', b'{"schema": 1}'):
            endpoint = self.endpoint()
            cfg, path, _ = self.loaded(endpoint)
            path.write_bytes(raw)
            os.chmod(path, 0o600)
            self.assert_transport_error(lambda: http.get(cfg, '/version', timeout=0.2))
            self.assert_no_connect(endpoint)

    def test_static_transport_boundary(self):
        import ast
        source = (PLUGIN / 'unix_http.py').read_text()
        tree = ast.parse(source)
        imports = set()
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split('.')[0])
            elif isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
        self.assertLessEqual(imports, {'dataclasses', 're', 'socket', 'time'})
        for forbidden in ('subprocess', 'requests', 'urllib', 'http', 'cli', 'environ', 'getenv', 'connect_ex'):
            self.assertNotIn(forbidden, imports | names)
        self.assertNotIn('http.client', source)
        self.assertNotIn('DOCKER_HOST', source)

    def test_config_change_before_connect_never_connects(self):
        endpoint = self.endpoint()
        cfg, path, _ = self.loaded(endpoint)
        path.write_bytes(json.dumps(self.data(endpoint.path, scope='changed')).encode())
        os.chmod(path, 0o600)
        self.assert_transport_error(lambda: http.get(cfg, '/version', timeout=0.2))
        self.assert_no_connect(endpoint)

    def test_config_replacement_after_response_detected(self):
        endpoint = self.endpoint(chunks=[response(200, b'ok')]).start()
        cfg, path, _ = self.loaded(endpoint)
        self.assertEqual(http.get(cfg, '/version', timeout=1).body, b'ok')
        endpoint.join()
        path.write_bytes(json.dumps(self.data(endpoint.path, scope='changed')).encode())
        os.chmod(path, 0o600)
        with self.assertRaises(config.InvalidConfig):
            cfg.revalidate()
        self.assert_transport_error(lambda: http.get(cfg, '/version', timeout=0.2))
        self.assert_no_connect(endpoint)

    def test_socket_replacement_after_response_detected(self):
        endpoint = self.endpoint(chunks=[response(200, b'ok')]).start()
        cfg, _, _ = self.loaded(endpoint)
        self.assertEqual(http.get(cfg, '/version', timeout=1).body, b'ok')
        endpoint.join()
        socket_path = endpoint.path
        original = socket_path.stat()
        # Keep the original inode alive while creating its replacement.
        replacement = self.endpoint()
        distinct = replacement.path.stat()
        self.assertNotEqual((original.st_dev, original.st_ino),
                            (distinct.st_dev, distinct.st_ino))
        self.assertEqual(original.st_mode, distinct.st_mode)
        os.replace(replacement.path, socket_path)
        replacement.path = socket_path
        installed = socket_path.stat()
        self.assertEqual((installed.st_dev, installed.st_ino),
                         (distinct.st_dev, distinct.st_ino))
        with self.assertRaises(config.InvalidConfig):
            cfg.revalidate()
        self.assert_transport_error(lambda: http.get(cfg, '/version', timeout=0.2))
        self.assert_no_connect(replacement)

    def test_missing_duplicate_and_conflicting_framing(self):
        cases = [
            b'HTTP/1.1 200 OK\r\n\r\n',
            b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n',
            b'HTTP/1.1 200 OK\r\ncontent-length: 0\r\nContent-Length: 0\r\n\r\n',
            b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n',
            b'HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n',
            b'HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\n',
            b'HTTP/1.1 200 OK\r\nContent-Length: 01\r\n\r\n',
            b'HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n',
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n',
            b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n',
            b'HTTP/1.1 600 Bad\r\nContent-Length: 0\r\n\r\n',
            b'HTTP/2 200 OK\r\nContent-Length: 0\r\n\r\n',
            b'HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n',
            b'HTTP/1.1 200 OK\r\nBad\r\n\r\n',
            b'HTTP/1.1 200 OK\r\nX: \x01\r\nContent-Length: 0\r\n\r\n',
            b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nab',
        ]
        for raw in cases:
            with self.subTest(raw=raw[:40]):
                endpoint = self.endpoint(chunks=[raw]).start()
                cfg, _, _ = self.loaded(endpoint, name='framing')
                self.assert_transport_error(lambda: http.get(cfg, '/version', timeout=0.5), 'nonexistent-secret')
                endpoint.close()

    def test_truncation_and_header_exhaustion(self):
        cases = [
            response(200, b'', length=True)[:-4],
            b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc',
            b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n' + b'x',
            b'X' * 17000,
        ]
        for raw in cases:
            with self.subTest(size=len(raw)):
                endpoint = self.endpoint(chunks=[raw]).start()
                cfg, _, _ = self.loaded(endpoint, name='trunc')
                self.assert_transport_error(lambda: http.get(cfg, '/version', timeout=0.5))
                endpoint.close()

    def test_header_and_body_size_boundaries(self):
        endpoint = self.endpoint(chunks=[response(200, b'')]).start()
        cfg, _, _ = self.loaded(endpoint)
        self.assertEqual(http.get(cfg, '/version', timeout=1).status, 200)
        endpoint.join()

        fields = [(b'X-%d' % i, b'v') for i in range(63)]
        endpoint = self.endpoint(chunks=[response(200, b'', headers=fields)]).start()
        cfg, _, _ = self.loaded(endpoint, name='fields64')
        self.assertEqual(http.get(cfg, '/version', timeout=1).status, 200)
        endpoint.join()

        fields = [(b'X-%d' % i, b'v') for i in range(64)]
        endpoint = self.endpoint(chunks=[response(200, b'', headers=fields)]).start()
        cfg, _, _ = self.loaded(endpoint, name='fields65')
        self.assert_transport_error(lambda: http.get(cfg, '/version', timeout=0.5))
        endpoint.close()

        prefix, suffix = b'HTTP/1.1 200 OK\r\nX: ', b'\r\nContent-Length: 0\r\n\r\n'
        exact = prefix + b'a' * (16384 - len(prefix) - len(suffix)) + suffix
        self.assertEqual(len(exact), 16384)
        endpoint = self.endpoint(chunks=[exact]).start()
        cfg, _, _ = self.loaded(endpoint, name='headers-exact')
        self.assertEqual(http.get(cfg, '/version', timeout=1).status, 200)
        endpoint.join()

        over = prefix + b'a' * (16385 - len(prefix) - len(suffix)) + suffix
        endpoint = self.endpoint(chunks=[over]).start()
        cfg, _, _ = self.loaded(endpoint, name='headers-over')
        self.assert_transport_error(lambda: http.get(cfg, '/version', timeout=0.5))
        endpoint.close()

        body = b'x' * 1048576
        endpoint = self.endpoint(chunks=[response(200, body)]).start()
        cfg, _, _ = self.loaded(endpoint, name='body-exact')
        self.assertEqual(http.get(cfg, '/version', timeout=2).body, body)
        endpoint.join()

        endpoint = self.endpoint(chunks=[response(200, b'', headers=[(b'Content-Length', b'1048577')], length=False)]).start()
        cfg, _, _ = self.loaded(endpoint, name='body-over')
        self.assert_transport_error(lambda: http.get(cfg, '/version', timeout=0.5))
        endpoint.close()

    def test_timeout_trickle_and_cancellation(self):
        endpoint = self.endpoint(chunks=[], stall=1).start()
        cfg, _, _ = self.loaded(endpoint)
        started = time.monotonic()
        self.assert_transport_error(lambda: http.get(cfg, '/version', timeout=0.15))
        self.assertLess(time.monotonic() - started, 2)
        endpoint.close()

        raw = response(200, b'ok')
        endpoint = self.endpoint(chunks=[bytes([byte]) for byte in raw], delay=0.06).start()
        cfg, _, _ = self.loaded(endpoint, name='trickle')
        self.assert_transport_error(lambda: http.get(cfg, '/version', timeout=0.2))
        endpoint.close()

        endpoint = self.endpoint()
        cfg, _, _ = self.loaded(endpoint, name='cancel-before')
        self.assert_transport_error(lambda: http.get(cfg, '/version', cancelled=lambda: True))
        self.assert_no_connect(endpoint)

        cancel = threading.Event()
        endpoint = self.endpoint(
            chunks=[response(200, b'ok')], on_request=cancel.set).start()
        cfg, _, _ = self.loaded(endpoint, name='cancel-during')
        self.assert_transport_error(
            lambda: http.get(cfg, '/version', timeout=1, cancelled=cancel.is_set))
        endpoint.close()

        sent = threading.Event()
        endpoint = self.endpoint(
            chunks=[response(200, b'ok')], on_sent=sent.set).start()
        cfg, _, _ = self.loaded(endpoint, name='cancel-after')
        with self.assertRaises((http.TransportError, config.InvalidConfig)):
            http.get(cfg, '/version', timeout=1, cancelled=lambda: sent.is_set())
        endpoint.close()

    def test_errors_do_not_echo_body_or_request(self):
        sentinel = b'response-secret-42'
        raw = (b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n' + sentinel)
        endpoint = self.endpoint(chunks=[raw]).start()
        cfg, _, _ = self.loaded(endpoint)
        error = self.assert_transport_error(lambda: http.get(cfg, '/version', timeout=0.5), sentinel.decode())
        self.assertNotIn(str(endpoint.path), str(error))
        endpoint.close()

    def test_raw_404_is_not_absence(self):
        endpoint = self.endpoint(chunks=[response(404, b'not found')]).start()
        cfg, _, _ = self.loaded(endpoint)
        reply = http.get(cfg, '/version', timeout=1)
        endpoint.join()
        self.assertEqual((reply.status, reply.body), (404, b'not found'))
        self.assertFalse(hasattr(reply, 'absent'))
