import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.dont_write_bytecode = True
PLUGIN = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, PLUGIN / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


config = module('runtime_config', 'config.py')
http = module('unix_http', 'unix_http.py')
sys.modules['unix_http'] = http
observation = module('runtime_observation', 'observation.py')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def reply(body, status=200):
    return b'HTTP/1.1 %d OK\r\nContent-Length: %d\r\n\r\n' % (status, len(body)) + body


def json_reply(value, status=200):
    return reply(json.dumps(value).encode(), status)


class Router:
    def __init__(self, path, responses, *, delay=0, on_request=None):
        self.path = Path(path)
        self.responses = responses
        self.delay = delay
        self.on_request = on_request
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.path))
        self.listener.listen(8)
        os.chmod(self.path, 0o600)
        self.requests = []
        self.errors = []
        self.stop = threading.Event()
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        return self

    def run(self):
        while not self.stop.is_set():
            self.listener.settimeout(0.2)
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                connection.settimeout(2)
                data = b''
                while b'\r\n\r\n' not in data:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                line = data.split(b'\r\n', 1)[0].decode('ascii', 'replace')
                parts = line.split(' ')
                path = parts[1] if len(parts) >= 2 else ''
                self.requests.append(path)
                if self.on_request is not None:
                    self.on_request(path)
                raw = self.responses.get(path, reply(b'{"error":"missing"}', 500))
                if isinstance(raw, list):
                    raw = raw.pop(0) if raw else reply(b'{}', 500)
                if self.delay:
                    time.sleep(self.delay)
                connection.sendall(raw)
            except OSError as error:
                self.errors.append(error)
            finally:
                connection.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        if self.thread is not None:
            self.thread.join(0.3)


class ObservationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp(prefix='docker-runtime-observation-', dir=Path.home()))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root)

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=self.root))
        os.chmod(self.dir, 0o700)
        self.socket_path = self.dir / 'engine.sock'
        self.object_id = 'a' * 64
        self.config_path = self.dir / 'config.json'
        self.routers = []

    def tearDown(self):
        for router in self.routers:
            router.close()
        shutil.rmtree(self.dir)

    def router(self, responses, **kwargs):
        value = Router(self.socket_path, responses, **kwargs)
        self.routers.append(value)
        return value

    def data(self, api_version='1.47'):
        return {
            'schema': 'gate-runtime-engine-config/v2',
            'engine': 'docker',
            'transport': 'unix-http',
            'socket_path': str(self.socket_path),
            'socket_uid': os.geteuid(),
            'principal_uid': os.geteuid(),
            'rootless': False,
            'api_version': api_version,
            'server_version': '27.0.1',
            'daemon_id': 'daemon-1',
            'scope': 'scope-1',
        }

    def load(self, api_version='1.47'):
        payload = json.dumps(self.data(api_version)).encode()
        self.config_path.write_bytes(payload)
        os.chmod(self.config_path, 0o600)
        return config.load(str(self.config_path), digest(payload))

    def version(self, *, Version='27.0.1', ApiVersion='1.48', MinAPIVersion='1.40', extra=None):
        value = {'Version': Version, 'ApiVersion': ApiVersion, 'MinAPIVersion': MinAPIVersion}
        value.update(extra or {})
        return json_reply(value)

    def info(self, *, ID='daemon-1', extra=None):
        value = {'ID': ID}
        value.update(extra or {})
        return json_reply(value)

    def inspect(self, *, ID='default', labels=None, config_value='default', extra=None):
        value = {'Id': self.object_id} if ID == 'default' else ({'Id': ID} if ID is not None else {})
        if config_value == 'default':
            value['Config'] = {'Labels': labels if labels is not None else {'owner': 'harness-gate'}}
        else:
            value['Config'] = config_value
        value.update(extra or {})
        return json_reply(value)

    def routes(self, api='1.47', version=None, info=None, inspect=None, version_after=None, info_after=None):
        first_version = version or self.version()
        last_version = version_after or first_version
        first_info = info or self.info()
        last_info = info_after or first_info
        first_inspect = inspect or self.inspect()
        return {
            '/version': [first_version, last_version],
            f'/v{api}/info': [first_info, last_info],
            f'/v{api}/containers/{self.object_id}/json': [first_inspect],
        }

    def run_observation(self, responses, *, api='1.47', **kwargs):
        router = self.router(responses).start()
        cfg = self.load(api)
        result = observation.inspect(cfg, self.object_id, **kwargs)
        router.close()
        return result, router.requests

    def assert_unavailable(self, result):
        self.assertEqual(result, {'outcome': 'unavailable', 'observations': None})

    def test_exact_five_route_sequence_and_present(self):
        result, requests = self.run_observation(self.routes(), timeout=1)
        self.assertIn('outcome', result)
        self.assertIn('present', result['outcome'])
        self.assertEqual(result['outcome']['present']['object']['object_id'], self.object_id)
        self.assertEqual(result['outcome']['present']['object']['labels'],
                         [{'key': 'owner', 'value': 'harness-gate'}])
        self.assertEqual(requests, ['/version', '/v1.47/info',
                                    f'/v1.47/containers/{self.object_id}/json',
                                    '/version', '/v1.47/info'])
        self.assertEqual(result['observations']['observed_before'],
                         {'api_version': '1.47', 'server_version': '27.0.1', 'daemon_id': 'daemon-1'})
        self.assertEqual(result['observations']['observed_before'], result['observations']['observed_after'])

    def test_api_range_is_numeric_and_selected_need_not_be_max(self):
        result, requests = self.run_observation(
            self.routes(api='1.10', version=self.version(ApiVersion='1.10', MinAPIVersion='1.9')),
            api='1.10', timeout=1)
        self.assertIn('present', result['outcome'])
        self.assertIn('/v1.10/info', requests)

        result, _ = self.run_observation(self.routes(), timeout=1)
        self.assertIn('present', result['outcome'])

    def test_api_out_of_range_and_malformed(self):
        cases = [
            self.version(ApiVersion='1.46'),
            self.version(MinAPIVersion='1.48'),
            self.version(ApiVersion='1.40', MinAPIVersion='1.50'),
            self.version(ApiVersion='1.010'),
            self.version(MinAPIVersion=None),
            self.version(ApiVersion=None),
            self.version(ApiVersion=['1.47']),
            reply(b'{"Version":"27.0.1"}'),
            reply(b'not-json'),
            reply(b'[]'),
        ]
        for body in cases:
            with self.subTest(body=body[:80]):
                result, requests = self.run_observation(self.routes(version=body), timeout=1)
                self.assert_unavailable(result)
                self.assertEqual(requests, ['/version'])

    def test_version_info_mismatch_missing_and_malformed(self):
        cases = [
            (self.routes(version=self.version(Version='27.0.2')), ['/version']),
            (self.routes(info=self.info(ID='daemon-2')), ['/version', '/v1.47/info']),
            (self.routes(version_after=self.version(Version='27.0.2')), None),
            (self.routes(info_after=self.info(ID='daemon-2')), None),
            (self.routes(version=reply(b'{"ApiVersion":"1.48","MinAPIVersion":"1.40"}')), ['/version']),
            (self.routes(info=reply(b'{"Version":"27.0.1"}')), ['/version', '/v1.47/info']),
            (self.routes(version=reply(b'{}', 200)), ['/version']),
            (self.routes(info=reply(b'{}', 500)), ['/version', '/v1.47/info']),
            (self.routes(version=reply(b'{}', 404)), ['/version']),
            (self.routes(info=reply(b'{}', 404)), ['/version', '/v1.47/info']),
            (self.routes(version=reply(b'\xff', 200)), ['/version']),
            (self.routes(info=reply(b'\xff', 200)), ['/version', '/v1.47/info']),
        ]
        for routes, expected in cases:
            with self.subTest(expected=expected):
                result, requests = self.run_observation(routes, timeout=1)
                self.assert_unavailable(result)
                if expected is not None:
                    self.assertEqual(requests, expected)

    def test_inspect_present_validation(self):
        wrong_id = 'b' * 64
        cases = [
            self.inspect(ID=wrong_id),
            self.inspect(ID=self.object_id.upper()),
            self.inspect(ID=None),
            self.inspect(config_value=None),
            self.inspect(config_value=[]),
            self.inspect(config_value={'Labels': {}}),
            self.inspect(config_value={'Labels': []}),
            self.inspect(config_value={'Labels': {'owner': ''}}),
            self.inspect(config_value={'Labels': {'owner': 1}}),
            self.inspect(config_value={'Labels': {'': 'v'}}),
            self.inspect(config_value={'Labels': {'owner': '\x01'}}),
            reply(b'[]'),
            reply(b'\xff'),
            reply(b'{"Id":"' + self.object_id.encode() + b'","Config":{"Labels":{"x":NaN}}}'),
            reply(b'{"Id":"' + self.object_id.encode() + b'","Config":{"Labels":{"x":"a","x":"b"}}}'),
            reply(b'{"Id":"' + self.object_id.encode() + b'","Id":"' + self.object_id.encode() + b'","Config":{"Labels":{"x":"v"}}}'),
        ]
        for body in cases:
            with self.subTest(body=body[:100]):
                result, _ = self.run_observation(self.routes(inspect=body), timeout=1)
                self.assert_unavailable(result)

    def test_present_labels_are_normalized_facts(self):
        result, _ = self.run_observation(
            self.routes(inspect=self.inspect(labels={'z': 'last', 'a': 'first'}, extra={'State': {}})),
            timeout=1)
        self.assertEqual(result['outcome']['present']['object']['labels'],
                         [{'key': 'a', 'value': 'first'}, {'key': 'z', 'value': 'last'}])
        self.assertNotIn('absent', result)
        self.assertNotIn('accepted', result['outcome']['present'])
        self.assertNotIn('required', result['outcome']['present'])

    def test_non200_and_errors_are_always_unavailable_not_absent(self):
        cases = [
            self.routes(inspect=reply(b'{}', 404)),
            self.routes(inspect=reply(b'{}', 500)),
            self.routes(version_after=reply(b'{}', 503)),
            self.routes(info_after=reply(b'{}', 401)),
        ]
        for routes in cases:
            with self.subTest(routes=list(routes)):
                result, _ = self.run_observation(routes, timeout=1)
                self.assert_unavailable(result)
                self.assertNotIn('absent', result)

    def test_shared_budget_timeout_and_cancellation(self):
        router = self.router(self.routes(), delay=0.08).start()
        cfg = self.load()
        result = observation.inspect(cfg, self.object_id, timeout=0.15)
        router.close()
        self.assert_unavailable(result)
        self.assertLessEqual(len(router.requests), 3)

        stalled = self.routes()
        router = self.router(stalled, delay=0.2).start()
        cfg = self.load()
        started = time.monotonic()
        result = observation.inspect(cfg, self.object_id, timeout=0.2)
        router.close()
        self.assert_unavailable(result)
        self.assertLess(time.monotonic() - started, 1.5)

        router = self.router(self.routes())
        cfg = self.load()
        result = observation.inspect(cfg, self.object_id, timeout=0.2, cancelled=lambda: True)
        self.assert_unavailable(result)
        self.assertEqual(router.requests, [])
        self.assert_no_connect(router)
        router.close()

        cancel = threading.Event()
        router = self.router(self.routes(), on_request=lambda path: cancel.set() if path == '/version' else None).start()
        cfg = self.load()
        result = observation.inspect(cfg, self.object_id, timeout=1, cancelled=cancel.is_set)
        router.close()
        self.assert_unavailable(result)
        self.assertLessEqual(len(router.requests), 2)

        after = threading.Event()
        router = self.router(
            self.routes(inspect=self.inspect()),
            on_request=lambda path: after.set() if '/containers/' in path else None).start()
        cfg = self.load()
        result = observation.inspect(cfg, self.object_id, timeout=1, cancelled=after.is_set)
        router.close()
        self.assert_unavailable(result)

    def test_invalid_arguments_never_connect(self):
        router = self.router(self.routes())
        cfg = self.load()
        for object_id in ('a' * 63, 'A' * 64, 1, None):
            with self.subTest(object_id=object_id):
                self.assert_unavailable(observation.inspect(cfg, object_id))
        for timeout in (0, -1, 30.1, True, '1', None):
            with self.subTest(timeout=timeout):
                self.assert_unavailable(observation.inspect(cfg, self.object_id, timeout=timeout))
        self.assertEqual(router.requests, [])
        self.assert_no_connect(router)

    def assert_no_connect(self, router):
        router.listener.settimeout(0.1)
        with self.assertRaises(socket.timeout):
            connection, _ = router.listener.accept()
            connection.close()
            self.fail('unexpected observation connection')

    def test_static_observation_boundary(self):
        import ast
        source = (PLUGIN / 'observation.py').read_text()
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
        self.assertLessEqual(imports, {'json', 're', 'time', 'unix_http'})
        for forbidden in ('subprocess', 'requests', 'urllib', 'http', 'os', 'environ', 'getenv', 'socket'):
            self.assertNotIn(forbidden, imports | names)
        self.assertNotIn('absent', result_outcome_names(tree))


def result_outcome_names(tree):
    names = set()
    for node in __import__('ast').walk(tree):
        if isinstance(node, __import__('ast').Name):
            names.add(node.id)
    return names
