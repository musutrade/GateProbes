import ast
import dataclasses
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import tempfile
import unittest

sys_dont_write = True
import sys
sys.dont_write_bytecode = sys_dont_write

PLUGIN = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('docker_runtime_config', PLUGIN / 'config.py')
config = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(config)


def digest(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


class ConfigTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp(prefix='docker-runtime-', dir=Path.home()))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root)

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=self.root))
        os.chmod(self.dir, 0o700)
        self.paths = []
        self.sockets = []
        self.counter = 0

    def tearDown(self):
        for item in self.sockets:
            item.close()
        for item in self.paths:
            try:
                item.unlink()
            except FileNotFoundError:
                pass
        shutil.rmtree(self.dir)

    def mk_socket(self, name='engine.sock'):
        path = self.dir / name
        item = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        item.bind(str(path))
        os.chmod(path, 0o600)
        self.paths.append(path)
        self.sockets.append(item)
        return path

    def data(self, socket=None, **overrides):
        value = {
            'schema': 'gate-runtime-engine-config/v2',
            'engine': 'docker',
            'transport': 'unix-http',
            'socket_path': str(socket or self.mk_socket()),
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

    def write(self, data=None, *, raw=None, name='config.json', mode=0o600):
        self.counter += 1
        path = self.dir / f'{name}-{self.counter}'
        payload = raw if raw is not None else json.dumps(data or self.data()).encode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, mode)
        return path, payload

    def assert_invalid(self, path, sha, sentinel=None):
        with self.assertRaises(config.InvalidConfig) as caught:
            config.load(str(path), sha)
        if sentinel is not None:
            self.assertNotIn(sentinel, str(caught.exception))
        return caught.exception

    def test_valid_current_uid_config_and_revalidate(self):
        sock = self.mk_socket()
        path, payload = self.write(self.data(sock))
        loaded = config.load(str(path), digest(payload))
        self.assertIsInstance(loaded, config.Config)
        self.assertEqual(loaded.socket_path, str(sock))
        self.assertEqual(loaded.principal_uid, os.geteuid())
        self.assertEqual(loaded.socket_uid, os.geteuid())
        self.assertEqual(loaded.file_identity, config.identity(path.stat()))
        loaded.revalidate()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            loaded.scope = 'other'

    def test_digest_and_type_pins(self):
        sock = self.mk_socket()
        path, payload = self.write(self.data(sock))
        good = digest(payload)
        for sha in [good.upper(), good[:-1], good + '0', '', None, 1, b'x' * 32]:
            with self.subTest(sha=sha):
                self.assert_invalid(path, sha)

    def test_missing_extra_and_duplicate_fields(self):
        sock = self.mk_socket()
        base = self.data(sock)
        for key in tuple(base):
            value = dict(base)
            value.pop(key)
            path, payload = self.write(value, name=f'missing-{key}.json')
            self.assert_invalid(path, digest(payload))
        extra = dict(base, extra='sentinel-extra')
        path, payload = self.write(extra, name='extra.json')
        self.assert_invalid(path, digest(payload), 'sentinel-extra')
        raw = json.dumps(base).encode()
        duplicate = raw[:1] + b'"schema":"gate-runtime-engine-config/v2",' + raw[1:]
        path, payload = self.write(raw=duplicate, name='duplicate.json')
        self.assert_invalid(path, digest(payload))

    def test_wrong_field_types(self):
        sock = self.mk_socket()
        values = {
            'schema': [None, 1],
            'engine': [None, 'podman'],
            'transport': [None, 'tcp'],
            'socket_uid': [True, '0', -1, 4294967296, 0.0],
            'principal_uid': [True, '0', -1, 4294967296, 0.0],
            'rootless': [0, 1, 'false', None],
            'api_version': [1, None, 1.47],
            'server_version': [1, None],
            'daemon_id': [1, None],
            'scope': [1, None],
            'socket_path': [1, None],
        }
        for key, candidates in values.items():
            for value in candidates:
                with self.subTest(key=key, value=value):
                    path, payload = self.write(self.data(sock, **{key: value}), name=f'type-{key}.json')
                    self.assert_invalid(path, digest(payload))

    def test_schema_engine_transport_are_exact(self):
        sock = self.mk_socket()
        for key, value in [('schema', 'gate-runtime-engine-config/v1'),
                           ('schema', 'gate-runtime-engine-config/v2 '),
                           ('engine', 'Docker'), ('engine', 'podman'),
                           ('transport', 'unix-http '), ('transport', 'tcp')]:
            with self.subTest(key=key, value=value):
                path, payload = self.write(self.data(sock, **{key: value}), name=f'exact-{key}.json')
                self.assert_invalid(path, digest(payload))

    def test_string_fields_are_nonempty_and_have_no_controls(self):
        sock = self.mk_socket()
        for key in ('socket_path', 'api_version', 'server_version', 'daemon_id', 'scope'):
            for value in ('', '   ', '\x01', '\x7f', '\x85'):
                with self.subTest(key=key, value=value):
                    path, payload = self.write(self.data(sock, **{key: value}), name=f'string-{key}.json')
                    self.assert_invalid(path, digest(payload))

    def test_api_version_is_strict(self):
        sock = self.mk_socket()
        for value in ('1', '1.', '.1', '01.1', '1.01', '1.2.3', '65536.0', '1.65536',
                      '-1.0', '1.-1', '1. 0', '1.0\n', '0x1.0'):
            with self.subTest(value=value):
                path, payload = self.write(self.data(sock, api_version=value), name='api.json')
                self.assert_invalid(path, digest(payload))
        for value in ('0.0', '1.0', '1.47', '65535.65535'):
            with self.subTest(value=value):
                path, payload = self.write(self.data(sock, api_version=value), name='api-ok.json')
                self.assertTrue(config.load(str(path), digest(payload)))

    def test_principal_must_match_euid(self):
        sock = self.mk_socket()
        other = (os.geteuid() + 1) % 4294967296
        path, payload = self.write(self.data(sock, principal_uid=other))
        self.assert_invalid(path, digest(payload))

    def test_config_path_must_be_canonical_and_protected(self):
        sock = self.mk_socket()
        path, payload = self.write(self.data(sock))
        sha = digest(payload)
        for value in ('config.json', str(path) + '/', '//' + str(path).lstrip('/'),
                      str(self.dir / '..' / self.dir.name / 'config.json')):
            with self.subTest(value=value):
                with self.assertRaises(config.InvalidConfig):
                    config.load(value, sha)
        outside = Path(tempfile.mkdtemp(dir='/tmp'))
        try:
            outside_config = outside / 'config.json'
            outside_config.write_bytes(payload)
            os.chmod(outside_config, 0o600)
            self.assert_invalid(outside_config, sha)
        finally:
            shutil.rmtree(outside)

    def test_parent_must_not_be_group_or_world_writable(self):
        sock = self.mk_socket()
        path, payload = self.write(self.data(sock))
        sha = digest(payload)
        for mode in (0o770, 0o775, 0o777):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.dir, mode)
                self.assert_invalid(path, sha)
        os.chmod(self.dir, 0o700)
        self.assertTrue(config.load(str(path), sha))

    def test_config_file_mode(self):
        sock = self.mk_socket()
        path, payload = self.write(self.data(sock))
        sha = digest(payload)
        for mode in (0o604, 0o640, 0o660, 0o644):
            with self.subTest(mode=oct(mode)):
                os.chmod(path, mode)
                self.assert_invalid(path, sha)
        for mode in (0o600, 0o400, 0o700):
            with self.subTest(mode=oct(mode)):
                os.chmod(path, mode)
                self.assertTrue(config.load(str(path), sha))

    def test_hardlink_and_fifo_and_directory(self):
        sock = self.mk_socket()
        path, payload = self.write(self.data(sock))
        sha = digest(payload)
        hardlink = self.dir / 'hardlink.json'
        os.link(path, hardlink)
        self.assert_invalid(hardlink, sha)
        fifo = self.dir / 'fifo.json'
        os.mkfifo(fifo, 0o600)
        self.assert_invalid(fifo, sha)
        self.assert_invalid(self.dir, sha)

    def test_symlinked_config_and_symlinked_parent(self):
        sock = self.mk_socket()
        path, payload = self.write(self.data(sock))
        sha = digest(payload)
        link = self.dir / 'config-link.json'
        link.symlink_to(path)
        self.assert_invalid(link, sha)
        real = self.dir / 'real'
        real.mkdir(mode=0o700)
        nested = real / 'config.json'
        nested.write_bytes(payload)
        os.chmod(nested, 0o600)
        parent_link = self.dir / 'parent-link'
        parent_link.symlink_to(real, target_is_directory=True)
        self.assert_invalid(parent_link / 'config.json', sha)

    def test_socket_type_and_owner(self):
        sock = self.mk_socket()
        path, payload = self.write(self.data(sock, socket_uid=(os.geteuid() + 1) % 4294967296))
        self.assert_invalid(path, digest(payload))
        regular = self.dir / 'regular.sock'
        regular.write_bytes(b'x')
        os.chmod(regular, 0o600)
        path, payload = self.write(self.data(str(regular)), name='regular-config.json')
        self.assert_invalid(path, digest(payload))
        fifo = self.dir / 'fifo.sock'
        os.mkfifo(fifo, 0o600)
        path, payload = self.write(self.data(str(fifo)), name='fifo-config.json')
        self.assert_invalid(path, digest(payload))
        path, payload = self.write(self.data(str(self.dir)), name='dir-config.json')
        self.assert_invalid(path, digest(payload))

    def test_symlinked_socket_and_symlinked_socket_parent(self):
        sock = self.mk_socket()
        link = self.dir / 'socket-link'
        link.symlink_to(sock)
        path, payload = self.write(self.data(str(link)), name='socket-link-config.json')
        self.assert_invalid(path, digest(payload))
        real = self.dir / 'socket-real'
        real.mkdir(mode=0o700)
        nested = real / 'engine.sock'
        item = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        item.bind(str(nested))
        self.sockets.append(item)
        self.paths.append(nested)
        parent_link = self.dir / 'socket-parent-link'
        parent_link.symlink_to(real, target_is_directory=True)
        path, payload = self.write(self.data(str(parent_link / 'engine.sock')), name='socket-parent-config.json')
        self.assert_invalid(path, digest(payload))

    def test_socket_path_must_be_canonical_and_protected(self):
        sock = self.mk_socket()
        sha = None
        for value in ('engine.sock', str(self.dir / '..' / 'engine.sock'),
                      '//' + str(sock).lstrip('/'), str(sock) + '/'):
            with self.subTest(value=value):
                path, payload = self.write(self.data(sock, socket_path=value), name='socket-path.json')
                self.assert_invalid(path, digest(payload))
        outside = Path(tempfile.mkdtemp(dir='/tmp'))
        try:
            outside_sock = outside / 'engine.sock'
            item = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            item.bind(str(outside_sock))
            os.chmod(outside_sock, 0o600)
            path, payload = self.write(self.data(str(outside_sock)), name='tmp-socket.json')
            self.assert_invalid(path, digest(payload))
            item.close()
        finally:
            shutil.rmtree(outside)
        writable = self.dir / 'writable'
        writable.mkdir(mode=0o700)
        writable_sock = writable / 'engine.sock'
        item = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        item.bind(str(writable_sock))
        self.sockets.append(item)
        self.paths.append(writable_sock)
        os.chmod(writable, 0o770)
        path, payload = self.write(self.data(str(writable_sock)), name='writable-socket.json')
        self.assert_invalid(path, digest(payload))

    def test_size_boundary(self):
        sock = self.mk_socket()
        base = json.dumps(self.data(sock)).encode()
        exact = base + b' ' * (config.LIMIT - len(base))
        path = self.dir / 'exact.json'
        path.write_bytes(exact)
        os.chmod(path, 0o600)
        self.assertTrue(config.load(str(path), digest(exact)))
        over = base + b' ' * (config.LIMIT + 1 - len(base))
        path = self.dir / 'over.json'
        path.write_bytes(over)
        os.chmod(path, 0o600)
        self.assert_invalid(path, digest(over))

    def test_json_errors_are_static(self):
        sock = self.mk_socket()
        base = json.dumps(self.data(sock)).encode()
        for name, raw in [('nonutf8', b'\xff' + base),
                          ('trailing', base + b'x'),
                          ('array', b'[]'),
                          ('empty', b''),
                          ('nan', base.replace(b'"api_version": "1.47"', b'"api_version": NaN'))]:
            with self.subTest(name=name):
                path, payload = self.write(raw=raw, name=f'{name}.json')
                self.assert_invalid(path, digest(payload), 'sentinel-secret')

    def test_env_is_ignored(self):
        sock = self.mk_socket()
        path, payload = self.write(self.data(sock))
        sha = digest(payload)
        before = config.load(str(path), sha)
        old = dict(os.environ)
        try:
            os.environ.update({'DOCKER_HOST': 'tcp://127.0.0.1:1', 'XDG_CONFIG_HOME': '/tmp',
                               'GATE_RUNTIME_CONFIG': '/tmp/other', 'GP_SOCKET': '/tmp/x'})
            after = config.load(str(path), sha)
            self.assertEqual(before, after)
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_revalidate_detects_config_socket_and_metadata_changes(self):
        sock = self.mk_socket()
        path, payload = self.write(self.data(sock))
        loaded = config.load(str(path), digest(payload))
        path.write_bytes(json.dumps(self.data(sock, scope='scope-2')).encode())
        os.chmod(path, 0o600)
        with self.assertRaises(config.InvalidConfig):
            loaded.revalidate()
        path, payload = self.write(self.data(sock), name='config2.json')
        loaded = config.load(str(path), digest(payload))
        sock.unlink()
        replacement = self.mk_socket()
        with self.assertRaises(config.InvalidConfig):
            loaded.revalidate()
        loaded = config.load(str(path), digest(payload))
        os.chmod(sock, 0o660)
        with self.assertRaises(config.InvalidConfig):
            loaded.revalidate()

    def test_exact_replacement_same_bytes_detected(self):
        sock = self.mk_socket()
        path, payload = self.write(self.data(sock))
        loaded = config.load(str(path), digest(payload))
        path.unlink()
        path.write_bytes(payload)
        os.chmod(path, 0o600)
        with self.assertRaises(config.InvalidConfig):
            loaded.revalidate()

    def test_static_boundary(self):
        source = (PLUGIN / 'config.py').read_text()
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
        self.assertLessEqual(imports, {'dataclasses', 'hashlib', 'json', 'os', 'pathlib', 're', 'stat'})
        for forbidden in ('socket', 'http', 'subprocess', 'requests', 'urllib', 'connect', 'Popen', 'system', 'environ', 'getenv'):
            self.assertNotIn(forbidden, imports | names)
        self.assertIn('os.geteuid', source)

    def test_foreign_owned_protected_file_rejects_without_echo(self):
        path = Path('/etc/hostname')
        if not path.exists():
            self.skipTest('no root-owned fixture')
        payload = path.read_bytes()
        with self.assertRaises(config.InvalidConfig) as caught:
            config.load(str(path), digest(payload))
        self.assertNotIn('/etc/hostname', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
