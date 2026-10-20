"""Protected local configuration boundary; no engine connection or execution."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

LIMIT = 65536
FIELDS = {'schema', 'engine', 'transport', 'socket_path', 'socket_uid',
          'principal_uid', 'rootless', 'api_version', 'server_version',
          'daemon_id', 'scope'}


class InvalidConfig(ValueError):
    """Static diagnostics intentionally omit configuration contents."""


def require(condition):
    if not condition:
        raise InvalidConfig('runtime configuration or local identity rejected')


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns)


def canonical(path):
    require(type(path) is str and path.startswith('/'))
    require(all(part not in ('', '.', '..') for part in path[1:].split('/')))
    require(str(Path(path).resolve(strict=True)) == path)
    return Path(path)


def protected_parents(path):
    # Root or the invoking user may control ancestors; writable group/world
    # directories (including sticky /tmp) are not a protected production root.
    for parent in path.parents:
        info = parent.stat()
        require(stat.S_ISDIR(info.st_mode))
        require(info.st_uid in (0, os.geteuid()) and info.st_mode & 0o022 == 0)


@dataclass(frozen=True, init=False)
class Config:
    path: Path
    sha256: str
    file_identity: tuple
    socket_identity: tuple
    socket_path: str
    socket_uid: int
    principal_uid: int
    rootless: bool
    api_version: str
    server_version: str
    daemon_id: str
    scope: str
    source_fd: int | None = None

    def __init__(self, *args, **kwargs):
        raise InvalidConfig('runtime configuration requires validated loading')

    def revalidate(self):
        """Recheck pins before/after future I/O; never establishes daemon identity."""
        try:
            current = (load_sealed(self.source_fd, self.sha256) if self.source_fd is not None
                       else load(str(self.path), self.sha256))
            require(current == self)
        except (OSError, ValueError, TypeError, RecursionError):
            raise InvalidConfig('runtime configuration or local identity rejected') from None


def load(path, expected_sha256):
    """Require independent digest pins. No ambient endpoint/context discovery."""
    try:
        return _load(path, expected_sha256)
    except (OSError, ValueError, TypeError, RecursionError):
        raise InvalidConfig('runtime configuration or local identity rejected') from None


def _load(path, expected_sha256):
    require(os.name == 'posix')
    require(type(expected_sha256) is str and
            re.fullmatch('[0-9a-f]{64}', expected_sha256) is not None)
    path = canonical(path)
    protected_parents(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
        require(before.st_uid == os.geteuid() and before.st_mode & 0o077 == 0)
        data = stream.read(LIMIT + 1)
        require(len(data) <= LIMIT)
        require(hashlib.sha256(data).hexdigest() == expected_sha256)
        require(identity(before) == identity(os.fstat(stream.fileno())))
        require(identity(before) == identity(path.lstat()))
    value, socket_info = _values(data, expected_sha256)
    return _build(path, expected_sha256, identity(before), socket_info, value)


def _values(data, expected_sha256):
    require(hashlib.sha256(data).hexdigest() == expected_sha256)
    value = json.loads(data.decode('utf-8'), object_pairs_hook=pairs)
    require(type(value) is dict and set(value) == FIELDS)
    require(value['schema'] == 'gate-runtime-engine-config/v2')
    require(value['engine'] == 'docker' and value['transport'] == 'unix-http')
    for key in ('socket_uid', 'principal_uid'):
        require(type(value[key]) is int and 0 <= value[key] <= 4294967295)
    require(type(value['rootless']) is bool)
    require(value['principal_uid'] == os.geteuid())
    for key in ('socket_path', 'api_version', 'server_version', 'daemon_id', 'scope'):
        item = value[key]
        require(type(item) is str and bool(item.strip()) and
                not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in item))
    require(re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value['api_version']) is not None)
    require(all(int(part) <= 65535 for part in value['api_version'].split('.')))
    socket_path = canonical(value['socket_path'])
    protected_parents(socket_path)
    socket_info = socket_path.lstat()
    require(stat.S_ISSOCK(socket_info.st_mode) and socket_info.st_uid == value['socket_uid'])
    return value, socket_info


def _build(path, expected_sha256, file_identity, socket_info, value, source_fd=None):
    # The supported construction path exists only after every check succeeds.
    # This is API discipline, not a sandbox against hostile in-process Python.
    config = object.__new__(Config)
    fields = {key: value[key] for key in FIELDS - {'schema', 'engine', 'transport'}}
    fields.update(path=path, sha256=expected_sha256, file_identity=file_identity,
                  socket_identity=identity(socket_info), source_fd=source_fd)
    for name, item in fields.items():
        object.__setattr__(config, name, item)
    return config


def sealed_bytes(fd):
    """Linux fixture-only immutable descriptors; no path reopening/fallback."""
    import fcntl
    require(type(fd) is int and fd >= 3)
    seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid())
    require(before.st_nlink == 0 and stat.S_IMODE(before.st_mode) == 0o600)
    require(fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals == seals)
    data = os.pread(fd, LIMIT + 1, 0)
    require(len(data) <= LIMIT and before.st_size == len(data))
    require(identity(before) == identity(os.fstat(fd)))
    return data, identity(before)


def load_sealed(fd, expected_sha256):
    try:
        require(type(expected_sha256) is str and
                re.fullmatch('[0-9a-f]{64}', expected_sha256) is not None)
        data, file_identity = sealed_bytes(fd)
        value, socket_info = _values(data, expected_sha256)
        return _build(None, expected_sha256, file_identity, socket_info, value, fd)
    except (OSError, ValueError, TypeError, AttributeError, RecursionError):
        raise InvalidConfig('runtime configuration or local identity rejected') from None
