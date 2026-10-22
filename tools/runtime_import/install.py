#!/usr/bin/env python3
"""Explicit Linux-only offline import; never executes imported content."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from contextlib import ExitStack

# Isolated Python (-I) deliberately omits the script directory from sys.path.
# Load only the adjacent shipped module, never PYTHONPATH or a global module.
import importlib.util
_spec = importlib.util.spec_from_file_location("runtime_import_preflight", Path(__file__).with_name("preflight.py"))
preflight = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(preflight)


class ImportRejected(ValueError):
    pass


def require(condition):
    if not condition:
        raise ImportRejected('runtime import rejected')


def identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_gid, metadata.st_nlink, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def protected_path(path):
    require(path.is_absolute() and path.resolve(strict=True) == path)
    for parent in path.parents:
        metadata = parent.lstat()
        require(stat.S_ISDIR(metadata.st_mode))
        require(metadata.st_uid in (0, os.geteuid()) and metadata.st_mode & 0o022 == 0)


class HeldInput:
    def __init__(self, path, limit, protected=False):
        self.path = Path(path)
        self.protected = protected
        require(self.path.is_absolute())
        if protected:
            protected_path(self.path)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            metadata = os.fstat(self.fd)
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1)
            if protected:
                require(metadata.st_uid == os.geteuid())
                require(stat.S_IMODE(metadata.st_mode) in (0o400, 0o600))
            require(metadata.st_size <= limit)
            self.identity = identity(metadata)
            with os.fdopen(os.dup(self.fd), 'rb') as source:
                self.data = source.read(limit + 1)
            require(len(self.data) <= limit)
            self.revalidate()
        except BaseException:
            os.close(self.fd)
            raise

    def revalidate(self):
        if self.protected:
            protected_path(self.path)
        require(identity(os.fstat(self.fd)) == self.identity)
        require(identity(self.path.lstat()) == self.identity)

    def close(self):
        os.close(self.fd)


def write_file(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as destination:
        # Exact protected mode, independent of the caller's umask.
        os.fchmod(destination.fileno(), mode)
        destination.write(data)
        destination.flush()
        os.fsync(destination.fileno())


def publish(parent_fd, source, target):
    # Linux renameat2(RENAME_NOREPLACE): no exists-check/rename overwrite race.
    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, 'renameat2', None)
    require(rename is not None)
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent_fd, os.fsencode(source), parent_fd, os.fsencode(target), 1) != 0:
        raise ImportRejected('runtime destination publication rejected')


def descriptor(pin, destination):
    return {'schema': 'gate-runtime-installation/v1',
            'repository': pin['repository'], 'tag': pin['tag'],
            'source_commit': pin['source_commit'], 'archive_sha256': pin['archive_sha256'],
            'executable': {'path': str(destination / preflight.profile(pin)[1]),
                           'sha256': pin['executable_sha256'], 'version': pin['version']}}


def import_release(pin_path, assets_path, destination_path):
    """Pin authority is the operator's responsibility; this verifies its protection."""
    require(sys.platform == 'linux')
    with ExitStack() as stack:
        pin_file = HeldInput(pin_path, 65536, protected=True)
        stack.callback(pin_file.close)
        pin = preflight.pin(pin_file.data)
        assets = Path(assets_path)
        require(assets.is_absolute() and assets.resolve(strict=True) == assets and assets.is_dir())
        archive = preflight.archive_name(pin)
        binary = preflight.profile(pin)[1]
        inputs = {}
        for key, name, limit in [('archive', archive, preflight.MAX_ARCHIVE),
                                  ('sbom', archive + '.sbom.cdx.json', 1024 * 1024),
                                  ('inventory', 'release-inventory.json', 1024 * 1024),
                                  ('checksums', 'SHA256SUMS', 4096)]:
            held = HeldInput(assets / name, limit)
            stack.callback(held.close)
            inputs[key] = held
        files = preflight.validate(pin_file.data, **{key: held.data for key, held in inputs.items()})
        destination = Path(destination_path)
        require(destination.is_absolute() and destination.name not in ('', '.', '..'))
        parent = destination.parent
        protected_path(parent)
        require(parent.is_dir() and parent.stat().st_uid == os.geteuid())
        require(parent.stat().st_mode & 0o022 == 0)
        require(not os.path.lexists(destination))
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, parent_fd)
        parent_identity = os.fstat(parent_fd)
        with tempfile.TemporaryDirectory(prefix='.runtime-import-', dir=parent) as temporary:
            stage = Path(temporary)
            for name, content in files.items():
                write_file(stage / name, content, 0o500 if name == binary else 0o400)
            data = json.dumps(descriptor(pin, destination), indent=2, sort_keys=True).encode() + b'\n'
            write_file(stage / 'installation.json', data, 0o400)
            stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(stage_fd)
            finally:
                os.close(stage_fd)
            pin_file.revalidate()
            for held in inputs.values():
                held.revalidate()
            protected_path(parent)
            current = parent.stat()
            require((current.st_dev, current.st_ino) == (parent_identity.st_dev, parent_identity.st_ino))
            require(current.st_uid == os.geteuid() and current.st_mode & 0o022 == 0)
            publish(parent_fd, stage.name, destination.name)
            # If this fails, keep the published directory and report failure.
            # Never claim success or remove a possibly committed installation.
            os.fsync(parent_fd)
        return destination / 'installation.json'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pin', required=True, type=Path)
    parser.add_argument('--assets', required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = import_release(args.pin, args.assets, args.destination)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print('runtime import rejected; inspect destination before retry', file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
