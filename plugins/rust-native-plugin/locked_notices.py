"""Build-only Cargo archive/source/notice checks, retained from candidate packaging."""
import hashlib
from pathlib import Path, PurePosixPath
import tarfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path, limit=64 * 1024 * 1024):
    require(not path.is_symlink() and path.is_file(), f'not a regular file: {path}')
    require(path.stat().st_size <= limit, f'file exceeds bound: {path}')
    return path.read_bytes()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    data = read(path)
    return {'sha256': sha(data), 'bytes': len(data)}



def registry_notices(package, lock):
    """Authenticate archived licenses and the actual unpacked build input.

    This never extracts or republishes a .crate archive. Registry metadata alone
    is not proof of the cached source that Cargo will compile.
    """
    require(package['source'] == 'registry+https://github.com/rust-lang/crates.io-index',
            f'unsupported release dependency source: {package["id"]}')
    source = Path(package['manifest_path']).parent
    key = (package['name'], package['version'], package['source'])
    expected = lock[key]['checksum']
    archive = source.parents[2] / 'cache' / source.parent.name / (source.name + '.crate')
    require(identity(archive)['sha256'] == expected, f'crate checksum mismatch: {archive}')
    notices = {}
    seen = set()
    total = 0
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar:
            relative = PurePosixPath(member.name)
            require(relative.parts and relative.parts[0] == source.name
                    and '..' not in relative.parts and not relative.is_absolute(),
                    f'unsafe crate member: {member.name}')
            if member.isdir():
                continue
            require(member.isfile(), f'nonregular crate member: {member.name}')
            name = relative.relative_to(source.name).as_posix()
            require(name not in seen, f'duplicate crate member: {name}')
            seen.add(name)
            total += member.size
            require(member.size <= 16 * 1024 * 1024 and total <= 128 * 1024 * 1024,
                    'crate expands beyond release preparation bound')
            contents = tar.extractfile(member).read()
            require(contents == read(source / name), f'cached source differs from locked archive: {source / name}')
            leaf = relative.name.lower()
            if leaf.startswith(('license', 'copying', 'copyright', 'notice', 'unlicense')):
                notices[name] = contents.decode('utf-8')
    # Cargo cache markers are generated outside the archive; no additional source
    # or license file can silently affect a build or its notices.
    actual = set()
    for path in source.rglob('*'):
        require(not path.is_symlink(), f'cached crate symlink: {path}')
        if path.is_file():
            actual.add(path.relative_to(source).as_posix())
        else:
            require(path.is_dir(), f'cached crate special file: {path}')
    require(actual - {'.cargo-ok', '.cargo-checksum.json'} == seen,
            f'undeclared cached crate files: {source}')
    require(package.get('license') and notices, f'missing crate license notices: {package["id"]}')
    return notices, {'package': package['name'], 'version': package['version'],
                     'license_expression': package['license'], 'crate_sha256': expected,
                     'notices': {name: sha(text.encode()) for name, text in sorted(notices.items())}}
