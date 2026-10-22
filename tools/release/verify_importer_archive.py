"""Bounded importer archive verification before extraction; trust pins are external."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

LIMIT = 4 * 1024 * 1024
PREFIX = 'gateprobes-runtime-importer-0.1.0'
NAMES = frozenset(('LICENSE', 'plugins/runtime-importer/README.md',
    'plugins/runtime-importer/plugin.json', 'plugins/runtime-importer/core-pin.json',
    'tools/runtime_import/install.py', 'tools/runtime_import/preflight.py',
    'tools/runtime_import/README.md', 'tools/runtime_import/release-pin.json'))


def profile(version):
    # The trusted caller selects the version before any archive bytes are parsed.
    if version == '0.1.0':
        return PREFIX, NAMES
    if version == '0.2.0':
        names = (NAMES - {'plugins/runtime-importer/core-pin.json',
                          'tools/runtime_import/release-pin.json'}) | {
            'plugins/runtime-importer/core-pin-v3.json',
            'tools/runtime_import/release-pin-v3.json'}
        return 'gateprobes-runtime-importer-0.2.0', names
    raise ValueError('unsupported importer distribution version')


def pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ValueError('duplicate SBOM field')
        result[key] = value
    return result


def validate(archive, sbom, archive_sha256, sbom_sha256, version="0.1.0"):
    prefix, names = profile(version)
    for data, expected in ((archive, archive_sha256), (sbom, sbom_sha256)):
        if not re.fullmatch('[0-9a-f]{64}', expected) or len(data) > LIMIT or hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('importer asset digest or size mismatch')
    with gzip.GzipFile(fileobj=io.BytesIO(archive)) as compressed:
        raw = compressed.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError('importer tar exceeds limit')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as stream:
        for member in stream:
            parts = member.name.split('/')
            name = '/'.join(parts[1:])
            if (not parts or parts[0] != prefix or any(p in ('', '.', '..') for p in parts)
                    or name not in names or name in files or not member.isreg()
                    or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    or member.pax_headers or member.linkname or member.mode != 0o644
                    or member.uid != 0 or member.gid != 0 or member.size <= 0 or member.size > LIMIT):
                raise ValueError('invalid importer archive member')
            files[name] = stream.extractfile(member).read()
        if stream.pax_headers or set(files) != names:
            raise ValueError('incomplete importer archive')
    canonical = io.BytesIO()
    with tarfile.open(fileobj=canonical, mode='w', format=tarfile.USTAR_FORMAT) as stream:
        for name, data in sorted(files.items()):
            member = tarfile.TarInfo(prefix + '/' + name)
            member.size, member.mode, member.mtime = len(data), 0o644, 0
            stream.addfile(member, io.BytesIO(data))
    if raw != canonical.getvalue():
        raise ValueError('noncanonical importer tar or hidden extension')
    value = json.loads(sbom, object_pairs_hook=pairs)
    if (value.get('bomFormat') != 'CycloneDX' or value.get('specVersion') != '1.5'
            or type(value.get('version')) is not int or value['version'] != 1
            or value.get('metadata') != {'component': {'type': 'application', 'name': 'runtime-importer', 'version': version}}):
        raise ValueError('invalid importer SBOM identity')
    expected = [{'type': 'file', 'name': name, 'hashes': [{'alg': 'SHA-256', 'content': hashlib.sha256(data).hexdigest()}]} for name, data in sorted(files.items())]
    if value.get('components') != expected:
        raise ValueError('importer SBOM members differ')
    return files


def extract(archive, sbom, archive_sha256, sbom_sha256, destination, version="0.1.0"):
    prefix, _ = profile(version)
    files = validate(archive, sbom, archive_sha256, sbom_sha256, version)
    # Exclusive new directory; never unpack over pre-existing user files/symlinks.
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    # Repack validated bytes, so extensions/hidden trailing members are never extracted.
    normalized = io.BytesIO()
    with tarfile.open(fileobj=normalized, mode='w', format=tarfile.USTAR_FORMAT) as stream:
        for name, data in sorted(files.items()):
            member = tarfile.TarInfo(prefix + '/' + name)
            member.size, member.mode = len(data), 0o644
            stream.addfile(member, io.BytesIO(data))
    normalized.seek(0)
    with tarfile.open(fileobj=normalized) as stream:
        stream.extractall(destination, filter='data')
    return destination / prefix


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--sbom', required=True, type=Path)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--sbom-sha256', required=True)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--version', choices=['0.1.0', '0.2.0'], default='0.1.0')
    args = parser.parse_args()
    def read(path):
        with path.open('rb') as stream:
            return stream.read(LIMIT + 1)
    print(extract(read(args.archive), read(args.sbom), args.archive_sha256, args.sbom_sha256, args.destination, args.version))
