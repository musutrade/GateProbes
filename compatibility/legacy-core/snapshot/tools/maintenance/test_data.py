#!/usr/bin/env python3
"""Fetch pinned, verified regression data explicitly; ordinary builds need none."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import urllib.parse
import urllib.request

from restore_evidence import restore, safe_path

ROOT = Path(__file__).resolve().parents[2]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f'duplicate manifest key: {key}')
        result[key] = value
    return result


def read_manifest(path):
    manifest = json.loads(path.read_text(), object_pairs_hook=unique)
    require(manifest.get('schema') == 'external-test-data/v1', 'invalid manifest schema')
    require(re.fullmatch('[0-9a-f]{40}', manifest.get('source_commit', '')), 'unbound source commit')
    seen, groups = set(), set()
    for row in manifest['archives']:
        group = row['group']
        require(re.fullmatch('[a-z][a-z0-9-]*', group) and group not in groups, 'invalid or duplicate group')
        groups.add(group)
        url = urllib.parse.urlsplit(row['url'])
        require(url.scheme == 'https' and url.netloc == 'github.com' and not url.query and not url.fragment
                and re.fullmatch(r'/musutrade/Harness-Gate/releases/download/source-data-[0-9]+/[a-z0-9-]+\.tar\.gz', url.path),
                'data must use an exact historical evidence release URL')
        require(type(row['archive_size']) is int and row['archive_size'] > 0, 'invalid archive size')
        require(re.fullmatch('[0-9a-f]{64}', row['archive_sha256']), 'invalid archive digest')
        require(row['file_count'] == len(row['files']) and row['files'], 'invalid member count')
        for name, member in row['files'].items():
            safe_path(name)
            require(name.startswith(('docs/quality/', 'docs/dogfood/', 'tools/quality/fixtures/'))
                    and Path(name).suffix in ('.json', '.gz', '.xz', '.bundle', '.log', '.stderr'),
                    f'not an external data path: {name}')
            require(name not in seen, f'duplicate member: {name}')
            seen.add(name)
            require(type(member['size']) is int and member['size'] >= 0, 'invalid member size')
            require(re.fullmatch('[0-9a-f]{64}', member['sha256']), 'invalid member digest')
    require(bool(groups), 'no data groups')
    return manifest


def destination(root, name):
    safe_path(name)
    target = root / name
    for part in (target, *target.parents):
        if part == root:
            break
        require(not part.is_symlink(), f'symlink in destination: {name}')
    require(not target.exists() or target.is_file(), f'non-file destination: {name}')
    return target


def matches(path, row):
    return path.is_file() and path.stat().st_size == row['size'] and digest(path) == row['sha256']


def fetch_archive(row, cache, offline):
    archive = cache / (row['archive_sha256'] + '.tar.gz')
    require(not archive.is_symlink(), 'symlink in archive cache')
    if archive.exists():
        require(archive.stat().st_size == row['archive_size'] and digest(archive) == row['archive_sha256'],
                f'corrupt cached archive: {archive}')
        return archive
    require(not offline, f'offline cache miss: {row["group"]}')
    cache.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.download-', dir=cache)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as output, urllib.request.urlopen(row['url'], timeout=60) as response:
            require(urllib.parse.urlsplit(response.url).scheme == 'https', 'insecure download redirect')
            count = 0
            while block := response.read(1024 * 1024):
                count += len(block)
                require(count <= row['archive_size'], 'download exceeds pinned size')
                output.write(block)
        require(temporary.stat().st_size == row['archive_size'] and digest(temporary) == row['archive_sha256'],
                'download size or SHA-256 mismatch')
        temporary.replace(archive)
    finally:
        temporary.unlink(missing_ok=True)
    return archive


def hydrate(root, manifest, cache, groups, offline=False):
    root = root.resolve(strict=True)
    known = {row['group'] for row in manifest['archives']}
    require(groups <= known, f'unknown groups: {sorted(groups - known)}')
    selected = [row for row in manifest['archives'] if row['group'] in groups]
    # Check all existing destinations before downloading or writing anything.
    for row in selected:
        for name, member in row['files'].items():
            path = destination(root, name)
            require(not path.exists() or matches(path, member), f'changed local data; refusing overwrite: {name}')
    restored = 0
    for row in selected:
        missing = [name for name in row['files'] if not (root / name).exists()]
        if not missing:
            continue
        archive = fetch_archive(row, cache, offline)
        index = dict(row, schema='quality-evidence-archive-index/v1')
        with tempfile.TemporaryDirectory(prefix='gatehouse-test-data-') as directory:
            stage = Path(directory) / 'verified'
            restore(index, archive, stage, missing)
            for name in missing:
                target = destination(root, name)
                target.parent.mkdir(parents=True, exist_ok=True)
                # Exclusive creation refuses races and never overwrites local edits.
                with (stage / name).open('rb') as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output)
                restored += 1
    return {'groups': sorted(groups), 'restored_files': restored,
            'verified_files': sum(len(row['files']) for row in selected)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--cache', type=Path, default=Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')) / 'gatehouse-test-data')
    parser.add_argument('--group', action='append', help='default: all regression groups')
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--list', action='store_true')
    args = parser.parse_args()
    try:
        manifest = read_manifest(args.manifest or args.root / 'test-data/manifest.json')
        if args.list:
            result = [{'group': row['group'], 'files': row['file_count'], 'download_bytes': row['archive_size']}
                      for row in manifest['archives']]
        else:
            groups = set(args.group or [row['group'] for row in manifest['archives']])
            result = hydrate(args.root, manifest, args.cache, groups, args.offline)
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, f'test data unavailable: {error}\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
