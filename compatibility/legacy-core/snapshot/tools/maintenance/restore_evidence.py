#!/usr/bin/env python3
"""Restore selected, digest-verified historical evidence into a new directory."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / 'docs/quality/archived-evidence-index.json'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_path(name):
    require(isinstance(name, str) and bool(name), 'empty archive member path')
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.as_posix() == name and
            '\\' not in name and ':' not in name and
            all(part not in ('', '.', '..') for part in name.split('/')),
            f'unsafe archive member path: {name}')
    return path


def archive_records(index):
    require(index.get('schema') == 'quality-evidence-archive-index/v1', 'unknown archive index schema')
    records = [index, *index.get('supplemental_archives', [])]
    known = set()
    for record in records:
        require(re.fullmatch('[0-9a-f]{64}', record.get('archive_sha256', '')) is not None,
                'invalid archive digest')
        files = record.get('files', {})
        require(bool(files) and record.get('file_count') == len(files), 'archive file count mismatch')
        for name, row in files.items():
            safe_path(name)
            require(name not in known, f'duplicate indexed member: {name}')
            known.add(name)
            require(type(row.get('size')) is int and row['size'] >= 0, f'invalid member size: {name}')
            require(re.fullmatch('[0-9a-f]{64}', row.get('sha256', '')) is not None,
                    f'invalid member digest: {name}')
    return records


@contextmanager
def payload(source, archive):
    if archive.name.endswith('.zst'):
        with subprocess.Popen(['zstd', '-qdc'], stdin=source, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as process:
            try:
                yield process.stdout
                process.stdout.read()
                error = process.stderr.read()
                require(process.wait() == 0, f'zstd failed: {error.decode(errors="replace")}')
            except BaseException:
                process.kill()
                raise
    else:
        yield source


def restore(index, archive, destination, members):
    records = archive_records(index)
    requested = set(members)
    require(bool(requested) and len(requested) == len(members), 'select distinct --member paths')
    for name in requested:
        safe_path(name)
    require(not destination.exists() and not destination.is_symlink(), 'destination must not exist')
    require(destination.parent.is_dir(), 'destination parent must exist')
    with archive.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
        matching = [row for row in records if row['archive_sha256'] == digest]
        require(len(matching) == 1, 'archive SHA-256 is not uniquely recorded in the index')
        record = matching[0]
        require(requested <= record['files'].keys(), 'selected member is not in this archive')
        source.seek(0)
        with tempfile.TemporaryDirectory(prefix='.evidence-restore-', dir=destination.parent) as temporary:
            staging = Path(temporary) / 'restored'
            staging.mkdir()
            actual = set()
            with payload(source, archive) as stream:
                with tarfile.open(fileobj=stream, mode='r|*') as bundle:
                    for member in bundle:
                        safe_path(member.name)
                        require(member.isfile() and not member.issym() and not member.islnk(),
                                f'non-regular archive member: {member.name}')
                        require(member.name not in actual, f'duplicate archive member: {member.name}')
                        actual.add(member.name)
                        require(member.name in record['files'], f'unindexed archive member: {member.name}')
                        row = record['files'][member.name]
                        require(member.size == row['size'], f'member size mismatch: {member.name}')
                        target = staging.joinpath(*PurePosixPath(member.name).parts)
                        selected = member.name in requested
                        if selected:
                            target.parent.mkdir(parents=True, exist_ok=True)
                        hasher = hashlib.sha256()
                        with bundle.extractfile(member) as content:
                            if selected:
                                with target.open('xb') as output:
                                    while block := content.read(1024 * 1024):
                                        hasher.update(block)
                                        output.write(block)
                            else:
                                hasher = hashlib.file_digest(content, 'sha256')
                        require(hasher.hexdigest() == row['sha256'], f'member digest mismatch: {member.name}')
            require(actual == record['files'].keys(), 'archive is missing indexed members')
            # No output survives validation failure; an existing destination is never replaced.
            require(not destination.exists() and not destination.is_symlink(), 'destination appeared during restore')
            destination.mkdir()
            for child in staging.iterdir():
                shutil.move(str(child), destination / child.name)
    return {'archive_sha256': digest, 'verified_members': len(actual),
            'restored_members': sorted(requested), 'destination': str(destination)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index', type=Path, default=INDEX)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--member', action='append', required=True)
    args = parser.parse_args()
    try:
        result = restore(json.loads(args.index.read_text()), args.archive, args.destination, args.member)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        parser.exit(1, f'evidence restore failed: {error}\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
