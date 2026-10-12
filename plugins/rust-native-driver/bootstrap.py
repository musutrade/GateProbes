#!/usr/bin/env python3
"""Build the pinned development driver in a fresh directory in this checkout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
COMMIT = '8bab26f4f68e0e26f0bb7960be334d5b520ea452'
DIST = 'rustc-dev-1.97.1-x86_64-unknown-linux-gnu'
URL = 'https://static.rust-lang.org/dist/2026-07-16/' + DIST + '.tar.xz'
SHA = '0109304e1995cce9e3362208f5d4ec0944e52a2ddfbc0a85d4ce5bea5d3081ab'


def overlay(source, target):
    if source.is_dir():
        target.mkdir(exist_ok=True)
        for child in source.iterdir():
            overlay(child, target / child.name)
    else:
        if target.is_symlink():
            target.unlink()
        target.symlink_to(source.resolve())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sysroot', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--archive', type=Path, help='Previously downloaded official archive; SHA is always checked')
    args = parser.parse_args()
    destination, sysroot = args.output.resolve(), args.sysroot.resolve()
    if not destination.is_relative_to(ROOT) or destination == ROOT:
        raise ValueError('output must be a fresh directory within this checkout')
    version = subprocess.check_output([sysroot / 'bin/rustc', '-vV'], text=True)
    if 'commit-hash: ' + COMMIT not in version:
        raise ValueError('incompatible compiler: ' + version)
    destination.mkdir(parents=True, exist_ok=False)
    archive = destination / (DIST + '.tar.xz')
    if args.archive:
        shutil.copyfile(args.archive, archive)
    else:
        with urllib.request.urlopen(URL, timeout=60) as source, archive.open('wb') as target:
            shutil.copyfileobj(source, target)
    with archive.open('rb') as source:
        actual = hashlib.file_digest(source, 'sha256').hexdigest()
    if actual != SHA:
        raise ValueError('rustc-dev archive hash mismatch: ' + actual)
    extracted = destination / 'extracted'
    with tarfile.open(archive) as bundle:
        bundle.extractall(extracted, filter='data')
    root = destination / 'sysroot'
    overlay(sysroot, root)
    overlay(extracted / DIST / 'rustc-dev/lib', root / 'lib')
    command = ['cargo', 'build', '--locked', '--manifest-path', str(Path(__file__).with_name('Cargo.toml'))]
    env = {'CARGO_TARGET_DIR': str(destination / 'build'), 'RUSTC_BOOTSTRAP': '1',
           'RUSTFLAGS': '--sysroot ' + str(root)}
    with (destination / 'build.stdout').open('wb') as out, (destination / 'build.stderr').open('wb') as err:
        result = subprocess.run(command, env=os.environ | env, stdout=out, stderr=err)
    (destination / 'bootstrap.json').write_text(json.dumps({'url': URL, 'sha256': SHA,
        'rustc': version, 'sysroot': str(sysroot), 'command': command, 'environment': env,
        'exit_code': result.returncode}, indent=2) + '\n')
    if result.returncode:
        raise RuntimeError('driver build failed; see ' + str(destination / 'build.stderr'))
    print(destination / 'build/debug/harness-gate-rust-native-driver')


if __name__ == '__main__':
    main()
