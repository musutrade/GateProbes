#!/usr/bin/env python3
"""Assemble a pinned local Linux runtime candidate; never publish or certify ABI.

Inputs are a reviewed JSON lock produced with --inventory. Building requires that
lock and checks every input byte. No download or global toolchain mutation occurs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parent
MODULES = ('rust_collector_entry', 'rust_native_driver', 'rust_native_classify', 'rust_collector_contract',
           'rust_collector_project', 'rust_collector_delivery', 'collector_runner', 'harness_evidence',
           'project_model', 'quality_evidence')
# Host contracts live in the repository schema root but install under app/schema.
HOST_SCHEMA_FILES = {'collector-protocol.schema.json': 'app/schema/collector-protocol.schema.json'}
HOST_LIBS = {'libc.so.6', 'libm.so.6', 'libpthread.so.0', 'libdl.so.2',
             'librt.so.1', 'ld-linux-x86-64.so.2'}


def sha(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def inventory(driver, sysroot, crate_cache, rustc_dev, build_record):
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('only the observed Linux x86_64 host is supported')
    files, build_inputs, crates = {}, {}, []

    def pin(path):
        path = Path(path).resolve(strict=True)
        build_inputs[str(path)] = sha(path)
        return path

    pin(Path(__file__))
    pin(rustc_dev)
    if sha(rustc_dev) != '0109304e1995cce9e3362208f5d4ec0944e52a2ddfbc0a85d4ce5bea5d3081ab':
        raise ValueError('wrong compiler-private archive')
    pin(build_record)
    tree_source = ROOT / 'rust-native-driver'
    for path in sorted(tree_source.rglob('*')):
        if path.is_file() and 'target' not in path.relative_to(tree_source).parts:
            pin(path)

    def add(source, destination):
        source = Path(source).resolve(strict=True)
        if destination in files and files[destination]['sha256'] != sha(source):
            raise ValueError('conflicting runtime library: ' + destination)
        files[destination] = {'source': str(source), 'sha256': sha(source),
                              'mode': 0o755 if source.stat().st_mode & 0o111 else 0o644}

    def tree(source, destination, predicate=lambda p: True):
        for path in sorted(Path(source).rglob('*')):
            if path.is_file() and predicate(path):
                add(path, destination + '/' + str(path.relative_to(source)))

    add(sys.executable, 'python/bin/python3')
    stdlib = Path(sysconfig.get_path('stdlib'))
    tree(stdlib, 'python/lib/' + stdlib.name,
         lambda p: p.suffix == '.py' and not ({'__pycache__', 'site-packages', 'dist-packages', 'test', 'tests', 'ensurepip', 'idlelib', 'tkinter'} & set(p.relative_to(stdlib).parts)))
    for name in MODULES:
        __import__(name)
        add(ROOT / (name + '.py'), 'app/' + name + '.py')
    # Extension allowlist is measured from the complete supported module import
    # graph; optional interactive/network/database Python tools are not shipped.
    extensions = sorted({m.__file__ for m in sys.modules.values()
                         if getattr(m, '__file__', None) and m.__file__.endswith('.so')})
    for name in extensions:
        add(name, 'python/lib/' + stdlib.name + '/lib-dynload/' + Path(name).name)
    tree(ROOT / 'schema', 'app/schema')
    for filename, destination in HOST_SCHEMA_FILES.items():
        add(ROOT.parents[1] / 'schema' / filename, destination)
    for name in ('harness-gate-rust-collector', 'native-wrapper', 'pkg-config'):
        add(ROOT / 'rust-collector-runtime' / name, 'bin/' + name)
    add(ROOT / 'rust-collector-runtime/native_wrapper.py', 'app/native_wrapper.py')
    add(ROOT / 'rust-collector-runtime/cc', 'bin/cc')
    # Cargo dependencies compile C as well as link Rust. Ship the compiler,
    # assembler and headers instead of depending on a host C toolchain.
    add('/usr/bin/cc', 'link/bin/gcc')
    add('/usr/bin/ld.bfd', 'link/gcc/ld')
    add('/usr/bin/as', 'link/gcc/as')
    for name in ('ar', 'ranlib'):
        add('/usr/bin/' + name, 'bin/' + name)
    add('/usr/bin/pkgconf', 'link/bin/pkgconf')
    for name in ('cc1', 'collect2', 'lto-wrapper', 'liblto_plugin.so', 'lto1'):
        add('/usr/libexec/gcc/x86_64-linux-gnu/15/' + name, 'link/gcc/' + name)
    tree('/usr/lib/gcc/x86_64-linux-gnu/15/include', 'link/gcc/include')
    for package in ('libc6-dev', 'linux-libc-dev', 'libssl-dev'):
        for name in command('dpkg-query', '-L', package).splitlines():
            path = Path(name)
            if path.is_file() and (path.is_relative_to('/usr/include') or name.endswith('.pc')):
                add(path, 'link/sysroot' + name)
    for name in ('libssl', 'libcrypto'):
        add('/usr/lib/x86_64-linux-gnu/' + name + '.so',
            'link/sysroot/usr/lib/x86_64-linux-gnu/' + name + '.so')
        for directory in ('lib', 'rust/lib'):
            add('/usr/lib/x86_64-linux-gnu/' + name + '.so.3', directory + '/' + name + '.so.3')
    tree('/usr/lib/gcc/x86_64-linux-gnu/15', 'link/gcc',
         lambda p: p.suffix in ('.o', '.a', '.so'))
    for name in ('Scrt1.o', 'crt1.o', 'crti.o', 'crtn.o', 'libc.so',
                 'libc.so.6', 'libc_nonshared.a', 'libm.so', 'libm.so.6',
                 'libmvec.so.1', 'libgcc_s.so.1', 'libpthread.a', 'libdl.a', 'librt.a', 'libutil.a'):
        add('/usr/lib/x86_64-linux-gnu/' + name,
            'link/sysroot/usr/lib/x86_64-linux-gnu/' + name)
    add('/lib64/ld-linux-x86-64.so.2', 'link/sysroot/lib64/ld-linux-x86-64.so.2')
    add(driver, 'bin/harness-gate-rust-native-driver')
    for name in ('rustc', 'cargo'):
        add(sysroot / 'bin' / name, 'rust/bin/' + name)
    for path in (sysroot / 'lib').glob('*.so*'):
        add(path, 'rust/lib/' + path.name)
    tree(sysroot / 'lib/rustlib/x86_64-unknown-linux-gnu/lib', 'rust/lib/rustlib/x86_64-unknown-linux-gnu/lib')
    for name in ('llvm-cov', 'llvm-profdata', 'rust-lld', 'gcc-ld/ld.lld'):
        add(sysroot / 'lib/rustlib/x86_64-unknown-linux-gnu/bin' / name,
            'rust/lib/rustlib/x86_64-unknown-linux-gnu/bin/' + name)
    tree(sysroot / 'share/doc/rust', 'licenses/rust', lambda p: 'html' not in p.relative_to(sysroot / 'share/doc/rust').parts)
    tree(sysroot / 'share/doc/cargo', 'licenses/cargo')
    add(ROOT.parents[1] / 'LICENSE', 'licenses/harness-gate/LICENSE')
    for package in tomllib.loads((tree_source / 'Cargo.lock').read_text())['package']:
        if 'checksum' not in package:
            continue
        name = package['name'] + '-' + package['version']
        archive = pin(crate_cache / (name + '.crate'))
        if sha(archive) != package['checksum']:
            raise ValueError('crate checksum mismatch: ' + name)
        # Retain the complete original crate, including its license and build
        # source. The lock checksum covers notices as well as compiled source.
        add(archive, 'licenses/crates/' + archive.name)
        with tarfile.open(archive) as source:
            metadata = tomllib.loads(source.extractfile(name + '/Cargo.toml').read().decode())
            notices = [p.name for p in source.getmembers()
                       if p.isfile() and ('LICENSE' in p.name or 'COPYING' in p.name)]
        if not metadata['package'].get('license') or not notices:
            raise ValueError('missing crate license closure: ' + name)
        crates.append({'name': name, 'sha256': package['checksum'],
                       'license': metadata['package']['license'], 'notices': notices})
    packages = {}
    for package in ('python3.14', 'python3.14-minimal', 'gcc-15-base',
                    'gcc-15-x86-64-linux-gnu', 'libgcc-15-dev', 'binutils-x86-64-linux-gnu',
                    'libc6-dev', 'libc6', 'linux-libc-dev', 'libssl-dev', 'pkgconf-bin'):
        add('/usr/share/doc/' + package + '/copyright', 'licenses/' + package + '/copyright')
        packages[package] = command('dpkg-query', '-W', '-f=${Version}', package)
    tree('/usr/share/common-licenses', 'licenses/common')
    dependencies, host = {}, {'launcher-shell': {'source': str(Path('/bin/sh').resolve()),
                                                'sha256': sha('/bin/sh')}}
    pending = list(files.values())
    seen = set()
    while pending:
        row = pending.pop()
        path = Path(row['source'])
        if path in seen:
            continue
        seen.add(path)
        with path.open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                continue
        env = os.environ | {'LD_LIBRARY_PATH': str(sysroot / 'lib')}
        result = subprocess.run(['ldd', str(path)], env=env, capture_output=True, text=True)
        if result.returncode and 'not a dynamic executable' not in result.stderr:
            raise ValueError('ldd failed: ' + str(path) + ': ' + result.stderr)
        dependencies[str(path)] = result.stdout
        for line in result.stdout.splitlines():
            if 'not found' in line:
                raise ValueError('unresolved runtime dependency: ' + line)
            words = line.split()
            if not words or words[0] == 'linux-vdso.so.1':
                continue
            name = Path(words[0]).name
            resolved = words[2] if len(words) > 2 and words[1] == '=>' else words[0]
            if not resolved.startswith('/'):
                continue
            if name in HOST_LIBS:
                host[name] = {'source': resolved, 'sha256': sha(resolved)}
            elif Path(resolved).is_relative_to(sysroot):
                continue
            else:
                add(resolved, 'lib/' + name)
                # Native legacy subprocesses explicitly select sysroot/lib.
                # Preserve that behavior without falling back to host libraries.
                add(resolved, 'rust/lib/' + name)
                pending.append(files['lib/' + name])
                owner = command('dpkg-query', '-S', str(Path(resolved).resolve())).split(': ')[0].split(':')[0]
                packages[owner] = command('dpkg-query', '-W', '-f=${Version}', owner)
                add('/usr/share/doc/' + owner + '/copyright', 'licenses/' + owner + '/copyright')
    return {'schema': 'rust-collector-build-inputs/1', 'python': sys.version,
            'rustc': command(str(sysroot / 'bin/rustc'), '-vV'),
            'host': {'system': platform.system(), 'machine': platform.machine(),
                     'kernel': platform.release(), 'glibc': os.confstr('CS_GNU_LIBC_VERSION'),
                     'libraries': host},
            'packages': packages, 'crates': crates, 'build_inputs': build_inputs,
            'extensions': extensions, 'ldd': dependencies,
            'files': dict(sorted(files.items()))}


def build(lock, output):
    if lock['schema'] != 'rust-collector-build-inputs/1':
        raise ValueError('unsupported build lock')
    if output.exists():
        raise ValueError('refusing to replace an existing build')
    # Validate all inputs before creating a partial destination.
    for name, expected in lock['build_inputs'].items():
        if sha(name) != expected:
            raise ValueError('changed build input: ' + name)
    for name in lock['files']:
        if Path(name).is_absolute() or any(p in ('', '.', '..') for p in name.split('/')):
            raise ValueError('unsafe payload name')
    for row in lock['files'].values():
        if sha(row['source']) != row['sha256']:
            raise ValueError('changed build input: ' + row['source'])
    for name, row in lock['files'].items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('unsafe payload name')
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(row['source'], target)
        target.chmod(row['mode'])
    # The assembly inventory is not a signed delivery manifest/compatibility receipt.
    payload = {name: {k: v for k, v in row.items() if k != 'source'} for name, row in lock['files'].items()}
    (output / 'runtime.json').write_text(json.dumps({'schema': 'rust-collector-runtime/1',
        'host': lock['host'], 'payload': payload}, sort_keys=True, indent=2) + '\n')
    (output / 'runtime.json').chmod(0o644)
    for path in [output, *output.rglob('*')]:
        if path.is_dir():
            path.chmod(0o755)
    with tarfile.open(str(output) + '.tar', 'w', format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(output.rglob('*')):
            info = archive.gettarinfo(str(path), arcname=str(path.relative_to(output)))
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ''
            info.pax_headers = {}
            if path.is_file():
                with path.open('rb') as source:
                    archive.addfile(info, source)
            else:
                archive.addfile(info)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', action='store_true')
    parser.add_argument('--driver', type=Path)
    parser.add_argument('--sysroot', type=Path)
    parser.add_argument('--crate-cache', type=Path)
    parser.add_argument('--rustc-dev', type=Path)
    parser.add_argument('--build-record', type=Path)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.inventory:
        if args.lock.exists():
            raise ValueError('refusing to overwrite build input lock')
        result = inventory(args.driver.resolve(strict=True), args.sysroot.resolve(strict=True),
                           args.crate_cache, args.rustc_dev, args.build_record)
        args.lock.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    else:
        build(json.loads(args.lock.read_text()), args.output)


if __name__ == '__main__':
    main()
