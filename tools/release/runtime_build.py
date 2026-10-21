"""Pinned Linux musl build inputs and static-PIE verification."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

TARGET = 'x86_64-unknown-linux-musl'
HOST = 'x86_64-unknown-linux-gnu'
TOOLCHAIN = '1.99.1'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_inputs(root):
    lock = json.loads((root / 'plugins/docker-runtime/native/build-inputs.json').read_text())
    if (lock['schema'], lock['target'], lock['toolchain']) != ('gateprobes-runtime-build/v1', TARGET, TOOLCHAIN):
        raise RuntimeError('unsupported runtime build identity')
    sysroot = Path(subprocess.check_output(['rustc', '+' + TOOLCHAIN, '--print', 'sysroot'], text=True).strip())
    version = subprocess.check_output(['rustc', '+' + TOOLCHAIN, '-vV'], text=True)
    if version != lock['rustc_verbose']:
        raise RuntimeError('runtime compiler identity changed')
    for relative, expected in lock['files'].items():
        path = Path(relative)
        if path.is_absolute() or '..' in path.parts or not path.parts:
            raise RuntimeError('unsafe runtime build input')
        if digest(sysroot / path) != expected:
            raise RuntimeError('runtime build input digest mismatch: ' + relative)
    libdir = sysroot / 'lib/rustlib' / TARGET / 'lib'
    actual = {str(p.relative_to(sysroot)) for p in libdir.rglob('*') if p.is_file()}
    declared = {p for p in lock['files'] if p.startswith(f'lib/rustlib/{TARGET}/lib/')}
    if actual != declared:
        raise RuntimeError('runtime target library set changed')
    return sysroot, lock


def environment(root, target, stage, sysroot):
    env = {k: v for k, v in os.environ.items() if not (
        k.startswith(('CARGO_PROFILE_', 'CARGO_TARGET_')) or k in
        ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'))}
    linker = sysroot / f'lib/rustlib/{HOST}/bin/rust-lld'
    flags = [f'-Clinker={linker}', '-Clink-self-contained=yes',
             f'--remap-path-prefix={root}=/gateprobes',
             f'--remap-path-prefix={target}=/target', f'--remap-path-prefix={stage}=/build']
    env.update(CARGO_TARGET_DIR=str(target), CARGO_INCREMENTAL='0', SOURCE_DATE_EPOCH='0',
               CARGO_ENCODED_RUSTFLAGS='\x1f'.join(flags))
    return env


def verify_static_pie(data):
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
        raise RuntimeError('invalid runtime ELF')
    if struct.unpack_from('<HH', data, 16) != (3, 62):
        raise RuntimeError('runtime must be x86_64 PIE')
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    if size != 56 or not count or offset + size * count > len(data):
        raise RuntimeError('invalid runtime program headers')
    relro = stack = False
    for index in range(count):
        kind, flags, start, _, _, length, _, _ = struct.unpack_from('<IIQQQQQQ', data, offset + index * size)
        if kind == 3:
            raise RuntimeError('runtime has a dynamic interpreter')
        if kind == 0x6474e552:
            relro = True
        if kind == 0x6474e551:
            if flags & 1:
                raise RuntimeError('runtime stack is executable')
            stack = True
        if kind == 2:
            if length % 16 or start + length > len(data):
                raise RuntimeError('invalid runtime dynamic section')
            for pos in range(start, start + length, 16):
                tag, _ = struct.unpack_from('<QQ', data, pos)
                if tag == 1:
                    raise RuntimeError('runtime has a needed shared library')
    if not (relro and stack):
        raise RuntimeError('runtime RELRO or NX stack missing')
