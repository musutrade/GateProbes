#!/usr/bin/env python3
"""Local capture host: snapshot inputs, run tests, retain native objects/counters.

This command does not sign requests or approve a quality verdict. An external
trusted host must authorize its bundle before production collection.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tomllib
import uuid
from plugin import COLLECTOR, TYPES, canonical, discover, inventory, series, sha
from measure import source_inventories, target_configuration


FORBIDDEN_BUILD_KEYS = {
    'rustc', 'rustc-wrapper', 'rustc-workspace-wrapper', 'rustdoc',
    'target', 'rustflags', 'rustdocflags', 'linker', 'runner',
}
FORBIDDEN_ENV_KEYS = {
    'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET',
    'CARGO_BUILD_RUSTFLAGS', 'CARGO_BUILD_RUSTC', 'CARGO_BUILD_RUSTC_WRAPPER',
    'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTDOC',
    'CARGO_BUILD_RUSTDOCFLAGS', 'RUSTC', 'RUSTC_WRAPPER',
    'RUSTC_WORKSPACE_WRAPPER', 'RUSTUP_TOOLCHAIN',
}


def host_target(cwd):
    version = subprocess.check_output(['rustc', '-vV'], cwd=cwd, text=True)
    return next(line.removeprefix('host: ') for line in version.splitlines() if line.startswith('host: '))


def compiler_configuration(target, cwd):
    values = sorted(set(subprocess.check_output(
        ['rustc', '--print', 'cfg', '--target', target], cwd=cwd, text=True).splitlines()))
    return target_configuration({'target': target, 'cfg': values})


def rustc_version(cwd):
    return subprocess.check_output(['rustc', '-vV'], cwd=cwd, text=True).strip()


def validate_environment(repo):
    for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET', 'CARGO_BUILD_RUSTFLAGS',
                 'CARGO_BUILD_RUSTC', 'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER',
                 'CARGO_BUILD_RUSTDOC', 'CARGO_BUILD_RUSTDOCFLAGS',
                 'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'):
        if os.environ.get(name):
            raise ValueError(f'unsupported environment variable for capture: {name}')
    for name in os.environ:
        if name.startswith('CARGO_TARGET_') and name.endswith('_RUSTFLAGS'):
            raise ValueError(f'unsupported environment variable for capture: {name}')


def configuration_sources(repo, root):
    paths = set()
    for base in (repo, root, *root.parents):
        paths.add(base / '.cargo/config.toml')
        paths.add(base / '.cargo/config')
    cargo_home = Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo')).resolve()
    paths.add(cargo_home / 'config.toml')
    paths.add(cargo_home / 'config')
    return sorted(path for path in paths if path.is_file())


def validate_configuration(repo, root):
    for path in configuration_sources(repo, root):
        text = path.read_text()
        if path.name.endswith('.toml'):
            data = tomllib.loads(text)
            build = data.get('build', {})
            forbidden = FORBIDDEN_BUILD_KEYS & set(build)
            if forbidden:
                raise ValueError(f'unsupported build configuration in {path}: {sorted(forbidden)}')
            for target, values in data.get('target', {}).items():
                forbidden = FORBIDDEN_BUILD_KEYS & set(values)
                if forbidden:
                    raise ValueError(f'unsupported target configuration in {path} ({target}): {sorted(forbidden)}')
            for key in data.get('env', {}):
                if key in FORBIDDEN_ENV_KEYS or (key.startswith('CARGO_TARGET_') and key.endswith('_RUSTFLAGS')):
                    raise ValueError(f'unsupported environment override in {path}: {key}')
        elif any(token in text for token in (*FORBIDDEN_BUILD_KEYS, *FORBIDDEN_ENV_KEYS)):
            raise ValueError(f'unsupported Cargo configuration in {path}')


def validate_effective_cfg_sources(repo, root):
    manifests = set()
    for base in (repo, root):
        for path in base.rglob('Cargo.toml'):
            if not any(part in {'.git', 'target'} for part in path.parts):
                manifests.add(path)
    disabled_build = set()
    for path in sorted(manifests):
        try:
            data = tomllib.loads(path.read_text())
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise ValueError(f'invalid Cargo manifest for effective cfg: {path}: {error}') from error
        package = data.get('package', {})
        if not isinstance(package, dict):
            raise ValueError(f'invalid package table for effective cfg: {path}')
        build = package.get('build')
        if build is False:
            disabled_build.add(path.parent.resolve())
            continue
        if build is not None:
            if isinstance(build, str) and build:
                raise ValueError(f'unsupported custom build script for effective cfg: {path}')
            raise ValueError(f'invalid package.build for effective cfg: {path}')
    for base in (repo, root):
        for path in base.rglob('build.rs'):
            if any(part in {'.git', 'target'} for part in path.parts):
                continue
            if path.parent.resolve() not in disabled_build:
                raise ValueError(f'unsupported build script for effective cfg: {path}')


def validate_toolchain(repo, root):
    repository_version = rustc_version(repo)
    snapshot_version = rustc_version(root)
    if repository_version != snapshot_version:
        raise ValueError('rustc version differs between repository and snapshot cwd')
    return snapshot_version


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, required=True)
    parser.add_argument('--manifest', default='Cargo.toml')
    parser.add_argument('--source-root', action='append', required=True)
    parser.add_argument('--input', action='append', required=True, help='file/directory to snapshot, including all build/test/migration inputs')
    parser.add_argument('--test', action='append', default=[])
    parser.add_argument('--target')
    args = parser.parse_args()
    repo = args.repository.resolve(strict=True)
    validate_environment(repo)
    out = args.output.absolute()
    out.mkdir(mode=0o700)
    root = out / 'workspace'
    root.mkdir()
    inputs = {}
    for name in args.input:
        path = repo / name
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(repo):
            raise ValueError('input escapes repository')
        candidates = sorted(path.rglob('*')) if path.is_dir() else [path]
        for p in candidates:
            if p.is_symlink():
                raise ValueError('symlink build input')
            if not p.is_file():
                continue
            relative = p.relative_to(repo)
            if str(relative) in inputs:
                raise ValueError('overlapping input roots')
            data = p.read_bytes()
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            inputs[str(relative)] = sha(data)
    (root / '.local-capture-snapshot').write_text('backend-source-only rehearsal\n')
    validate_configuration(repo, root)
    validate_effective_cfg_sources(repo, root)
    target_triple = args.target or host_target(root)
    target_cfg = compiler_configuration(target_triple, root)
    validate_toolchain(repo, root)
    # Inspect the same immutable input snapshot that will be compiled. Cheap
    # syntax/Serde failures must be reported together before cargo is started.
    sources = inventory({'workspace_root': str(root),
                         'parameters': {'source_roots': args.source_root}})
    source_inventories(root, list(sources), Path(__file__).resolve().parent / 'inventory', target_cfg)
    env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir.absolute()))
    command = ['cargo', 'llvm-cov', '--manifest-path', str(root / args.manifest), '--locked', '--json', '--output-path', str(out / 'cargo-coverage.json'), '--target', target_triple, '--verbose']
    for test in args.test:
        command += ['--test', test]
    with (out / 'capture.stdout').open('wb') as stdout, (out / 'capture.stderr').open('wb') as stderr:
        subprocess.run(command, env=env, cwd=root, stdout=stdout, stderr=stderr, check=True)
    exports = [shlex.split(line.strip()[len('Running `'):-1]) for line in (out / 'capture.stderr').read_text().splitlines()
               if line.strip().startswith('Running `') and '/llvm-cov export ' in line]
    if len(exports) != 1:
        raise ValueError('expected one native LLVM export invocation')
    export = exports[0]
    objects = [Path(export[i+1]) for i, arg in enumerate(export) if arg == '-object']
    profdata = Path(next(arg.split('=', 1)[1] for arg in export if arg.startswith('-instr-profile=')))
    profiles = sorted(profdata.parent.rglob('*.profraw'))
    raw = out / 'raw'
    raw.mkdir()
    retained = {}
    groups = {}
    for kind, paths in [('objects', objects), ('profiles', profiles)]:
        groups[kind] = []
        for i, p in enumerate(paths):
            name = f'{kind}-{i}-{p.name}'
            shutil.copyfile(p, raw / name)
            retained[name] = sha((raw / name).read_bytes())
            groups[kind].append(name)
    tools = {}
    for name in ('llvm-cov', 'llvm-profdata'):
        p = Path(export[0]).with_name(name)
        tools[name] = {'path': str(p), 'sha256': sha(p.read_bytes()), 'version': subprocess.check_output([p, '--version'], text=True).strip()}
    tools['rustc'] = rustc_version(root)
    tools['cargo-llvm-cov'] = subprocess.check_output(['cargo', 'llvm-cov', '--version'], cwd=root, text=True).strip()
    config = {p: h for p, h in inputs.items() if p.endswith(('Cargo.toml', 'Cargo.lock')) or p.startswith('.cargo/')}
    revision = subprocess.check_output(['git', '-C', repo, 'rev-parse', 'HEAD'], text=True).strip()
    request = {'schema': 'harness-collector-request/v1', 'project': 'codexsymphony', 'component': 'backend',
               'collector': COLLECTOR, 'context': {'commit': revision, 'base_commit': revision, 'run': 'rust-source-' + uuid.uuid4().hex, 'target': target_triple},
               'requested_capabilities': sorted(TYPES), 'workspace_root': str(root), 'output_root': str(root / 'evidence'),
               'parameters': {'source_roots': args.source_root, 'boundary': 'production', 'artifact_subdir': 'backend-source'}}
    (root / 'evidence').mkdir()
    request['parameters']['receipt'] = {'schema': 'rust-source-capture/v1', 'context': request['context'], 'coverage_root': str(root),
                                         'sources': inventory(request), 'inputs': inputs,
                                         'pipeline': {'files': config, 'tools': tools, 'tests': args.test, 'manifest': args.manifest, 'capture': 'cargo-llvm-cov-locked/v1', 'target_cfg': target_cfg},
                                         'raw_root': str(raw), 'raw': retained, **groups}
    request['parameters']['subjects'] = discover(request)
    bundle = {'request': request, 'series': series(request)}
    (out / 'bundle.json').write_text(canonical(bundle) + '\n')
    print(canonical({'bundle': str(out / 'bundle.json'), 'subjects': len(request['parameters']['subjects']), 'series': bundle['series']['id']}))

if __name__ == '__main__':
    try:
        main()
    except ValueError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
