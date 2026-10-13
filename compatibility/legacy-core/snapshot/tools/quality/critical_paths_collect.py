#!/usr/bin/env python3
"""Collect fresh LLVM profiles from one exact nextest identity per path."""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import time
import subprocess
import tomllib
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from critical_paths import (INVENTORY, POLICY, RULE, platform_for, require_committed_sources,
                            source_identity, validate_inventory)
from production_coverage import require
from quality_common import CRATE, ROOT, git_sha, metadata, sha256, write_json

# Failed collections retain their build tree for diagnosis. A build tree is large
# (instrumented deps + test binaries), so keep only the newest few and reclaim the
# rest before the next collection starts.
RETAIN_FAILED_BUILDS = 3


def prune_old_builds() -> None:
    root = ROOT / 'target/critical-path-build'
    if not root.is_dir():
        return
    kept = sorted((entry for entry in root.iterdir() if entry.is_dir()),
                  key=lambda entry: entry.stat().st_mtime, reverse=True)
    for entry in kept[RETAIN_FAILED_BUILDS:]:
        shutil.rmtree(entry, ignore_errors=True)


def collect(evidence: Path, jobs: int = 2) -> None:
    require(1 <= jobs <= 8, "critical-path jobs must be between 1 and 8")
    prune_old_builds()
    lock = ROOT / 'target/critical-path-collection.lock'
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        lock.mkdir()
    except FileExistsError as error:
        raise ValueError(f'collection already active; inspect {lock}') from error
    try:
        collect_locked(evidence, jobs)
    finally:
        lock.rmdir()


def collect_locked(evidence: Path, jobs: int = 2) -> None:
    started = time.monotonic()
    inventory = tomllib.loads(INVENTORY.read_text())
    policy = json.loads(POLICY.read_text())
    validate_inventory(inventory, policy)
    meta = metadata()
    for tool in ('nextest', 'llvm-cov'):
        meta[tool] = subprocess.check_output(['cargo', tool, '--version'], text=True).strip()
    identity = {'commit': git_sha(), 'target': meta['target'], 'rule': RULE}
    require_committed_sources(identity['commit'])
    before = source_identity(CRATE)
    evidence = evidence.resolve()
    evidence.parent.mkdir(parents=True, exist_ok=True)
    # Remove only the old declaration; retain all raw evidence, including failures.
    evidence.unlink(missing_ok=True)
    bundle = {'identity': identity, 'source_root': str(CRATE), 'sources': before,
              'inventory_sha256': hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest(),
              'tools': meta, 'runs': {}}
    # A fresh collection owns its build tree; no ambient coverage job can clean it.
    build = ROOT / 'target/critical-path-build' / str(uuid.uuid4())
    build.mkdir(parents=True)
    environment = dict(os.environ)
    for key in list(environment):
        if (key.startswith(('CARGO_LLVM_COV', '__CARGO_LLVM_COV', 'LLVM_PROFILE')) or
                key in ('CARGO_BUILD_TARGET', 'CARGO_BUILD_BUILD_DIR', 'RUSTFLAGS',
                        'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER')):
            environment.pop(key, None)
    environment.update(CARGO_TARGET_DIR=str(build), CARGO_LLVM_COV_TARGET_DIR=str(build),
                       CARGO_LLVM_COV_BUILD_DIR=str(build), CARGO_BUILD_TARGET=identity['target'],
                       NEXTEST_EXPERIMENTAL_LIBTEST_JSON='1')
    manifest = ['--manifest-path', str(CRATE / 'Cargo.toml')]
    setup = evidence.parent / ('build-' + build.name)
    setup.mkdir()
    tick = time.monotonic()
    command(['cargo', 'llvm-cov', 'show-env', *manifest], environment, setup, 'environment')
    # Parse assignments as data; never execute shell output. show-env's default
    # form is one bare `KEY=VALUE` per line (no `export` prefix or `;` terminator);
    # reject the shell-export variant explicitly instead of misparsing it.
    raw = (setup / 'environment.stdout').read_text()
    require(not any(';' in line or line.startswith(('export', 'set ', 'setenv'))
                    for line in raw.splitlines()),
            'unexpected shell-form coverage environment; expected bare KEY=VALUE lines')
    for assignment in shlex.split(raw):
        key, separator, value = assignment.partition('=')
        require(bool(separator) and key.isidentifier(), 'invalid coverage environment assignment')
        environment[key] = value
    command(['cargo', 'metadata', *manifest, '--format-version', '1', '--locked'],
            environment, setup, 'cargo-metadata')
    command(['cargo', 'nextest', 'list', *manifest, '--locked', '--list-type',
             'binaries-only', '--message-format', 'json'], environment, setup, 'binaries-metadata')
    bundle['build'] = {'directory': str(build), 'seconds': time.monotonic() - tick,
                      'metadata_directory': setup.name}
    rows = [row for row in inventory['paths']
            if platform_for(identity['target']) in row['platforms']]
    # Only tests overlap. Report/clean commands remain serialized on the owned
    # build tree. Every test (including child CLIs) writes to a fresh private root.
    tick = time.monotonic()
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = [pool.submit(run_test, row, identity, evidence.parent, setup, environment)
                   for row in rows]
        results = [future.result() for future in futures]
    bundle['test_seconds'] = time.monotonic() - tick
    for row, (directory, run, run_environment) in zip(rows, results):
        require(run['test_exit'] == 0, f"{row['id']}: test failed; see {directory}")
        export_coverage(directory, run, run_environment, build, manifest)
        for kind, name in [('nextest', 'nextest.jsonl'), ('coverage', 'coverage.json')]:
            run[kind] = {'path': f"{run['run_id']}/{name}", 'sha256': sha256(directory / name),
                         'identity': identity, 'run_id': run['run_id']}
        bundle['runs'][row['id']] = run
        write_json(directory / 'run.json', run)
        print(f"collected {row['id']}", flush=True)
    bundle['jobs'] = jobs
    require(before == source_identity(CRATE) and identity['commit'] == git_sha(), 'source/commit changed during collection')
    require_committed_sources(identity['commit'])
    # Successful evidence is self-contained; do not accumulate a full build per run.
    # Failed collections keep their build tree for diagnosis (bounded by prune_old_builds).
    shutil.rmtree(build)
    bundle['collection_seconds'] = time.monotonic() - started
    write_json(evidence, bundle)


def command(argv: list[str], environment: dict, directory: Path, name: str,
            stdout_name: str | None = None, *, check: bool = True) -> int:
    started = time.monotonic()
    with (directory / (stdout_name or f'{name}.stdout')).open('w') as stdout, \
            (directory / f'{name}.log').open('w') as stderr:
        code = subprocess.run(argv, cwd=ROOT, env=environment, stdout=stdout, stderr=stderr).returncode
    write_json(directory / f'{name}.command.json',
               {'argv': argv, 'exit_code': code, 'seconds': time.monotonic() - started})
    if check:
        require(code == 0, f'{name}: command failed ({code}); see {directory}')
    return code


def run_test(row: dict, identity: dict, parent: Path, setup: Path, environment: dict):
    run_id = str(uuid.uuid4())
    directory = parent / run_id
    directory.mkdir()
    profiles = directory / 'profiles'
    profiles.mkdir()
    run_environment = dict(environment, LLVM_PROFILE_FILE=str(profiles / '%p-%m.profraw'))
    test_filter = f"binary(={row['binary']}) & test(={row['test']})"
    argv = ['cargo', 'nextest', 'run', '--cargo-metadata', str(setup / 'cargo-metadata.stdout'),
            '--binaries-metadata', str(setup / 'binaries-metadata.stdout'),
            '-E', test_filter, '--test-threads', '1', '--retries', '0',
            '--message-format', 'libtest-json-plus', '--message-format-version', '0.1']
    run = {'identity': identity, 'run_id': run_id, 'binary': row['binary'], 'test': row['test'],
           'commands': [argv], 'observable': row['observable'], 'assertions': row['assertions']}
    write_json(directory / 'run.json', run)
    run['test_exit'] = command(argv, run_environment, directory, 'test', 'nextest.jsonl', check=False)
    write_json(directory / 'run.json', run)
    return directory, run, run_environment


def export_coverage(directory: Path, run: dict, environment: dict, build: Path, manifest: list[str]):
    # cargo-llvm-cov merges root-level profiles. Stage just this completed test's
    # profiles; preserve originals for diagnostics and never clean test binaries.
    profiles = sorted((directory / 'profiles').glob('*.profraw'))
    require(bool(profiles), f'no fresh profiles: {directory}')
    clean = ['cargo', 'llvm-cov', 'clean', '--profraw-only', *manifest]
    report = ['cargo', 'llvm-cov', 'report', *manifest, '--json', '--output-path',
              str(directory / 'coverage.json')]
    run['commands'].extend([clean, report])
    run['clean_exit'] = command(clean, environment, directory, 'clean', check=False)
    write_json(directory / 'run.json', run)
    require(run['clean_exit'] == 0, f'profile clean failed: {directory}')
    staged = []
    try:
        for profile in profiles:
            target = build / profile.name
            require(not target.exists(), f'foreign profile in report directory: {target}')
            shutil.copyfile(profile, target)
            staged.append(target)
        run['coverage_exit'] = command(report, environment, directory, 'report', check=False)
        write_json(directory / 'run.json', run)
        require(run['coverage_exit'] == 0, f'coverage export failed: {directory}')
    finally:
        for target in staged:
            target.unlink()
