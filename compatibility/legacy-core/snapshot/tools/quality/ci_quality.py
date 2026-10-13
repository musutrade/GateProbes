#!/usr/bin/env python3
"""Required CI policy and fresh, review-only quality candidates (schema 1)."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time
import uuid

from critical_paths import require_committed_sources
from production_coverage import CoverageTokenizer, require
from quality_common import ROOT, git_sha, metadata, sha256, write_json
from source_measure import SOURCE_FILES, compiler_configuration

COMMON = ('classify', 'test', 'test-cross-platform', 'security-audit', 'fmt', 'clippy', 'build',
          'quality-coverage', 'quality-contracts', 'docs-consistency', 'release-contracts',
          'quality-scripts')
PUSH_ONLY = ('build-cross-platform', 'coverage',
             'quality-contracts-cross-platform', 'quality-baseline')
STAGES = ('legacy', 'production', 'risk', 'matrix')
# Rust integration tests and their Python oracles read these repository trees.
# Historical reports under docs/quality are not test inputs: archiving that
# directory duplicated hundreds of MB of compressed evidence for each side.
SNAPSHOT_PATHS = ('tools/harness-gate', 'tools/quality', 'schema', 'docs/dogfood')
REPLAY_RELOCATION = ('tools/harness-gate/quality-core/examples/differential_replay.rs',
                     'tools/harness-gate/quality-replay/examples/differential_replay.rs')
# Reviewed 2026-10-12: the Postgres recipe left service/postgres.rs for the
# measured recipes series (source_measure.SOURCE_FILES). The exemption covers
# only the confirmed deletion: it applies while the old path exists at base and
# is absent at head. Recreating or modifying the old path fails the measurement
# review. This records the reviewed removal only; it does not establish
# function-level continuity between old and new sources, which are measured as
# separate functions.
REVIEWED_REMOVED_SOURCES = ('tools/harness-gate/src/service/postgres.rs',)


def reviewed_removals(base: str, head: str) -> set[str]:
    """Exempt a reviewed removal only while the old path is actually gone."""
    removals = set()
    for path in REVIEWED_REMOVED_SOURCES:
        present = [
            subprocess.run(['git', 'cat-file', '-e', f'{commit}:{path}'],
                           cwd=ROOT, capture_output=True).returncode == 0
            for commit in (base, head)
        ]
        if present == [True, False]:
            removals.add(path)
    return removals
REQUIRED_ARTIFACTS = {'coverage.json', 'coverage.raw.json', 'coverage.lcov',
                      'coverage.cobertura.xml', 'production.json', 'risk.json',
                      'critical-paths.json', 'critical-path-runs/bundle.json'} | {
    f'{label}-{suffix}' for label in ('base', 'head') for suffix in (
        'source.tar', 'manifest.json', 'coverage.json', 'coverage.lcov',
        'coverage.cobertura.xml', 'risk.json')}
MEASURER_PIN = ROOT / 'tools/quality/rust-measure-release.json'
MEASURER_RELEASE_URL = 'https://github.com/musutrade/Harness-Gate/releases/download'


def load_measurer_pin() -> dict:
    """The analyzer is consumed as a pinned release artifact, never built here."""
    pin = json.loads(MEASURER_PIN.read_text())
    require(pin.get('schema') == 'rust-measure-release-pin/v1', 'unknown measurer pin schema')
    for field in ('release', 'asset', 'sha256', 'version', 'executable'):
        require(isinstance(pin.get(field), str) and pin[field], f'invalid measurer pin {field}')
    require(re.fullmatch(r'[0-9a-f]{64}', pin['sha256']) is not None, 'invalid measurer pin sha256')
    require(pin['asset'].startswith('harness-gate-rust-measure-' + pin['version'] + '-'),
            'measurer pin asset/version mismatch')
    return pin


def verify_measurer_asset(path: Path, pin: dict) -> None:
    require(sha256(path) == pin['sha256'], 'pinned measurer asset digest mismatch')


def ensure_measurer(cache: Path) -> Path:
    """Download, digest-verify, bound-check and extract the pinned measurer.

    The release archive is the only source of the analyzer. Extraction accepts
    regular files and directories strictly inside the single release root, so an
    archive can never write outside its cache directory, and the declared
    executable must exist with its executable bit set.
    """
    pin = load_measurer_pin()
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / pin['asset']
    if not archive.is_file() or sha256(archive) != pin['sha256']:
        subprocess.run(['curl', '--fail', '--show-error', '--location', '--proto', '=https',
                        '--tlsv1.2', '--retry', '3', '--retry-all-errors', '--output', str(archive),
                        f'{MEASURER_RELEASE_URL}/{pin["release"]}/{pin["asset"]}'], check=True)
    verify_measurer_asset(archive, pin)
    root = pin['asset'].removesuffix('.tar.gz')
    executable = cache / root / pin['executable']
    with tarfile.open(archive) as source:
        members = source.getmembers()
        require(bool(members), 'empty measurer release archive')
        for member in members:
            require(not member.name.startswith('/') and '..' not in Path(member.name).parts,
                    f'unsafe measurer archive member: {member.name}')
            require(member.isfile() or member.isdir(),
                    f'unsupported measurer archive member: {member.name}')
            require(member.name == root or member.name.startswith(root + '/'),
                    f'measurer archive member outside the release root: {member.name}')
        source.extractall(cache, filter='data')
    require(executable.is_file(), 'pinned measurer executable missing from the release archive')
    require(os.access(executable, os.X_OK), 'pinned measurer executable is not executable')
    return executable


def relocated_migration_sources(base: str, head: str) -> set[str]:
    """Recognize only the unchanged move of the unpublished replay executable."""
    old, new = REPLAY_RELOCATION
    change = subprocess.check_output(
        ['git', 'diff', '--name-status', '--find-renames=100%', base, head, '--', old, new],
        cwd=ROOT, text=True)
    return {old} if change == f'R100\t{old}\t{new}\n' else set()


def terminal_test_module_boundary(source: str) -> tuple[str, str] | None:
    """Retain every byte except one exact top-level terminal cfg(test) body."""
    # The fixture lexer does not implement Rust's special shebang/BOM handling.
    # Reject that boundary rather than letting ignored text spoof a test module.
    if source.startswith(('#!', '\ufeff')):
        return None
    tokens = CoverageTokenizer(source).tokenize()
    header = ['#', '[', 'cfg', '(', 'test', ')', ']', 'mod', 'tests', '{']
    stack, pairs, modules = [], {}, []
    for index, token in enumerate(tokens):
        if not stack and [t.text for t in tokens[index:index + len(header)]] == header:
            modules.append(index + len(header) - 1)
        if token.text in ('(', '[', '{'):
            stack.append(index)
        elif token.text in (')', ']', '}'):
            require(bool(stack), 'unbalanced Rust source')
            opening = stack.pop()
            require(tokens[opening].text == {')': '(', ']': '[', '}': '{'}[token.text],
                    'unbalanced Rust source')
            pairs[opening] = index
    require(not stack, 'unbalanced Rust source')
    if len(modules) != 1 or pairs[modules[0]] != len(tokens) - 1:
        return None
    opening, closing = tokens[modules[0]], tokens[pairs[modules[0]]]
    return source[:opening.offset + 1], source[closing.offset:]


def only_terminal_test_module_changed(base: str, head: str, path: str) -> bool:
    """Prove unchanged production source bytes, not macro/runtime equivalence."""
    try:
        snapshots = []
        for commit in (base, head):
            mode = subprocess.check_output(
                ['git', '--literal-pathspecs', 'ls-tree', '-z',
                 '--format=%(objectmode) %(objecttype)', commit, '--', path],
                cwd=ROOT, stderr=subprocess.PIPE)
            require(mode in (b'100644 blob\0', b'100755 blob\0'), 'not one regular source file')
            source = subprocess.check_output(['git', 'show', f'{commit}:{path}'],
                                             cwd=ROOT, stderr=subprocess.PIPE).decode('utf-8')
            snapshots.append((mode, terminal_test_module_boundary(source)))
        return snapshots[0][1] is not None and snapshots[0] == snapshots[1]
    except (OSError, UnicodeError, ValueError, subprocess.CalledProcessError):
        # Missing files, unsupported lexical forms and malformed input retain
        # the existing measurement-review failure, never a guessed exemption.
        return False


PURE_DOC_EXCLUDED_PREFIXES = ('docs/dogfood/', 'docs/benchmarks/', 'docs/quality/')


def is_pure_document(path: str) -> bool:
    """Only prose markdown. Fixtures, records, specs and ownership are inputs."""
    if not path.endswith('.md'):
        return False
    if '/' not in path:
        return True
    return path.startswith('docs/') and not path.startswith(PURE_DOC_EXCLUDED_PREFIXES)


def changed_paths(base: str, head: str) -> list[str]:
    output = subprocess.check_output(
        ['git', 'diff', '--name-status', '--find-renames', base, head], cwd=ROOT, text=True,
        stderr=subprocess.PIPE)
    paths = []
    for line in output.splitlines():
        parts = line.split('\t')
        if len(parts) >= 2 and parts[1]:
            paths.append(parts[1])
        if len(parts) >= 3 and parts[2]:
            paths.append(parts[2])
    return paths


def classify(base: str, head: str) -> dict:
    """Pure docs select light checks only; unknown or empty scope stays full."""
    if not base or not head or set(base) == {'0'}:
        return {'docs_only': False, 'run_full': True, 'files': 0}
    paths = changed_paths(base, head)
    docs_only = bool(paths) and all(is_pure_document(path) for path in paths)
    return {'docs_only': docs_only, 'run_full': not docs_only, 'files': len(paths)}


def aggregate(event: str, needs: dict, full: bool = True) -> list[str]:
    """Evaluate child outcomes only; never collect evidence or launch tools here."""
    require(event in ('push', 'pull_request'), 'unsupported CI event')
    require(isinstance(needs, dict), 'CI needs must be an object')
    required = COMMON + (PUSH_ONLY if event == 'push' else ())
    if full:
        return [name for name in required
                if not isinstance(needs.get(name), dict) or needs[name].get('result') != 'success']
    failures = []
    for name in required:
        entry = needs.get(name)
        result = entry.get('result') if isinstance(entry, dict) else None
        if name in ('classify', 'docs-consistency'):
            if result != 'success':
                failures.append(name)
        elif result not in ('skipped', 'success'):
            failures.append(name)
    return failures


def verify(path: Path, head: str, base: str, run_id: str) -> dict:
    report = json.loads(path.read_text())
    require(report['schema_version'] == 1 and report['candidate'] is True, 'invalid candidate schema')
    require((report['commit'], report['base_sha'], report['run_id']) == (head, base, run_id),
            'stale or mixed candidate identity')
    require(set(report['stages']) == set(STAGES), 'missing required evidence stage')
    require(all(s['status'] == 'success' for s in report['stages'].values()),
            'failed, cancelled, skipped or incomplete collection')
    require(REQUIRED_ARTIFACTS <= report['artifacts'].keys(), 'missing required raw evidence')
    for relative, digest in report['artifacts'].items():
        artifact = (path.parent / relative).resolve()
        require(artifact.is_relative_to(path.parent.resolve()), 'artifact escapes candidate')
        require(sha256(artifact) == digest, f'stale or modified artifact: {relative}')
    return report


class Collector:
    def __init__(self, directory: Path, base: str, head: str, run_id: str):
        self.directory = directory.resolve()
        require(not self.directory.exists(), 'candidate directory already exists; choose a fresh path')
        self.directory.mkdir(parents=True)
        self.environment = dict(os.environ)
        for key in ('LLVM_PROFILE_FILE', 'CARGO_BUILD_TARGET', 'CARGO_LLVM_COV_TARGET_DIR',
                    'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS'):
            self.environment.pop(key, None)
        self.environment['CARGO_TARGET_DIR'] = str(self.directory / 'build')
        self.report = {**metadata(), 'schema_version': 1, 'candidate': True,
                       'base_sha': base, 'commit': head, 'run_id': run_id,
                       'stages': {}, 'commands': [], 'artifacts': {}}
        self.save()

    def save(self):
        write_json(self.directory / 'candidate.json', self.report)

    def command(self, name: str, command: list[str], allowed=(0,)):
        started = time.monotonic()
        print(f'{name}: started (log: {name}.log)', flush=True)
        with (self.directory / f'{name}.log').open('w') as log:
            code = subprocess.run(command, cwd=ROOT, env=self.environment,
                                  stdout=log, stderr=subprocess.STDOUT).returncode
        self.report['commands'].append({'name': name, 'argv': command, 'exit_code': code,
                                        'seconds': time.monotonic() - started})
        self.save()
        print(f'{name}: exited {code} in {self.report["commands"][-1]["seconds"]:.2f}s', flush=True)
        require(code in allowed, f'{name} exited {code}; see {name}.log')

    def python(self, name: str, script: str, *args: str, allowed=(0,)):
        self.command(name, [sys.executable, str(ROOT / 'tools/quality' / script), *map(str, args)], allowed)

    def measurer(self) -> Path:
        """Download the pinned analyzer release artifact and verify its digest."""
        pin = load_measurer_pin()
        cache = self.directory / 'measurer'
        cache.mkdir(exist_ok=True)
        archive = cache / pin['asset']
        url = f'{MEASURER_RELEASE_URL}/{pin["release"]}/{pin["asset"]}'
        self.command('measurer-download', ['curl', '--fail', '--show-error', '--location',
                                           '--proto', '=https', '--tlsv1.2',
                                           '--output', str(archive), url])
        verify_measurer_asset(archive, pin)
        installed = cache / pin['asset'].removesuffix('.tar.gz')
        with tarfile.open(archive) as source:
            source.extractall(cache, filter='data')
        binary = installed / pin['executable']
        require(binary.is_file(), 'pinned measurer executable missing from archive')
        self.report['measurer'] = {'release': pin['release'], 'asset': pin['asset'],
                                   'sha256': pin['sha256'], 'version': pin['version'],
                                   'rule': pin['rule']}
        self.save()
        return binary

    def legacy(self):
        self.python('legacy', 'coverage.py', '--output', self.directory / 'coverage.json')

    def production(self):
        self.python('production', 'coverage.py', '--production', '--raw', self.directory / 'coverage.raw.json',
                    '--lcov', self.directory / 'coverage.lcov', '--output', self.directory / 'production.json')

    def snapshot(self, label: str, commit: str) -> Path:
        snapshot = self.directory / 'snapshots' / label
        snapshot.mkdir(parents=True)
        archive = self.directory / f'{label}-source.tar'
        # Integration tests embed documentation fixtures. Archive them from the
        # measured commit too, preserving their repository-relative paths.
        paths = list(SNAPSHOT_PATHS)
        external = subprocess.run(['git', 'cat-file', '-e', f'{commit}:test-data/manifest.json'],
                                  cwd=ROOT, capture_output=True).returncode == 0
        if external:
            paths.extend(('tools/maintenance', 'test-data'))
        self.command(f'{label}-archive', ['git', 'archive', '--format=tar', f'--output={archive}',
                                          commit, *paths])
        with tarfile.open(archive) as source:
            source.extractall(snapshot, filter='data')
        if external:
            # Each measured commit supplies its own pinned bytes; never reuse
            # head data for the base or substitute a missing/corrupt payload.
            self.command(f'{label}-test-data', [sys.executable,
                         str(snapshot / 'tools/maintenance/test_data.py'),
                         '--root', str(snapshot), '--group', 'regression-corpus',
                         '--group', 'arc-admin-replay'])
        return snapshot

    def risk(self):
        base, head = self.report['base_sha'], self.report['commit']
        changed = subprocess.check_output(['git', 'diff', '--name-only', base, head, '--',
                                            'tools/harness-gate/src', 'tools/harness-gate/quality-core'], cwd=ROOT, text=True).splitlines()
        relocated = relocated_migration_sources(base, head)
        removed = reviewed_removals(base, head)
        unsupported = [p for p in changed if p.endswith('.rs') and
                       p not in relocated and
                       p not in removed and
                       p not in {str((ROOT / 'tools/harness-gate/src' / source).resolve().relative_to(ROOT))
                                 for source in SOURCE_FILES} and not
                       (p.startswith('tools/harness-gate/quality-core/tests/') or
                        p in ('tools/harness-gate/quality-core/tests.rs', 'tools/harness-gate/quality-core/policy_tests.rs',
                              'tools/harness-gate/src/config/quality/tests.rs',
                              'tools/harness-gate/src/config/tests.rs',
                              'tools/harness-gate/src/verify/tests.rs',
                              'tools/harness-gate/src/preset/tests.rs',
                              'tools/harness-gate/src/scope/tests.rs',
                              'tools/harness-gate/src/process/tests.rs',
                              'tools/harness-gate/src/doctor/tests.rs',
                              'tools/harness-gate/src/service/tests.rs',
                              'tools/harness-gate/src/config/quality/collectors/tests.rs',
                              'tools/harness-gate/src/config/quality/collectors/tests/dogfood_acceptance.rs',
                              'tools/harness-gate/src/config/quality/collectors/ci_acceptance.rs'))]
        unsupported = [p for p in unsupported if not only_terminal_test_module_changed(base, head, p)]
        require(not unsupported, 'production changes outside supported risk series; measurement review required: '
                + ', '.join(unsupported))
        binary = self.measurer()
        target = compiler_configuration()['target']
        for label, commit in (('base', base), ('head', head)):
            snapshot = self.snapshot(label, commit)
            crate = snapshot / 'tools/harness-gate'
            manifest = self.directory / f'{label}-manifest.json'
            self.python(f'{label}-prepare', 'source_measure.py', 'prepare', '--crate', crate,
                        '--binary', binary, '--manifest', manifest, '--target', target)
            # Include the separate base core package and linked head core in the same series.
            cargo_manifest = str(crate / 'Cargo.toml')
            self.command(f'{label}-coverage', ['cargo', 'llvm-cov', 'nextest', '--workspace', '--locked',
                         '--manifest-path', cargo_manifest, '--target', target, '--json', '--output-path',
                         str(self.directory / f'{label}-coverage.json')])
            for flag, suffix in (('--lcov', 'lcov'), ('--cobertura', 'cobertura.xml')):
                self.command(f'{label}-{suffix}', ['cargo', 'llvm-cov', 'report', '--workspace', '--manifest-path',
                             cargo_manifest, '--target', target, flag, '--output-path', str(self.directory / f'{label}-coverage.{suffix}')])
            # A complete base report may contain historical selected failures.
            # The compare command enforces every selected head threshold.
            self.python(f'{label}-measure', 'source_measure.py', 'measure', '--crate', crate,
                        '--binary', binary, '--manifest', manifest, '--llvm',
                        self.directory / f'{label}-coverage.json', '--output',
                        self.directory / f'{label}-risk.json', allowed=(0, 1))
            report = json.loads((self.directory / f'{label}-risk.json').read_text())
            require(report['manifest_sha256'] == sha256(manifest), 'stale risk manifest')
            require(report['llvm_sha256'] == sha256(self.directory / f'{label}-coverage.json'), 'stale risk profiles')
            original = json.loads(manifest.read_text())
            for path, item in original['files'].items():
                relative = (ROOT / 'tools/harness-gate/src' / path).resolve().relative_to(ROOT)
                committed = subprocess.check_output(['git', 'show', f'{commit}:{relative}'], cwd=ROOT)
                require(item['original'].encode() == committed, 'risk source/commit mismatch')
            for path in original['absent_sources']:
                relative = (ROOT / 'tools/harness-gate/src' / path).resolve().relative_to(ROOT)
                exists = subprocess.run(['git', 'cat-file', '-e', f'{commit}:{relative}'], cwd=ROOT,
                                        capture_output=True).returncode == 0
                require(not exists, f'absent risk source exists in commit: {relative}')
        self.python('risk-compare', 'source_measure.py', 'compare', '--base', self.directory / 'base-risk.json',
                    '--head', self.directory / 'head-risk.json', '--output', self.directory / 'risk.json')
        comparison = json.loads((self.directory / 'risk.json').read_text())
        (self.directory / 'risk.md').write_text('# Candidate function risk\n\n'
            f'Base: `{base}`\n\nHead: `{head}`\n\n'
            f"Identities: {len(comparison['identities'])}; failures: {len(comparison['failures'])}.\n\n"
            'Scope: GH-94 files, staged snapshot input, adapter replay, project discovery, CLI dispatch, quality configuration, preset composition and all linked generic-core production sources. Raw counters, exact rational CRAP and historical debt are retained in head-risk.json. '
            'Branch coverage is unsupported. This candidate is not an accepted baseline.\n')

    def matrix(self):
        self.python('matrix', 'critical_paths.py', '--collect', '--evidence',
                    self.directory / 'critical-path-runs/bundle.json', '--output',
                    self.directory / 'critical-paths.json')

    def collect(self):
        started = time.monotonic()
        for stage in STAGES:
            tick = time.monotonic()
            self.report['stages'][stage] = {'status': 'running'}
            self.save()
            try:
                getattr(self, stage)()
                result = {'status': 'success'}
            except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
                result = {'status': 'failure', 'error': str(error)}
            result['seconds'] = time.monotonic() - tick
            self.report['stages'][stage] = result
            self.save()
            print(f'{stage}: {result}', flush=True)
        require(git_sha() == self.report['commit'], 'commit changed during collection')
        require_committed_sources(self.report['commit'])
        self.report['collection_seconds'] = time.monotonic() - started
        for artifact in self.directory.rglob('*'):
            relative = artifact.relative_to(self.directory)
            if relative.parts[0] not in ('build', 'snapshots', 'candidate.json') and artifact.is_file():
                self.report['artifacts'][str(relative)] = sha256(artifact)
        self.save()
        verify(self.directory / 'candidate.json', self.report['commit'], self.report['base_sha'], self.report['run_id'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('aggregate', 'classify', 'collect', 'verify'))
    parser.add_argument('--event', default=os.environ.get('EVENT_NAME'))
    parser.add_argument('--needs', default=os.environ.get('NEEDS_JSON'))
    parser.add_argument('--base-sha')
    parser.add_argument('--head-sha')
    parser.add_argument('--run-id', default=str(uuid.uuid4()))
    parser.add_argument('--output', type=Path, default=ROOT / 'target/quality/candidate')
    parser.add_argument('--github-output', type=Path)
    args = parser.parse_args()
    try:
        if args.operation == 'aggregate':
            full = os.environ.get('RUN_FULL', 'true').strip().lower() != 'false'
            failures = aggregate(args.event, json.loads(args.needs or '{}'), full=full)
            require(not failures, f'required jobs did not succeed: {failures}')
        elif args.operation == 'classify':
            result = classify(args.base_sha or '', args.head_sha or '')
            print('classify: ' + json.dumps(result, sort_keys=True))
            if args.github_output:
                args.github_output.write_text(
                    f"run_full={'true' if result['run_full'] else 'false'}\n"
                    f"docs_only={'true' if result['docs_only'] else 'false'}\n"
                    f"files={result['files']}\n")
        else:
            for commit in (args.base_sha, args.head_sha):
                require(bool(re.fullmatch('[0-9a-f]{40}', commit or '')), 'full base/head SHAs required')
                subprocess.run(['git', 'cat-file', '-e', f'{commit}^{{commit}}'], cwd=ROOT, check=True)
            if args.operation == 'collect':
                require(git_sha() == args.head_sha, 'head must equal checked-out commit')
                require_committed_sources(args.head_sha)
                Collector(args.output, args.base_sha, args.head_sha, args.run_id).collect()
            else:
                verify(args.output / 'candidate.json', args.head_sha, args.base_sha, args.run_id)
        return 0
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(f'quality CI failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
