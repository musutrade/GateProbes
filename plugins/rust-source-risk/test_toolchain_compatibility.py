"""GH-288 bounded, opt-in real compiler matrix; no production capability changes.

Unittest discovery runs only static contracts. Invoke this file explicitly for
the expensive two-toolchain certification. Missing prerequisites are blocking
errors, not skips. Every compiler command and its original output is retained.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import traceback

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
COMBINATIONS = {
    '1.97.1': ('8bab26f4f68e0e26f0bb7960be334d5b520ea452', '22.1.6'),
    '1.99.0': ('b940084d7eb6a299eb4bfeb8e34901bc051e7ac4', '23.1.1'),
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def retained_root(prefix):
    retained = os.environ.get('RUST_SOURCE_TEST_EVIDENCE')
    if retained:
        Path(retained).mkdir(parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix=prefix, dir=retained)), None
    temporary = tempfile.TemporaryDirectory(prefix=prefix)
    return Path(temporary.name), temporary


def logged_run(root, label, command, *, env=None, cwd=None, check=True, timeout=600):
    commands = Path(root) / 'commands'
    commands.mkdir(parents=True, exist_ok=True)
    log = Path(tempfile.mkdtemp(prefix=label + '-', dir=commands))
    selected = os.environ if env is None else env
    metadata = {'command': list(map(str, command)), 'cwd': str(cwd or Path.cwd()),
                'environment': {key: selected.get(key) for key in
                                ('RUSTUP_TOOLCHAIN', 'CARGO_TARGET_DIR', 'RUST_SOURCE_INVENTORY',
                                 'LLVM_PROFILE_FILE', 'RUSTFLAGS', 'PATH')}}
    write(log / 'command.json', metadata)
    try:
        result = subprocess.run(list(map(str, command)), cwd=cwd, env=env,
                                capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        (log / 'stdout').write_bytes(getattr(error, 'stdout', None) or b'')
        (log / 'stderr').write_bytes(getattr(error, 'stderr', None) or b'')
        write(log / 'status.json', {'state': 'blocked', 'error': str(error)})
        raise
    (log / 'stdout').write_bytes(result.stdout)
    (log / 'stderr').write_bytes(result.stderr)
    write(log / 'status.json', {'exit': result.returncode})
    if check:
        result.check_returncode()
    return result


def tool_identity(root, env=None):
    version = logged_run(root, 'rustc-version', ['rustc', '-vV'], env=env).stdout.decode()
    sysroot = Path(logged_run(root, 'sysroot', ['rustc', '--print', 'sysroot'], env=env).stdout.decode().strip())
    host = next(line.split(': ', 1)[1] for line in version.splitlines() if line.startswith('host: '))
    llvm = next(line.split(': ', 1)[1] for line in version.splitlines() if line.startswith('LLVM version: '))
    tools = sysroot / 'lib/rustlib' / host / 'bin'
    records = {}
    for name, path in [('rustc', sysroot / 'bin/rustc'), ('cargo', sysroot / 'bin/cargo'),
                       ('llvm-cov', tools / 'llvm-cov'), ('llvm-profdata', tools / 'llvm-profdata')]:
        if not path.is_file():
            raise RuntimeError('blocked: missing selected tool ' + str(path))
        text = logged_run(root, name + '-version', [path, '--version'], env=env).stdout.decode().strip()
        if name.startswith('llvm-') and not re.search(r'\b' + re.escape(llvm) + r'\b', text):
            raise RuntimeError('blocked: LLVM tools do not match selected rustc')
        records[name] = {'path': str(path.resolve()), 'sha256': digest(path), 'version': text}
    result = {'rustc_vV': version, 'sysroot': str(sysroot), 'host': host, 'llvm': llvm, 'tools': records}
    python = Path(sys.executable).resolve()
    result['python'] = {'path': str(python), 'sha256': digest(python),
                        'version': logged_run(root, 'python-version', [python, '-VV'], env=env).stdout.decode().strip()}
    inventory = (os.environ if env is None else env).get('RUST_SOURCE_INVENTORY')
    if inventory:
        result['inventory'] = {'path': str(Path(inventory).resolve()), 'sha256': digest(inventory)}
    write(Path(root) / 'tools.json', result)
    return result


def retained_measure(root, label, action):
    directory = Path(root) / 'measurements'
    directory.mkdir(exist_ok=True)
    record = Path(tempfile.mkdtemp(prefix=label + '-', dir=directory))
    try:
        result = action()
    except Exception as error:
        write(record / 'rejection.json', {'type': type(error).__name__, 'reason': str(error)})
        raise
    write(record / 'metrics.json', result)
    return result


DERIVE = '''#[derive(Clone)]
struct Value { number: i32 }
fn manual(value: i32) -> i32 { if value > 0 { value } else { -value } }
fn main() {
    let value = Value { number: std::hint::black_box(1) };
    if std::hint::black_box(CALL_DERIVE) { std::hint::black_box(value.clone()); }
    std::hint::black_box(manual(value.number));
    std::hint::black_box(manual(-value.number));
}
'''
PROC_MACRO = '''extern crate proc_macro;
use proc_macro::TokenStream;
#[proc_macro_attribute]
pub fn generated(_: TokenStream, item: TokenStream) -> TokenStream {
    let mut result = item;
    result.extend("fn generated_owner() -> i32 { if std::hint::black_box(true) { 1 } else { 2 } }".parse::<TokenStream>().unwrap());
    result
}
'''
PROC_SOURCE = '''#[diagnostic::generated]
fn manual() -> i32 { 1 }
fn main() { std::hint::black_box(manual()); CALL_GENERATED }
'''
FEATURE = '''#[cfg(feature = "enabled")]
fn selected() -> i32 { 1 }
#[cfg(not(feature = "enabled"))]
fn selected() -> i32 { 2 }
fn main() { std::hint::black_box(selected()); }
'''
SUPPORTED = '''pub fn manual(value: bool) -> i32 { if value { 1 } else { 2 } }
#[cfg(test)]
mod tests {}
'''
INTEGRATION = '''#[test]
fn covers_both_paths() { assert_eq!(backend::manual(true), 1); assert_eq!(backend::manual(false), 2); }
'''
CFG_TEST = '''fn manual(value: bool) -> i32 { if value { 1 } else { 2 } }
#[cfg(test)]
mod tests { pub fn excluded() -> i32 { 99 } }
fn main() { std::hint::black_box(manual(true)); std::hint::black_box(manual(false)); }
'''


class Matrix:
    def __init__(self, root, toolchain, core, build_record):
        self.root, self.toolchain = root, toolchain
        root.mkdir()
        self.env = dict(os.environ, RUSTUP_TOOLCHAIN=toolchain,
                        CARGO_TARGET_DIR=str(root / 'ast-target'), PYTHONDONTWRITEBYTECODE='1')
        # No inherited flags/wrappers may substitute another compiler or cfg.
        for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC', 'RUSTC_WRAPPER',
                    'RUSTC_WORKSPACE_WRAPPER', 'LLVM_COV', 'LLVM_PROFDATA', 'LLVM_PROFILE_FILE',
                    'CARGO_BUILD_TARGET', 'CARGO_BUILD_RUSTFLAGS', 'RUST_SOURCE_INVENTORY'):
            self.env.pop(key, None)
        self.identity = tool_identity(root, self.env)
        if self.identity['host'] != 'x86_64-unknown-linux-gnu':
            raise RuntimeError('blocked: this certification fixture is Linux x86-64 only')
        commit, llvm = COMBINATIONS[toolchain]
        if ('commit-hash: ' + commit not in self.identity['rustc_vV'] or
                self.identity['llvm'] != llvm):
            raise RuntimeError('blocked: toolchain identity differs from selected certification combination')
        self.env['PATH'] = str(Path(self.identity['sysroot']) / 'bin') + os.pathsep + self.env['PATH']
        self.identity['cargo_llvm_cov'] = logged_run(root, 'cargo-llvm-cov-precheck',
                                                    ['cargo', 'llvm-cov', '--version'], env=self.env).stdout.decode().strip()
        cargo_llvm_cov = shutil.which('cargo-llvm-cov', path=self.env['PATH'])
        if not cargo_llvm_cov:
            raise RuntimeError('blocked: no exact cargo-llvm-cov executable')
        self.identity['cargo_llvm_cov_executable'] = {'path': str(Path(cargo_llvm_cov).resolve()),
                                                     'sha256': digest(cargo_llvm_cov)}
        self.identity['openssl'] = logged_run(root, 'openssl-precheck', ['openssl', 'version'], env=self.env).stdout.decode().strip()
        self.identity['core_version'] = logged_run(root, 'core-precheck', [core, '--version'], env=self.env).stdout.decode().strip()
        self.plugin = root / 'plugin'
        shutil.copytree(HERE, self.plugin, ignore=shutil.ignore_patterns('target', 'inventory', '__pycache__'))
        manifest = self.plugin / 'ast/Cargo.toml'
        lock = (self.plugin / 'ast/Cargo.lock').read_bytes()
        logged_run(root, 'ast-fetch', ['cargo', 'fetch', '--locked', '--manifest-path', manifest], env=self.env)
        logged_run(root, 'ast-build', ['cargo', 'build', '--locked', '--offline', '--manifest-path', manifest], env=self.env)
        if lock != (self.plugin / 'ast/Cargo.lock').read_bytes():
            raise RuntimeError('blocked: analyzer dependency lock changed')
        analyzer = root / 'ast-target/debug/harness-gate-rust-source-inventory'
        shutil.copy2(analyzer, self.plugin / 'inventory')
        self.env['RUST_SOURCE_INVENTORY'] = str(self.plugin / 'inventory')
        self.identity['inventory'] = {'path': str(self.plugin / 'inventory'), 'sha256': digest(self.plugin / 'inventory'),
                                      'toolchain': toolchain, 'fresh_target': str(root / 'ast-target')}
        self.identity['implementation'] = {str(p.relative_to(self.plugin)): digest(p)
                                           for p in self.plugin.rglob('*') if p.is_file()}
        self.core = core
        self.identity['core'] = {'path': str(core), 'sha256': digest(core), 'build': build_record}
        write(root / 'tools.json', self.identity)
        self.env['RUST_SOURCE_TEST_EVIDENCE'] = str(root / 'existing-fixtures')
        self.series = None

    def existing(self):
        logged_run(self.root, 'existing-source-tests', [sys.executable, '-B', '-m', 'unittest', 'discover',
                    '-s', self.plugin, '-p', 'test_*.py', '-v'], env=self.env, cwd=self.plugin)

    def diagnostic(self, name, source, flags=(), proc=False):
        root = self.root / name
        root.mkdir()
        path = root / 'sample.rs'
        path.write_text(source)
        inventory = logged_run(root, 'inventory', [self.plugin / 'inventory', path], env=self.env, check=False)
        (root / 'inventory.json' if inventory.returncode == 0 else root / 'inventory.stderr').write_bytes(
            inventory.stdout if inventory.returncode == 0 else inventory.stderr)
        extra = list(flags)
        if proc:
            macro = root / 'diagnostic.rs'
            macro.write_text(PROC_MACRO)
            library = root / 'libdiagnostic.so'
            logged_run(root, 'proc-macro-build', ['rustc', '--edition=2024', '--crate-name', 'diagnostic',
                        '--crate-type', 'proc-macro', macro, '-o', library], env=self.env)
            extra += ['--extern', 'diagnostic=' + str(library)]
        binary = root / 'sample'
        logged_run(root, 'compile', ['rustc', '--edition=2024', '-C', 'instrument-coverage',
                                   *extra, path, '-o', binary], env=self.env)
        runtime = dict(self.env, LLVM_PROFILE_FILE=str(root / 'raw-%p.profraw'))
        logged_run(root, 'execute', [binary], env=runtime)
        profiles = sorted(root.glob('*.profraw'))
        if not profiles:
            raise RuntimeError('blocked: execution produced no coverage profile')
        profdata = root / 'merged.profdata'
        tools = self.identity['tools']
        logged_run(root, 'merge', [tools['llvm-profdata']['path'], 'merge', '-sparse', *profiles, '-o', profdata], env=self.env)
        exported = logged_run(root, 'export', [tools['llvm-cov']['path'], 'export',
                                              '-instr-profile=' + str(profdata), binary], env=self.env)
        llvm = root / 'llvm.json'
        llvm.write_bytes(exported.stdout)
        result = logged_run(root, 'source-measure', [sys.executable, self.plugin / 'measure.py',
                            '--source-root', root, '--source', 'sample.rs', '--llvm-json', llvm,
                            '--ast-binary', self.plugin / 'inventory', '--output', root / 'metrics.json'],
                            env=self.env, check=False)
        data = json.loads(exported.stdout)
        boundary = ('llvm-format' if data.get('version') != '3.1.0' else
                    'source-inventory' if inventory.returncode else 'source-mapping' if result.returncode else 'measured')
        record = {'case': name, 'toolchain': self.toolchain, 'source_sha256': digest(path),
                  'cfg_flags': list(flags), 'inventory_exit': inventory.returncode,
                  'llvm_format': data.get('version'), 'measure_exit': result.returncode,
                  'earliest_measurement_boundary': boundary, 'diagnostic': result.stderr.decode(),
                  'raw_instances': [row for unit in data['data'] for row in unit['functions']],
                  'files_sha256': {str(p.relative_to(root)): digest(p) for p in root.iterdir() if p.is_file()}}
        write(root / 'case.json', record)
        return root, record

    def rejection_capture(self, root, expected):
        # Unsupported source is tested separately through real capture preflight;
        # successful diagnostic compilation does not claim collector/Core support.
        (root / 'Cargo.toml').write_text('[package]\nname="rejected"\nversion="0.1.0"\nedition="2024"\n')
        source = root / 'src'
        source.mkdir()
        shutil.copyfile(root / 'sample.rs', source / 'lib.rs')
        result = logged_run(root, 'capture-preflight', [sys.executable, self.plugin / 'capture.py',
                            '--repository', root, '--output', root / 'capture', '--target-dir', root / 'capture-target',
                            '--input', 'Cargo.toml', '--input', 'src', '--source-root', 'src'],
                            env=dict(self.env, CARGO_TARGET_DIR=str(root / 'capture-target')), check=False)
        if result.returncode == 0 or expected not in result.stderr.decode():
            raise AssertionError('capture did not reject at expected source preflight: ' + result.stderr.decode())
        if (root / 'capture/capture.stdout').exists() or (root / 'capture/bundle.json').exists():
            raise AssertionError('unsupported source started measurement or produced a bundle')
        write(root / 'capture-preflight.json', {'state': 'unsupported', 'stage': 'source-inventory',
                                               'exit': result.returncode, 'reason': result.stderr.decode(),
                                               'cargo_started': False, 'core_chain': 'not reached'})

    def core_chain(self):
        root = self.root / 'supported-core'
        root.mkdir()
        source = root / 'apps/server/src'
        source.mkdir(parents=True)
        (source / 'lib.rs').write_text(SUPPORTED)
        tests = root / 'tests'
        tests.mkdir()
        (tests / 'coverage.rs').write_text(INTEGRATION)
        (root / 'Cargo.toml').write_text('[package]\nname="backend"\nversion="0.1.0"\nedition="2024"\n'
                                       '[lib]\npath="apps/server/src/lib.rs"\n')
        logged_run(root, 'lock', ['cargo', 'generate-lockfile', '--offline'], env=self.env, cwd=root)
        logged_run(root, 'git-init', ['git', 'init', '--quiet'], env=self.env, cwd=root)
        logged_run(root, 'git-add', ['git', 'add', 'Cargo.toml', 'Cargo.lock', 'apps', 'tests'], env=self.env, cwd=root)
        logged_run(root, 'git-commit', ['git', '-c', 'user.name=Compatibility fixture', '-c',
                    'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', '-c',
                    'core.hooksPath=' + str(root / 'unused-hooks'), 'commit', '--quiet', '-m', 'isolated source fixture'],
                    env=self.env, cwd=root)
        env = dict(self.env, CARGO_TARGET_DIR=str(root / 'capture-target'))
        logged_run(root, 'cargo-llvm-cov-version', ['cargo', 'llvm-cov', '--version'], env=env)
        logged_run(root, 'capture', [sys.executable, self.plugin / 'capture.py', '--repository', root,
                    '--output', root / 'capture', '--target-dir', root / 'capture-target', '--input', 'Cargo.toml',
                    '--input', 'Cargo.lock', '--input', 'apps', '--input', 'tests', '--source-root', 'apps/server/src'], env=env)
        bundle = root / 'capture/bundle.json'
        captured = json.loads(bundle.read_text())
        if digest(self.identity['cargo_llvm_cov_executable']['path']) != self.identity['cargo_llvm_cov_executable']['sha256']:
            raise AssertionError('cargo-llvm-cov executable changed during capture')
        receipt = captured['request']['parameters']['receipt']
        if receipt['pipeline']['tools']['rustc'] != self.identity['rustc_vV'].strip():
            raise AssertionError('capture used a different rustc')
        for name in ('llvm-cov', 'llvm-profdata'):
            if receipt['pipeline']['tools'][name]['sha256'] != self.identity['tools'][name]['sha256']:
                raise AssertionError('capture used a different LLVM tool')
        request = root / 'request.json'
        write(request, captured['request'])
        discovered = logged_run(root, 'plugin-discover-reexport', [sys.executable, self.plugin / 'plugin.py',
                                                                 'discover', '--request', request], env=env)
        if json.loads(discovered.stdout)['subjects'] != captured['request']['parameters']['subjects']:
            raise AssertionError('independent plugin re-export changed source owners')
        corebin = root / 'core-bin'
        corebin.mkdir()
        shutil.copyfile(self.core, corebin / 'harness-gate')
        (corebin / 'harness-gate').chmod(0o700)
        env['PATH'] = str(corebin) + os.pathsep + env['PATH']
        if Path(shutil.which('harness-gate', path=env['PATH'])).resolve() != corebin / 'harness-gate':
            raise AssertionError('acceptance would pick another Core')
        write(root / 'core-selection.json', {'original': str(self.core), 'executed': str(corebin / 'harness-gate'),
                                            'sha256': digest(corebin / 'harness-gate'), 'build': self.identity['core']['build']})
        logged_run(root, 'core-acceptance', [sys.executable, self.plugin / 'acceptance.py', '--bundle', bundle,
                                           '--plugin', self.plugin], env=env)
        accepted = list((root / 'capture').glob('host-*/acceptance.json'))
        if len(accepted) != 1:
            raise AssertionError('missing unique actual Core acceptance record')
        result = json.loads(accepted[0].read_text())
        if result['evaluation_exit'] != 0 or result['negative_cases'] != [
                'stale-context', 'expired', 'tampered-signature', 'replay', 'tampered-artifact']:
            raise AssertionError('Core chain incomplete')
        write(root / 'case.json', {'state': 'supported', 'series': captured['series'], 'core': result,
                                  'synthetic_threshold_cases': result['threshold_cases'],
                                  'core_adapter_environment': 'Core clears environment; re-export uses pinned absolute LLVM tools and fresh analyzer, no compiler invocation',
                                  'scope': 'local isolated source collector/Core; no production signing'})
        return captured['series']['id']


def certification_suite(matrix):
    class CompatibilityTests(unittest.TestCase):
        def test_existing_contracts_with_selected_fresh_analyzer(self):
            matrix.existing()

        def test_projection_original_bytes_reject_at_actual_boundary(self):
            original = (HERE / 'fixtures/closure_without_counter.rs').read_bytes()
            root, row = matrix.diagnostic('projection', original.decode())
            self.assertEqual((root / 'sample.rs').read_bytes(), original)
            self.assertEqual(row['earliest_measurement_boundary'], 'source-mapping', row)
            self.assertNotEqual(row['measure_exit'], 0)
            self.assertIn('source callable missing native mapping', row['diagnostic'])
            self.assertIn('parent execution is not a substitute', row['diagnostic'])

        def test_derive_manual_owners_separate_from_generated_methods(self):
            for called in (False, True):
                with self.subTest(called=called):
                    root, row = matrix.diagnostic('derive-' + str(called).lower(),
                                                 DERIVE.replace('CALL_DERIVE', str(called).lower()))
                    self.assertEqual(row['earliest_measurement_boundary'], 'measured', row)
                    owners = json.loads((root / 'metrics.json').read_text())['functions']
                    self.assertEqual({owner['name'] for owner in owners}, {'manual', 'main'})
                    for owner in owners:
                        self.assertEqual(owner['coverage.function']['numerator'], 1)
                        for metric in ('coverage.line', 'coverage.region'):
                            self.assertGreater(owner[metric]['denominator'], 0)
                    write(root / 'generated-boundary.json', {'derive_called': called,
                          'generated_methods': 'outside source inventory; no generated coverage certification',
                          'original_llvm_records': row['raw_instances']})

        def test_proc_attribute_diagnostic_execution_and_collector_rejection(self):
            for called in (False, True):
                with self.subTest(called=called):
                    root, row = matrix.diagnostic('proc-attribute-' + str(called).lower(),
                        PROC_SOURCE.replace('CALL_GENERATED', 'std::hint::black_box(generated_owner());' if called else ''), proc=True)
                    self.assertNotEqual(row['inventory_exit'], 0)
                    self.assertIn('unsupported attribute diagnostic::generated', (root / 'inventory.stderr').read_text())
                    matrix.rejection_capture(root, 'unsupported attribute diagnostic::generated')
                    write(root / 'collector-boundary.json', {'state': 'unsupported', 'core_chain': 'not reached',
                                                            'generated_called': called, 'measurement_boundary': row['earliest_measurement_boundary']})

        def test_cfg_feature_diagnostic_variants_do_not_certify_source_ownership(self):
            for enabled in (False, True):
                with self.subTest(enabled=enabled):
                    flags = ['--cfg', 'feature="enabled"'] if enabled else []
                    root, row = matrix.diagnostic('cfg-' + str(enabled).lower(), FEATURE, flags)
                    self.assertNotEqual(row['inventory_exit'], 0)
                    self.assertIn('unsupported attribute cfg', (root / 'inventory.stderr').read_text())
                    matrix.rejection_capture(root, 'unsupported attribute cfg')
                    write(root / 'collector-boundary.json', {'state': 'unsupported', 'core_chain': 'not reached',
                                                            'cfg_flags': flags, 'measurement_boundary': row['earliest_measurement_boundary']})

        def test_cfg_test_inventory_exclusion_and_actual_native_boundary(self):
            for test_cfg in (False, True):
                with self.subTest(test_cfg=test_cfg):
                    root, row = matrix.diagnostic('cfg-test-' + str(test_cfg).lower(), CFG_TEST,
                                                 ['--cfg', 'test'] if test_cfg else [])
                    self.assertEqual(row['inventory_exit'], 0)
                    owners = json.loads((root / 'inventory.json').read_text())
                    self.assertEqual({owner['name'] for owner in owners}, {'manual', 'main'})
                    write(root / 'collector-boundary.json', {
                        'ast_exclusion': 'exact cfg(test) module excludes test owners',
                        'native_measurement_boundary': row['earliest_measurement_boundary'],
                        'core_chain': 'not run for this diagnostic configuration'})
                    if not test_cfg:
                        self.assertEqual(row['earliest_measurement_boundary'], 'measured', row)
                    if row['earliest_measurement_boundary'] == 'llvm-format':
                        self.fail('blocked at LLVM format; downstream cfg/test mapping not certified')
                    if row['measure_exit']:
                        self.assertIn('exact source anchor', row['diagnostic'])

        def test_supported_capture_reexport_signed_core_and_negatives(self):
            matrix.series = matrix.core_chain()
    return unittest.defaultTestLoader.loadTestsFromTestCase(CompatibilityTests)


class CompatibilityStaticTests(unittest.TestCase):
    def test_projection_fixture_and_explicit_tool_pairs_remain_bounded(self):
        self.assertEqual(set(COMBINATIONS), {'1.97.1', '1.99.0'})
        self.assertIn('|value: &i32| *value', (HERE / 'fixtures/closure_without_counter.rs').read_text())
        self.assertNotIn('expand_expr', PROC_MACRO)
        self.assertIn('#[cfg(test)]', SUPPORTED)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True, help='new directory outside checkout')
    parser.add_argument('--core', type=Path, required=True, help='explicit freshly built Core binary')
    parser.add_argument('--core-build-record', type=Path, required=True,
                        help='trusted build JSON: binary, sha256, source_commit, command, exit')
    args = parser.parse_args()
    root = args.evidence.absolute()
    root.mkdir(parents=True, exist_ok=False)
    try:
        if root.resolve().is_relative_to(REPO.resolve()):
            raise RuntimeError('blocked: evidence must be outside checkout')
        core = args.core.resolve(strict=True)
        build = json.loads(args.core_build_record.read_text())
        revision = logged_run(root, 'source-commit', ['git', '-C', REPO, 'rev-parse', 'HEAD']).stdout.decode().strip()
        if (not args.core.is_absolute() or build['binary'] != str(core) or build['sha256'] != digest(core) or
                build['source_commit'] != revision or build['exit'] != 0 or not isinstance(build['command'], list) or
                'build' not in build['command'] or '--locked' not in build['command']):
            raise RuntimeError('blocked: missing exact current Core build provenance')
        write(root / 'core-build.json', build)
        outcomes = []
        for toolchain in COMBINATIONS:
            entry = {'toolchain': toolchain}
            try:
                matrix = Matrix(root / toolchain, toolchain, core, build)
                with (matrix.root / 'unittest.log').open('w') as stream:
                    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(certification_suite(matrix))
                entry.update(state='certified' if result.wasSuccessful() else 'failed',
                             tests=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                             series=getattr(matrix, 'series', None))
            except Exception as error:
                entry.update(state='blocked', reason=str(error))
                (root / toolchain / 'blocked.traceback').write_text(traceback.format_exc())
            outcomes.append(entry)
            write(root / 'matrix.json', {'scope': 'source-risk Linux x86-64 compatibility only', 'combinations': outcomes})
        cases = {}
        for toolchain in COMBINATIONS:
            for path in (root / toolchain).glob('*/case.json'):
                row = json.loads(path.read_text())
                if 'source_sha256' in row:
                    cases.setdefault(path.parent.name, {})[toolchain] = {
                        'source_sha256': row['source_sha256'], 'cfg_flags': row['cfg_flags'],
                        'llvm_format': row['llvm_format'], 'boundary': row['earliest_measurement_boundary'],
                        'measure_exit': row['measure_exit'], 'evidence': str(path)}
        write(root / 'diagnostic-comparison.json', cases)
        for rows in cases.values():
            if len(rows) == len(COMBINATIONS) and (len({row['source_sha256'] for row in rows.values()}) != 1 or
                                                  len({tuple(row['cfg_flags']) for row in rows.values()}) != 1):
                raise AssertionError('comparison changed diagnostic source/configuration across compilers')
        if all(row['state'] == 'certified' for row in outcomes):
            if len({row['series'] for row in outcomes}) != len(COMBINATIONS):
                raise AssertionError('different toolchains unexpectedly shared a measurement series')
            write(root / 'success.json', {'state': 'certified', 'combinations': outcomes,
                                         'baseline_adopted': False, 'native_1_99_migration': False})
            return 0
        return 1
    except Exception as error:
        write(root / 'blocked.json', {'state': 'blocked', 'reason': str(error)})
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
