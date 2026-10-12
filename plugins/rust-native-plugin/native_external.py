"""External-toolchain lifecycle around the unchanged native measurement engine."""
from __future__ import annotations
import argparse
import copy
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rust_native_driver as native
import rust_native_classify as classifier
import rust_native_policy as policy
import rust_collector_project as project
import harness_evidence as evidence


def dependency_check(root, sysroot):
    native.require(sys.version_info >= (3, 12), 'external Python 3.12 or newer is required')
    target = native.host_target()
    native.require(sysroot is not None, 'select external Rust 1.97.1 with --sysroot or HARNESS_GATE_RUST_SYSROOT; no toolchain was installed')
    sysroot = Path(sysroot).resolve(strict=True)
    driver = native.executable(root / 'bin', 'harness-gate-rust-native-driver')
    for name in ('rustc', 'cargo', 'rustdoc'):
        native.require(native.executable(sysroot / 'bin', name).is_file(), 'missing external ' + name)
    with tempfile.TemporaryDirectory(prefix='native-doctor-') as temporary:
        tools = native.tools_identity(Path(temporary), driver, sysroot)
    env = os.environ | native.library_environment(sysroot) | {'RUSTUP_AUTO_INSTALL': '0'}
    result = subprocess.run([str(driver), '--version'], env=env, capture_output=True, text=True, timeout=30)
    native.require(result.returncode == 0 and result.stdout.startswith('rustc 1.97.1 '),
                   'native driver cannot load the selected compiler libraries: ' + result.stderr[-1000:])
    runtime_libraries = sorted(p for base in ('bin', 'lib') for p in (sysroot / base).glob('*LLVM*')
                               if p.is_file() and ('.so' in p.name or p.suffix in ('.dylib', '.dll')))
    return {'schema': 'native-external-dependencies/v1', 'state': 'supported', 'sysroot': str(sysroot), 'target': target,
            'python': {'path': sys.executable, 'version': platform.python_version(),
                       'sha256': native.file_hash(Path(sys.executable))},
            'external_runtime': {str(path): native.file_hash(path) for path in
                [native.executable(sysroot / 'bin', name) for name in ('cargo', 'rustdoc')] + runtime_libraries},
            'tools': tools, 'measurement_series': native.SERIES, 'bundled_toolchains': False,
            'scope': 'existing native compiler-owner/MIR-block contract; no stable fallback'}


def external_capture(manifest, output, samples, features, root, status):
    """Only orchestration changes: native finish/certification/mapping are reused."""
    for key in ('RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS',
                'RUSTC_BOOTSTRAP', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC'):
        native.require(key not in os.environ, 'unset inherited compiler override before capture: ' + key)
    sysroot = Path(status['sysroot'])
    output, manifest = output.resolve(), manifest.resolve(strict=True)
    native.require(not output.is_relative_to(manifest.parent), 'capture output must be outside the measured project')
    output.mkdir(parents=True, exist_ok=False)
    raw = output / 'raw'
    raw.mkdir()
    cargo = str(native.executable(sysroot / 'bin', 'cargo'))
    env = {'CARGO_TARGET_DIR': str(output / 'build'), 'CARGO_INCREMENTAL': '0',
           'RUSTC_BOOTSTRAP': '1', 'RUSTFLAGS': ' '.join(native.FLAGS),
           'RUSTC': str(native.executable(sysroot / 'bin', 'rustc')), 'RUSTDOC': str(native.executable(sysroot / 'bin', 'rustdoc')),
           'RUSTC_WORKSPACE_WRAPPER': os.environ['HARNESS_GATE_NATIVE_EXECUTABLE'],
           'NATIVE_CAPTURE_ROOT': str(raw), 'NATIVE_DRIVER': str(native.executable(root / 'bin', 'harness-gate-rust-native-driver')),
           'NATIVE_DRIVER_LIB': str(sysroot / 'lib'), 'HARNESS_GATE_NATIVE_WRAPPER': '1',
           'HARNESS_GATE_RUST_SYSROOT': str(sysroot), 'HARNESS_GATE_PYTHON': sys.executable,
           'RUSTUP_AUTO_INSTALL': '0', 'LLVM_PROFILE_FILE': str(raw / 'compile-%p-%m.profraw')}
    command = [cargo, 'test', '--locked', '--no-run', '--manifest-path', str(manifest), '--message-format=json']
    if features:
        command += ['--features', ','.join(features)]
    for sample in samples:
        command += ['--test', sample]
    native.run(raw, 'cargo', command, env)
    # Cargo metadata must use the same explicit compiler, including when the
    # target repository pins a different default toolchain.
    os.environ['RUSTC'] = str(native.executable(sysroot / 'bin', 'rustc'))
    try:
        anchor = native.finish_cargo(raw, manifest, native.executable(root / 'bin', 'harness-gate-rust-native-driver'),
                                     sysroot, samples, cargo)
    finally:
        os.environ.pop('RUSTC', None)
    return {'capture': str(raw), 'anchor': anchor}


def check_capture(directory, anchor, status):
    native.verified_files(directory, anchor)
    capture = json.loads((directory / 'capture.json').read_bytes(), object_pairs_hook=evidence._unique_object)
    native.require(capture['tools'] == status['tools'],
                   'capture uses different tools or tool paths; keep the original dependency selection')


def measurement(report):
    report.pop('passed', None)
    for function in report['functions']:
        function.pop('passed', None)
    return report


def adapter(root, status, args):
    request = json.load(sys.stdin, object_pairs_hook=evidence._unique_object)
    project.validate_request(request)
    for variable, field in (('HARNESS_GATE_INVOCATION_ID', 'invocation_id'),
                            ('HARNESS_GATE_STEP_ID', 'step_id')):
        native.require(os.environ.get(variable) == request[field], 'Core invocation environment mismatch: ' + variable)
    # Core exports fs::canonicalize's directory (including the Windows extended
    # path prefix), while the signature retains the request's original spelling.
    artifact_root = os.environ.get('HARNESS_GATE_ARTIFACT_ROOT')
    native.require(artifact_root is not None and Path(artifact_root).is_absolute()
                   and Path(artifact_root).is_dir()
                   and Path(artifact_root).samefile(request['artifact_root']),
                   'Core invocation environment mismatch: HARNESS_GATE_ARTIFACT_ROOT')
    native.require(all(os.environ.get(key) == value for key, value in request['environment'].items()),
                   'signed environment mismatch')
    native.require(request['args'] == sys.argv[1:], 'external dependency options differ from signed arguments')
    executable = Path(os.environ['HARNESS_GATE_NATIVE_EXECUTABLE']).resolve(strict=True)
    native.require(Path(request['adapter']['executable']).samefile(executable)
                   and native.file_hash(executable) == request['adapter']['source_digest'], 'adapter executable identity mismatch')
    native.require(request['adapter']['name'] == 'harness-gate-rust-collector'
                   and request['adapter']['version'] == os.environ['HARNESS_GATE_NATIVE_VERSION'], 'adapter version mismatch')
    # Core has authenticated the complete original args above. The existing
    # binding parser receives its unchanged capture-selection argument shape.
    normalized = copy.deepcopy(request)
    normalized['args'] = ['collect', '--binding', str(args.binding), '--binding-sha256', args.binding_sha256]
    binding = project.load_binding(normalized, args.binding, args.binding_sha256)
    native.require(binding.get('delivery') is None, 'bundled-runtime delivery receipts cannot authorize the external-toolchain product')
    directory = Path(binding['capture']['path'])
    check_capture(directory, binding['capture']['anchor'], status)
    report = measurement(native.certify(directory, binding['capture']['anchor']))
    return project.project_report(report, binding)


def main():
    root = Path(os.environ['HARNESS_GATE_NATIVE_ROOT'])
    # The same precompiled launcher is Cargo's wrapper, using the selected host
    # Python. No shebang/PATH selection of another interpreter is involved.
    if len(sys.argv) > 1 and Path(sys.argv[1]).name in ('rustc', 'rustc.exe') and os.environ.get('HARNESS_GATE_NATIVE_WRAPPER') == '1':
        sysroot = Path(os.environ['HARNESS_GATE_RUST_SYSROOT']).resolve(strict=True)
        native.require(Path(sys.argv[1]).resolve(strict=True) == native.executable(sysroot / 'bin', 'rustc').resolve(strict=True), 'unexpected wrapper compiler')
        native.require(not any(a == '--sysroot' or a.startswith('--sysroot=') for a in sys.argv[2:]), 'unexpected compiler sysroot override')
        return native.wrapper([sys.argv[1], *sys.argv[2:], '--sysroot', str(sysroot)])
    parser = argparse.ArgumentParser(description=__doc__)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--sysroot', type=Path, default=os.environ.get('HARNESS_GATE_RUST_SYSROOT'))
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('doctor', parents=[common])
    for name in ('capture', 'fixture'):
        cmd = sub.add_parser(name, parents=[common])
        cmd.add_argument('--source', type=Path, required=True, help='Cargo.toml for capture, .rs for fixture')
        cmd.add_argument('--output', type=Path, required=True)
        if name == 'capture':
            cmd.add_argument('--sample', action='append', required=True)
            cmd.add_argument('--feature', action='append', default=[])
        else:
            cmd.add_argument('--cfg', action='append', default=[])
    for name in ('certify', 'classify'):
        cmd = sub.add_parser(name, parents=[common])
        cmd.add_argument('--evidence', type=Path, required=True)
        cmd.add_argument('--anchor', required=True)
        cmd.add_argument('--output', type=Path)
        if name == 'classify':
            cmd.add_argument('--witness', type=Path)
            cmd.add_argument('--witness-anchor')
    cmd = sub.add_parser('collect', parents=[common])
    cmd.add_argument('--binding', type=Path, required=True)
    cmd.add_argument('--binding-sha256', required=True)
    cmd = sub.add_parser('evaluate', parents=[common])
    for name in ('base', 'base-anchor', 'head', 'head-anchor', 'output', 'harness-gate', 'base-context', 'head-context', 'project', 'hotspots', 'repository-root', 'policy-binding'):
        cmd.add_argument('--' + name, required=True)
    cmd.add_argument('--mappings')
    args = parser.parse_args()
    try:
        if args.action in ('certify', 'classify') and args.output:
            inputs = [args.evidence]
            if args.action == 'classify' and args.witness:
                inputs.append(args.witness)
            native.require(not args.output.exists(), 'report output must be new')
            native.require(all(not args.output.resolve().is_relative_to(p.resolve()) for p in inputs),
                           'report output must be outside retained evidence')
        status = dependency_check(root, args.sysroot)
        if args.action == 'doctor':
            result = status
        elif args.action == 'capture':
            result = external_capture(args.source, args.output, args.sample, args.feature, root, status)
        elif args.action == 'fixture':
            anchor = native.collect_fixture(args.source, args.output, native.executable(root / 'bin', 'harness-gate-rust-native-driver'), Path(status['sysroot']), args.cfg)
            result = {'capture': str(args.output.resolve()), 'anchor': anchor}
        elif args.action in ('certify', 'classify'):
            check_capture(args.evidence, args.anchor, status)
            if args.action == 'certify':
                result = {'measurement': measurement(native.certify(args.evidence, args.anchor)), 'error': None}
            else:
                native.require(bool(args.witness) == bool(args.witness_anchor), 'witness and anchor required together')
                witness = None
                if args.witness:
                    check_capture(args.witness, args.witness_anchor, status)
                    witness = classifier.load_evidence(args.witness, args.witness_anchor)
                result = classifier.classify(classifier.load_evidence(args.evidence, args.anchor), witness)
                result.pop('measurement_passed', None)
                result.pop('baseline_accepted', None)
        elif args.action == 'collect':
            result = adapter(root, status, args)
        else:
            for directory, anchor in ((args.base, args.base_anchor), (args.head, args.head_anchor)):
                check_capture(Path(directory), anchor, status)
            result = policy.evaluate(args.base, args.base_anchor, args.head, args.head_anchor, args.output, args.harness_gate,
                json.loads(Path(args.base_context).read_text()), json.loads(Path(args.head_context).read_text()),
                args.project, json.loads(Path(args.hotspots).read_text()),
                json.loads(Path(args.mappings).read_text()) if args.mappings else (),
                repository_root=args.repository_root, policy_binding=args.policy_binding)
            native.require(status == dependency_check(root, args.sysroot), 'external dependencies changed during operation')
            print(json.dumps(result['aggregate']))
            return int(result['aggregate']['state'] != 'pass')
        native.require(status == dependency_check(root, args.sysroot), 'external dependencies changed during operation')
        if args.action in ('certify', 'classify') and args.output:
            native.require(not args.output.exists(), 'report output must be new')
            native.write_json(args.output, result)
        print(json.dumps(result))
        return int(args.action == 'classify' and not result['classification_complete'])
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({'state': 'measurement_error', 'message': str(error)}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
