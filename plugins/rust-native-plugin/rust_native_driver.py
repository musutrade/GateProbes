#!/usr/bin/env python3
"""Opt-in compiler-ID/MIR-counter production mapping. No project gate switch.

The pinned driver emits independent counters even for closures and derives.
This adapter never uses a parent invocation as evidence that a child executed.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import defaultdict
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

RUSTC_COMMIT = '8bab26f4f68e0e26f0bb7960be334d5b520ea452'
SCHEMA = 'rustc-mir-block-inventory/3'
SERIES = {
    'id': 'rust-native-production-mir-block/1',
    'ownership': 'rustc-def-path-hash-expansion/1',
    'regions': 'independent-mir-basic-block-counter/1',
    'lines': 'all-local-span-origins-any-positive-block/1',
    'complexity': 'typed-normal-mir-cfg-common-exit/1',
    'instances': 'same-owner-sum-distinct-llvm-symbols/1',
    'selection': 'cargo-production-targets-exclude-test-and-build/1',
}
FLAGS = ['-C', 'instrument-coverage', '-C', 'link-dead-code', '-C', 'opt-level=0',
         '-Z', 'mir-opt-level=0']
if os.name == 'nt':
    # MSVC incremental linking pads the profiling sections, including before
    # the first name. LLVM rejects the resulting raw profile as an empty symbol.
    # Keep dead owners/counters; disable only linker padding, in both capture paths.
    FLAGS.extend(['-C', 'link-arg=/INCREMENTAL:NO'])


def host_target():
    targets = {('Linux', 'x86_64'): 'x86_64-unknown-linux-gnu',
               ('Darwin', 'x86_64'): 'x86_64-apple-darwin',
               ('Darwin', 'arm64'): 'aarch64-apple-darwin',
               ('Windows', 'amd64'): 'x86_64-pc-windows-msvc'}
    target = targets.get((platform.system(), platform.machine().lower()))
    require(target is not None, 'unsupported native host platform')
    return target


def executable(directory, name):
    return Path(directory) / (name + ('.exe' if os.name == 'nt' else ''))


def library_environment(sysroot):
    sysroot = Path(sysroot)
    if os.name == 'nt':
        return {'PATH': os.pathsep.join([str(sysroot / 'bin'), str(sysroot / 'lib'), os.environ.get('PATH', '')])}
    return {'DYLD_LIBRARY_PATH' if sys.platform == 'darwin' else 'LD_LIBRARY_PATH': str(sysroot / 'lib')}


def tools_identity(directory, driver, sysroot):
    driver, sysroot = Path(driver).resolve(), Path(sysroot).resolve()
    target = host_target()
    llvm = sysroot / 'lib/rustlib' / target / 'bin'
    paths = {'driver': driver, 'rustc': executable(sysroot / 'bin', 'rustc'),
             'llvm-cov': executable(llvm, 'llvm-cov'), 'llvm-profdata': executable(llvm, 'llvm-profdata')}
    pattern = 'rustc_driver-*.dll' if os.name == 'nt' else 'librustc_driver-*.' + ('dylib' if sys.platform == 'darwin' else 'so')
    libraries = list((sysroot / ('bin' if os.name == 'nt' else 'lib')).glob(pattern))
    require(len(libraries) == 1, 'missing/ambiguous rustc driver library')
    paths['rustc-driver-library'] = libraries[0]
    version = run(directory, 'rustc-version', [str(paths['rustc']), '-vV']).read_text()
    require('commit-hash: ' + RUSTC_COMMIT in version and 'LLVM version: 22.1.6' in version
            and 'host: ' + target in version,
            'incompatible rustc/LLVM toolchain')
    records = {name: {'path': str(path), 'sha256': file_hash(path)} for name, path in paths.items()}
    for name in ('llvm-cov', 'llvm-profdata'):
        records[name]['version'] = run(directory, name + '-version', [str(paths[name]), '--version']).read_text()
        require('22.1.6' in records[name]['version'], 'incompatible LLVM tool')
    records['rustc']['version'] = version
    return records


def seal(directory):
    """Return an anchor for a host to retain separately; never accept it implicitly."""
    directory = Path(directory)
    paths = sorted(p for p in directory.rglob('*') if p.is_file() and p != directory / 'manifest.json')
    require(not any(p.is_symlink() for p in directory.rglob('*')), 'symlink in evidence')
    write_json(directory / 'manifest.json', {'schema': 'native-driver-artifacts/1',
               'artifacts': {p.relative_to(directory).as_posix(): file_hash(p) for p in paths}})
    return file_hash(directory / 'manifest.json')


def verified_files(directory, anchor):
    directory = Path(directory)
    require(not any(p.is_symlink() for p in directory.rglob('*')), 'symlink in evidence')
    require(file_hash(directory / 'manifest.json') == anchor, 'untrusted manifest')
    manifest = json.loads((directory / 'manifest.json').read_text())
    require(manifest['schema'] == 'native-driver-artifacts/1', 'incompatible artifact manifest')
    require({p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()}
            == set(manifest['artifacts']) | {'manifest.json'}, 'missing/extra evidence file')
    for name, expected in manifest['artifacts'].items():
        path = directory / name
        require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'artifact path escape')
        require(not any(p.is_symlink() for p in [path, *path.parents]), 'artifact symlink')
        require(path.is_file() and file_hash(path) == expected, 'artifact tampering: ' + name)
    return manifest


def export_native(directory, binaries, tools, profile_paths, label='native'):
    require(bool(binaries) and bool(profile_paths), 'missing binary/raw profile evidence')
    merged = directory / (label + '.profdata')
    run(directory, label + '-merge', [tools['llvm-profdata']['path'], 'merge', '-sparse',
        *[str(directory / p) for p in profile_paths], '-o', str(merged)])
    command = [tools['llvm-cov']['path'], 'export', str(directory / binaries[0]), '-instr-profile=' + str(merged)]
    for binary in binaries[1:]:
        command.extend(['-object', str(directory / binary)])
    return run(directory, label + '-export', command)


def collect_fixture(source, directory, driver, sysroot, cfg=()):
    """Real compiler fixture proof, explicitly distinct from Cargo backend scope."""
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    unit = directory / 'units/fixture'
    unit.mkdir(parents=True)
    original = Path(source).read_bytes()
    local = directory / 'fixture.rs'
    local.write_bytes(original)
    require(all(v != 'test' and not v.startswith('test=') for v in cfg), 'test cfg not supported for fixture')
    tools = tools_identity(directory, driver, sysroot)
    command = [tools['driver']['path'], '--sysroot', str(sysroot), str(local), '--edition=2021',
               '--crate-name', 'native_driver_fixture', *FLAGS, '--out-dir', str(directory)]
    for value in cfg:
        command.extend(['--cfg', value])
    env = library_environment(sysroot) | {'RUSTC_BOOTSTRAP': '1',
           'NATIVE_DRIVER_OUTPUT': str(unit / 'inventory.json'), 'LLVM_PROFILE_FILE': str(unit / 'compile-%p-%m.profraw')}
    run(unit, 'effective-cfg', [tools['rustc']['path'], *command[1:], '--print=cfg'], env)
    run(unit, 'compile', command, env)
    binary = executable(Path('.'), 'native_driver_fixture').name
    run(directory, 'sample', [str(directory / binary)], {'LLVM_PROFILE_FILE': str(directory / 'sample.profraw')})
    export_native(directory, [binary], tools, ['sample.profraw'])
    write_json(directory / 'capture.json', {
        'scope': 'single-file-fixture', 'tools': tools, 'flags': FLAGS,
        'cfg': sorted((unit / 'effective-cfg.stdout').read_text().splitlines()),
        'units': [{'id': 'fixture', 'inventory': 'units/fixture/inventory.json', 'cwd': str(Path.cwd()), 'production': True}],
        'production_sources': {str(local): {'relative': 'fixture.rs', 'sha256': digest(original)}},
        'binaries': [binary], 'profiles': ['sample.profraw'], 'dependency_exclusions': [],
    })
    return seal(directory)


def cargo_selection(directory, metadata, cargo_messages, manifest_path, replay=False):
    package = next(p for p in metadata['packages'] if Path(p['manifest_path']) == manifest_path)
    root = manifest_path.parent
    targets = {str(Path(t['src_path'])): t for t in package['targets']}
    production_targets = {p for p, t in targets.items() if set(t['kind']) & {'lib', 'bin'}}
    require(bool(production_targets), 'no declared production Cargo targets')
    units, compiled = [], set()
    for path in sorted((directory / 'units').glob('*/inventory.json')):
        command = json.loads((path.parent / 'compile.command.json').read_text())
        require(command['exit_code'] == 0, 'failed compiler unit')
        args, cwd = command['command'], command['cwd']
        candidates = {source_key(a, cwd) for a in args if a.endswith('.rs')} & targets.keys()
        require(len(candidates) == 1, 'unresolved Cargo target compilation')
        source = candidates.pop()
        target = targets[source]
        if target['kind'] == ['custom-build']:
            continue  # raw build inventory retained; it is not a sampled application.
        is_test = '--test' in args
        require(not is_test or target['kind'] == ['test'], 'mixed production/test crate compilation is unsupported')
        production = source in production_targets
        require(production or target['kind'] == ['test'], 'unsupported Cargo target selection')
        compiled.add(source)
        units.append({'id': path.parent.name, 'inventory': path.relative_to(directory).as_posix(),
                      'cwd': cwd, 'production': production, 'target': target})
    require(production_targets <= compiled, 'missing production Cargo target')
    production_sources = {}
    # Preserve the complete lexical source inventory, including files not loaded
    # by this cfg. Absence from SourceMap is not a claim of no executable code.
    source_root = directory / 'source' if replay else root
    for path in sorted((source_root / 'src').rglob('*.rs')):
        require(not path.is_symlink(), 'production source symlink')
        relative = path.relative_to(source_root).as_posix()
        target = directory / 'source' / relative
        if not replay:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        production_sources[str(root / relative)] = {'relative': relative, 'sha256': file_hash(path)}
    exclusions = [{'id': p['id'], 'root': str(Path(p['manifest_path']).parent)}
                  for p in metadata['packages'] if p['id'] != package['id']]
    exclusions.append({'id': 'rust-std:' + RUSTC_COMMIT, 'root': '/rustc/' + RUSTC_COMMIT + '/library'})
    package_ids = {p['id'] for p in metadata['packages']}
    for record in cargo_messages:
        if record['reason'] == 'build-script-executed':
            require(record['package_id'] in package_ids, 'unknown generated dependency package')
            if record['package_id'] != package['id']:
                exclusions.append({'id': record['package_id'], 'root': record['out_dir']})
    return units, production_sources, exclusions


def compiler_options(args, prefix):
    values = []
    for i, arg in enumerate(args):
        if arg == prefix:
            require(i + 1 < len(args), 'missing compiler option value')
            values.append(args[i + 1])
        elif arg.startswith(prefix):
            values.append(arg[len(prefix):])
    return values


def cargo_configuration(directory, units, tools, samples):
    configuration = []
    for unit in units:
        parent = (directory / unit['inventory']).parent
        invocation = json.loads((parent / 'invocation.json').read_text())
        require(invocation['driver_sha256'] == tools['driver']['sha256'] and
                invocation['compiler_sha256'] == tools['rustc']['sha256'], 'compiler changed during capture')
        command = json.loads((parent / 'compile.command.json').read_text())
        cfg_command = json.loads((parent / 'effective-cfg.command.json').read_text())
        require(cfg_command['exit_code'] == 0 and cfg_command['command'][1:-1] == command['command'][1:]
                and cfg_command['command'][-1] == '--print=cfg', 'unverified effective cfg')
        args = command['command']
        require(command['exit_code'] == 0, 'failed compiler unit')
        codegen = compiler_options(args, '-C')
        unstable = compiler_options(args, '-Z')
        require(not any(v.startswith('incremental=') for v in codegen), 'incremental custom MIR capture is unsupported')
        for flag in ('instrument-coverage', 'link-dead-code', 'opt-level=0'):
            require([v for v in codegen if v.split('=')[0] == flag.split('=')[0]] == [flag],
                    'missing/duplicate/overridden required codegen flag')
        require([v for v in unstable if v.split('=')[0] == 'mir-opt-level'] == ['mir-opt-level=0'],
                'unverified MIR optimization level')
        configuration.append({'target': unit['target']['name'], 'kind': unit['target']['kind'],
                              'edition': unit['target']['edition'], 'production': unit['production'],
                              'cfg': sorted((parent / 'effective-cfg.stdout').read_text().splitlines()),
                              'codegen': sorted(c for c in codegen if not c.startswith(('metadata=', 'extra-filename='))),
                              'unstable': sorted(unstable),
                              'features': sorted(k for k in invocation['environment'] if k.startswith('CARGO_FEATURE_'))})
    return {'samples': sorted(samples), 'units': sorted(configuration, key=lambda c: (c['target'], c['kind']))}


def cargo_inputs(directory, metadata, replay=False):
    """Retain the resolved lock and every package manifest, including dependencies."""
    originals = sorted({p['manifest_path'] for p in metadata['packages']} |
                       {str(Path(metadata['workspace_root']) / 'Cargo.lock')})
    result = []
    for index, original in enumerate(originals):
        relative = f'cargo-inputs/{index}'
        target = directory / relative
        if not replay:
            target.parent.mkdir(exist_ok=True)
            shutil.copyfile(original, target)
        result.append({'original': original, 'artifact': relative, 'sha256': file_hash(target)})
    return result


def finish_cargo(directory, manifest_path, driver, sysroot, samples, cargo='cargo', runtime=None):
    """Finish a captured build using only project-owned contract-test binaries."""
    directory, manifest_path = Path(directory).resolve(), Path(manifest_path).resolve()
    tools = tools_identity(directory, driver, sysroot)
    metadata_env = {'CARGO_TARGET_DIR': str(directory.parent / 'build')}
    if runtime is not None:
        metadata_env['RUSTC'] = str(runtime / 'rust/bin/rustc')
    metadata = json.loads(run(directory, 'metadata', [cargo, 'metadata', '--locked', '--format-version=1',
                           '--manifest-path', str(manifest_path)], metadata_env).read_text())
    messages = [json.loads(line) for line in (directory / 'cargo.stdout').read_text().splitlines()]
    units, sources, exclusions = cargo_selection(directory, metadata, messages, manifest_path)
    artifacts = [a for a in messages if a.get('executable')]
    tests = {a['target']['name']: a for a in artifacts if a['target']['kind'] == ['test']}
    require(set(tests) == set(samples) and len(samples) == len(set(samples)), 'missing/extra test selection')
    binaries = []
    for index, artifact in enumerate(artifacts):
        path = 'binaries/' + str(index) + ('.exe' if os.name == 'nt' else '')
        target = directory / path
        target.parent.mkdir(exist_ok=True)
        shutil.copyfile(artifact['executable'], target)
        target.chmod(0o755)
        binaries.append(path)
        if artifact['target']['kind'] == ['test']:
            run(directory, 'sample-' + artifact['target']['name'], [str(target)],
                {'LLVM_PROFILE_FILE': str(directory / ('sample-' + str(index) + '-%p-%m.profraw'))})
    profiles = sorted(p.name for p in directory.glob('sample-*.profraw'))
    export_native(directory, binaries, tools, profiles)
    write_json(directory / 'capture.json', {
        'scope': 'cargo-production-targets', 'tools': tools, 'flags': FLAGS,
        'cfg': cargo_configuration(directory, units, tools, samples),
        'units': units, 'production_sources': sources, 'dependency_exclusions': exclusions,
        'binaries': binaries, 'profiles': profiles, 'manifest_path': str(manifest_path),
        'cargo_inputs': cargo_inputs(directory, metadata),
    })
    return seal(directory)


def collect_cargo(manifest_path, directory, driver, sysroot, samples, features=(), *, runtime=None, wrapper=None):
    directory, manifest_path = Path(directory).resolve(), Path(manifest_path).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    raw = directory / 'raw'
    raw.mkdir()
    env = {'CARGO_TARGET_DIR': str(directory / 'build'), 'CARGO_INCREMENTAL': '0', 'RUSTC_BOOTSTRAP': '1', 'RUSTFLAGS': ' '.join(FLAGS),
           'RUSTC_WORKSPACE_WRAPPER': str(Path(__file__).resolve()), 'NATIVE_CAPTURE_ROOT': str(raw),
           'NATIVE_DRIVER': str(Path(driver).resolve()), 'NATIVE_DRIVER_LIB': str(Path(sysroot) / 'lib'),
           'LLVM_PROFILE_FILE': str(raw / 'compile-%p-%m.profraw')}
    cargo = 'cargo'
    if wrapper is not None:
        cargo = str(executable(Path(sysroot) / 'bin', 'cargo'))
        env.update({'RUSTC': str(executable(Path(sysroot) / 'bin', 'rustc')),
                    'RUSTDOC': str(executable(Path(sysroot) / 'bin', 'rustdoc')),
                    'RUSTC_WORKSPACE_WRAPPER': str(wrapper), 'HARNESS_GATE_NATIVE_WRAPPER': '1',
                    'HARNESS_GATE_RUST_SYSROOT': str(sysroot), 'HARNESS_GATE_PYTHON': sys.executable})
    if runtime is not None:
        cargo = str(runtime / 'rust/bin/cargo')
        env.update({'RUSTC': str(runtime / 'rust/bin/rustc'),
                    'RUSTC_WORKSPACE_WRAPPER': str(runtime / 'bin/native-wrapper')})
    command = [cargo, 'test', '--locked', '--no-run', '--manifest-path', str(manifest_path), '--message-format=json']
    if features:
        command.extend(['--features', ','.join(features)])
    for sample in samples:
        command.extend(['--test', sample])
    run(raw, 'cargo', command, env)
    return finish_cargo(raw, manifest_path, driver, sysroot, samples, cargo, runtime)


def certify(directory, anchor):
    directory = Path(directory).resolve()
    manifest = verified_files(directory, anchor)
    capture = json.loads((directory / 'capture.json').read_text())
    require(capture['flags'] == FLAGS, 'incompatible compilation flags')
    for record in capture['tools'].values():
        require(file_hash(record['path']) == record['sha256'], 'incompatible/tampered local tool')
    if capture['scope'] == 'cargo-production-targets':
        metadata = json.loads((directory / 'metadata.stdout').read_text())
        messages = [json.loads(line) for line in (directory / 'cargo.stdout').read_text().splitlines()]
        expected = cargo_selection(directory, metadata, messages, Path(capture['manifest_path']), replay=True)
        require(expected == (capture['units'], capture['production_sources'], capture['dependency_exclusions']),
                'production/test/dependency selection differs from Cargo evidence')
        require(capture['cfg'] == cargo_configuration(directory, capture['units'], capture['tools'], capture['cfg']['samples']),
                'configuration differs from compiler evidence')
        require(capture['cargo_inputs'] == cargo_inputs(directory, metadata, replay=True),
                'Cargo inputs differ from retained resolution')
    else:
        require(capture['scope'] == 'single-file-fixture', 'unknown capture scope')
        require(capture['production_sources'] == {str(directory / 'fixture.rs'):
                {'relative': 'fixture.rs', 'sha256': file_hash(directory / 'fixture.rs')}}, 'fixture source mismatch')
        unit = directory / 'units/fixture'
        command = json.loads((unit / 'compile.command.json').read_text())
        cfg_command = json.loads((unit / 'effective-cfg.command.json').read_text())
        require(command['exit_code'] == cfg_command['exit_code'] == 0 and
                cfg_command['command'] == [capture['tools']['rustc']['path'], *command['command'][1:], '--print=cfg'],
                'unverified fixture cfg')
        require(capture['cfg'] == sorted((unit / 'effective-cfg.stdout').read_text().splitlines()),
                'fixture cfg mismatch')
    units = []
    for unit in capture['units']:
        require(unit['inventory'] in manifest['artifacts'], 'unsealed compiler inventory')
        units.append(unit | {'inventory': json.loads((directory / unit['inventory']).read_text())})
    # Re-merge and re-export in a fresh workspace directory; never execute an
    # archived binary. This checks counts independently of the saved JSON.
    import tempfile
    replay = Path(tempfile.mkdtemp(prefix='native-replay-', dir=directory.parent))
    for name in capture['binaries'] + capture['profiles']:
        require(name in manifest['artifacts'], 'unsealed native artifact')
        target = replay / name
        target.parent.mkdir(parents=True, exist_ok=True)
        os.link(directory / name, target)
    raw = export_native(replay, capture['binaries'], capture['tools'], capture['profiles'])
    llvm = json.loads(raw.read_text())
    require(llvm == json.loads((directory / 'native-export.stdout').read_text()), 'saved export differs from native artifacts')
    report = map_native(units, llvm, capture['production_sources'], capture['dependency_exclusions'])
    report.update({'scope': capture['scope'], 'tools': {k: {a: b for a, b in v.items() if a != 'path'} for k, v in capture['tools'].items()},
                   'flags': capture['flags'], 'cfg': capture['cfg'], 'artifact_anchor': anchor,
                   'mapping_complete_for_declared_scope': True, 'backend_complete': capture['scope'] == 'cargo-production-targets'})
    report['build_inputs'] = [{'sha256': p['sha256'], 'name': Path(p['original']).name}
                              for p in capture.get('cargo_inputs', [])]
    source_root = directory / 'source' if report['backend_complete'] else directory
    source_lines = {p['relative']: (source_root / p['relative']).read_bytes().splitlines(keepends=True)
                    for p in report['source_inventory']}
    for function in report['functions']:
        # Conservative change selection: all production origin lines, including
        # macro definition and invocation. Moving lines alone preserves content.
        content = [(path, source_lines[path][line - 1].hex()) for path, line in function['source_lines']]
        function['syntax_sha256'] = digest(json.dumps(content, separators=(',', ':')).encode())
    report['adapter_sha256'] = file_hash(Path(__file__))
    return report


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def file_hash(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(directory, label, command, env=None, cwd=None):
    """Retain failures too. A command record is never inferred from an artifact."""
    directory = Path(directory)
    require(not (directory / (label + '.command.json')).exists(), 'refusing to overwrite evidence')
    with (directory / (label + '.stdout')).open('wb') as out, (directory / (label + '.stderr')).open('wb') as err:
        result = subprocess.run(command, cwd=cwd, env=os.environ | (env or {}), stdout=out, stderr=err)
    write_json(directory / (label + '.command.json'), {
        'command': command, 'environment': env or {}, 'cwd': str(cwd or Path.cwd()),
        'exit_code': result.returncode,
    })
    require(result.returncode == 0, f'{label} exited {result.returncode}; see {directory}/{label}.stderr')
    return directory / (label + '.stdout')


def wrapper(arguments):
    """Cargo workspace wrapper: target kind is certified from Cargo metadata later."""
    compiler, *args = arguments
    if '--crate-name' not in args or any(a.startswith('--print') for a in args):
        if os.name == 'nt':
            return subprocess.call(arguments)
        os.execv(compiler, arguments)
    root = Path(os.environ['NATIVE_CAPTURE_ROOT'])
    unit = root / 'units' / digest(json.dumps(arguments).encode())
    unit.mkdir(parents=True, exist_ok=False)
    relevant_env = {k: v for k, v in os.environ.items()
                    if k.startswith(('CARGO_CFG_', 'CARGO_FEATURE_', 'CARGO_PKG_'))
                    or k in ('OUT_DIR', 'TARGET', 'HOST', 'OPT_LEVEL', 'DEBUG', 'CARGO_ENCODED_RUSTFLAGS')}
    write_json(unit / 'invocation.json', {'compiler': compiler, 'compiler_sha256': file_hash(compiler),
               'driver_sha256': file_hash(os.environ['NATIVE_DRIVER']), 'environment': relevant_env})
    env = library_environment(Path(os.environ['NATIVE_DRIVER_LIB']).parent) | {
           'NATIVE_DRIVER_OUTPUT': str(unit / 'inventory.json'),
           'LLVM_PROFILE_FILE': str(unit / 'compile-%p-%m.profraw')}
    command = [os.environ['NATIVE_DRIVER'], *args]
    try:
        run(unit, 'effective-cfg', [compiler, *args, '--print=cfg'])
        run(unit, 'compile', command, env)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


def normal_complexity(blocks):
    graph = {b['id']: b for b in blocks}
    require(len(graph) == len(blocks) and set(graph) == set(range(len(blocks))), 'duplicate/missing MIR block')
    visited, pending, edges = set(), [0], 0
    while pending:
        index = pending.pop()
        if index in visited:
            continue
        visited.add(index)
        if index == 'exit':
            continue
        require(index in graph and not graph[index]['cleanup'], 'normal edge to missing/cleanup block')
        targets = graph[index]['normal_successors'] or ['exit']
        require(all(t == 'exit' or type(t) is int for t in targets), 'invalid CFG edge')
        edges += len(targets)
        pending.extend(targets)
    require('exit' in visited, 'nonterminating normal CFG is not certified')
    result = edges - len(visited) + 2
    require(result >= 1, 'invalid MIR complexity')
    return result


def source_key(file, cwd):
    path = Path(file)
    return str(path if path.is_absolute() else Path(cwd) / path)


def span_origins(span, sources, cwd, depth=0):
    """Validate every expansion edge; retain definition AND invocation origins."""
    require(depth < 128, 'cyclic/deep expansion provenance')
    if span.get('dummy'):
        require(span == {'dummy': True}, 'malformed dummy span')
        return set()
    require(set(span) == {'source_id', 'file', 'start', 'end', 'context', 'expansion'}, 'incomplete source span')
    require(type(span['start']) is int and type(span['end']) is int and 0 <= span['start'] <= span['end'], 'invalid source span')
    key = source_key(span['file'], cwd)
    require(span['source_id'] in sources, 'source absent from compiler inventory: ' + key)
    source = sources[span['source_id']]
    require(source['file'] == span['file'], 'span source identity disagreement')
    result = set()
    if source.get('source') is not None:
        data = source['source'].encode()
        require(span['end'] <= len(data), 'source span outside recorded bytes')
        if source.get('production') and span['end'] > span['start']:
            first = bisect_right(source['lines'], span['start'])
            last = bisect_right(source['lines'], span['end'] - 1)
            result = {(source['relative'], n) for n in range(first, last + 1)}
    expansion = span['expansion']
    if expansion is not None:
        require(set(expansion) == {'id', 'kind', 'macro_def', 'call_site', 'def_site'}, 'incomplete expansion edge')
        require(span['context'] != '#0', 'expansion missing syntax context')
        if expansion['kind'].startswith('Macro('):
            require(expansion['macro_def'] is not None, 'macro missing compiler definition ID')
        result |= span_origins(expansion['call_site'], sources, cwd, depth + 1)
        result |= span_origins(expansion['def_site'], sources, cwd, depth + 1)
    else:
        require(span['context'] == '#0', 'missing expansion edge for non-root context')
    return result


def unit_sources(inventory, cwd, production_sources, shared_sources):
    sources = {}
    for source in inventory['sources']:
        key = source_key(source['file'], cwd)
        require(source['source_id'] not in sources, 'duplicate compiler source identity')
        source = dict(source)
        if source['source'] is None and key in production_sources:
            original = shared_sources.get((key, source['compiler_hash']))
            require(original is not None, 'imported production source lacks matching compiler provenance')
            require(original['lines'] == source['lines'], 'imported source line table mismatch')
            source.update(source=original['source'], sha256=original['sha256'])
        if source['source'] is not None:
            data = source['source'].encode()
            require(digest(data) == source['sha256'], 'compiler source hash mismatch')
            expected = [0] + [i + 1 for i, b in enumerate(data) if b == 10 and i + 1 < len(data)]
            require(source['lines'] == expected or not data and source['lines'] == [], 'invalid source line table')
        source['production'] = key in production_sources
        if source['production']:
            require(source['sha256'] == production_sources[key]['sha256'], 'production source hash mismatch')
            source['relative'] = production_sources[key]['relative']
        sources[source['source_id']] = source
    return sources


def prepare_units(units, production_sources):
    owners, map_files, symbols, source_seen = {}, {}, defaultdict(set), set()
    definition_inventory = []
    shared_sources = {}
    for unit in units:
        for source in unit['inventory']['sources']:
            if source['source'] is not None:
                key = (source_key(source['file'], unit['cwd']), source['compiler_hash'])
                require(key not in shared_sources or all(shared_sources[key][k] == source[k]
                        for k in ('source', 'sha256', 'lines')),
                        'ambiguous imported source provenance')
                shared_sources[key] = source
    for unit in units:
        inv, cwd, selected = unit['inventory'], unit['cwd'], unit['production']
        require(inv.get('schema') == SCHEMA and inv.get('rustc_commit') == RUSTC_COMMIT, 'incompatible compiler inventory')
        sources = unit_sources(inv, cwd, production_sources, shared_sources)
        source_seen.update(source_key(s['file'], cwd) for s in sources.values() if s['production'])
        definitions = inv['definitions']
        require([d['index'] for d in definitions] == list(range(len(definitions))), 'incomplete compiler definition inventory')
        require(len({d['id'] for d in definitions}) == len(definitions), 'duplicate compiler definition')
        require({d['id'] for d in definitions if d['role'] == 'runtime'} == {o['id'] for o in inv['owners']},
                'runtime definition/owner inventory differs')
        for definition in definitions:
            require(definition['role'] in ('runtime', 'compile-time', 'declaration'), 'unknown compiler definition role')
            origins = span_origins(definition['span'], sources, cwd)
            if definition['role'] == 'compile-time':
                require(isinstance(definition['ctfe_mir'], str) and digest(definition['ctfe_mir'].encode()) == definition['ctfe_sha256'],
                        'missing/tampered constant evaluation MIR')
            else:
                require(definition['ctfe_mir'] is None and definition['ctfe_sha256'] is None, 'unexpected constant evaluation MIR')
            definition_inventory.append({k: definition[k] for k in ('id', 'index', 'name', 'kind', 'role', 'ctfe_sha256')} |
                                        {'unit': unit['id'], 'production_target': selected,
                                         'source_lines': [list(v) for v in sorted(origins)]})
        for owner in inv['owners']:
            key = owner['id']
            require(key not in owners, 'duplicate/ambiguous compiler owner')
            # A compiler-inserted coverage(off) (e.g. derived Eq) is retained.
            # It never waives the independent-counter completeness check below.
            require([b['id'] for b in owner['blocks']] == list(range(len(owner['blocks']))), 'reordered MIR blocks')
            require(bool(owner['blocks']) and len(owner['blocks']) == len(owner['mappings']), 'missing independent MIR counters')
            require(len({m['span']['file'] for m in owner['mappings']}) == 1, 'owner maps multiple counter files')
            path = str(Path(owner['mappings'][0]['span']['file']))
            require(path not in map_files, 'ambiguous counter map')
            for i, mapping in enumerate(owner['mappings']):
                require(mapping['kind'] == f'Code {{ bcb: bcb{i} }}' and mapping['span']['start'] == i * 11 and mapping['span']['end'] == i * 11 + 10,
                        'counter mapping omitted/reordered')
                span_origins(mapping['span'], sources, cwd)
            origin = span_origins(owner['span'], sources, cwd)
            block_lines = []
            for block in owner['blocks']:
                lines = span_origins(block['terminator_span'], sources, cwd)
                for statement in block['statements']:
                    lines |= span_origins(statement['span'], sources, cwd)
                block_lines.append(lines)
            if selected:
                require(bool(origin), 'production owner has no verified production origin: ' + owner['name'])
                require(any(block_lines), 'production owner has no executable source projection: ' + owner['name'])
            owners[key] = {'raw': owner, 'production': selected, 'unit': unit['id'],
                           'lines': block_lines, 'counts': [0] * len(block_lines), 'instances': [],
                           'cc': normal_complexity(owner['blocks']) if selected else None}
            map_files[path] = key
            symbols[owner['dummy_symbol']].add(key)
        for instance in inv['instances']:
            if instance['local']:
                require(instance['owner'] in owners and owners[instance['owner']]['unit'] == unit['id'], 'unowned local compiler instance')
            symbols[instance['symbol']].add(instance['owner'])
    require(all(len(v) == 1 for v in symbols.values()), 'ambiguous compiler symbol')
    return owners, map_files, symbols, source_seen, definition_inventory


def exclude_region_file(path, exclusions):
    """Only declared dependency/generated/sysroot roots may exclude stock regions."""
    matches = [e for e in exclusions if Path(path) != Path(e['root']) and Path(path).is_relative_to(Path(e['root']))]
    require(bool(matches), 'unattributed LLVM source: ' + path)
    matches.sort(key=lambda e: len(e['root']), reverse=True)
    require(len(matches) == 1 or len(matches[0]['root']) != len(matches[1]['root']), 'ambiguous dependency source')
    return matches[0]['id']


def map_native(units, llvm, production_sources, exclusions):
    require(llvm.get('type') == 'llvm.coverage.json.export' and llvm.get('version') == '3.1.0' and len(llvm['data']) == 1, 'incompatible LLVM export')
    owners, map_files, symbols, source_seen, definitions = prepare_units(units, production_sources)
    names, excluded = set(), []
    dependency_owners = {}
    for function in llvm['data'][0]['functions']:
        name = function['name']
        require(name not in names, 'duplicate LLVM instance')
        names.add(name)
        files = [str(Path(path)) for path in function['filenames']]
        require(bool(files) and bool(function['regions']), 'empty LLVM source/region inventory')
        for region in function['regions']:
            require(len(region) == 8 and all(type(v) is int for v in region), 'invalid LLVM region')
            require(region[4] >= 0 and 0 <= region[5] < len(files) and 0 <= region[6] < len(files)
                    and region[7] in (0, 1, 2, 3), 'unattributable LLVM region')
        mapped = {map_files[p] for p in files if p in map_files}
        if not mapped:
            require(not any(p.endswith('.mir-map') for p in files), 'unowned compiler counter map')
            require(not (symbols.get(name, set()) & owners.keys()), 'local compiler symbol lacks direct counters')
            # The declared roots are immutable for this export. Cache only a
            # successful attribution, and keep validating every instance/region.
            for path in files:
                if path not in dependency_owners:
                    dependency_owners[path] = exclude_region_file(path, exclusions)
            reasons = sorted({dependency_owners[p] for p in files})
            excluded.append({'symbol': name, 'reason': 'dependency', 'owners': reasons, 'regions': len(function['regions'])})
            continue
        require(len(mapped) == 1 and len(files) == 1, 'ambiguous LLVM owner')
        key = mapped.pop()
        require(symbols.get(name) == {key}, 'LLVM symbol/owner disagreement')
        owner = owners[key]
        require(not function['branches'] and not function.get('mcdc_records'), 'unexpected branch/MCDC mapping')
        regions = function['regions']
        require(len(regions) == len(owner['counts']), 'missing/duplicate LLVM block region')
        seen = set()
        for region in regions:
            require(len(region) == 8 and all(type(v) is int for v in region), 'invalid LLVM region')
            start, col, end, endcol, count, file_id, expanded, kind = region
            index = start - 1
            require(0 <= index < len(owner['counts']) and index not in seen, 'duplicate/unowned LLVM region')
            require((col, end, endcol, file_id, expanded, kind) == (1, start, 11, 0, 0, 0) and count >= 0, 'LLVM region differs from compiler map')
            seen.add(index)
            owner['counts'][index] += count
        require(function['count'] == regions[0][4], 'LLVM entry counter disagreement')
        owner['instances'].append(name)
    require(all(o['instances'] for o in owners.values()), 'missing LLVM owner')
    functions, global_lines, covered_lines = [], set(), set()
    for key, owner in sorted(owners.items()):
        if not owner['production']:
            excluded.append({'owner': key, 'reason': 'test-target', 'symbols': owner['instances'], 'regions': len(owner['counts'])})
            continue
        lines, covered = set(), set()
        for origins, count in zip(owner['lines'], owner['counts']):
            lines |= origins
            if count:
                covered |= origins
        global_lines |= lines
        covered_lines |= covered
        cc = owner['cc']
        crap = cc * cc * (1 - Fraction(len(covered), len(lines))) ** 3 + cc
        regions = {'count': len(owner['counts']), 'covered': sum(c > 0 for c in owner['counts'])}
        line_counts = {'count': len(lines), 'covered': len(covered)}
        functions.append({'owner': key, 'unit': owner['unit'], 'name': owner['raw']['name'], 'kind': owner['raw']['kind'],
                          'definition': owner['raw']['span'], 'explicit_coverage_enabled': owner['raw']['explicit_coverage_enabled'],
                          'instances': sorted(owner['instances']),
                          'blocks': owner['counts'], 'lines': line_counts, 'regions': regions, 'cc': cc,
                          'source_lines': [list(v) for v in sorted(lines)],
                          'crap_exact': [crap.numerator, crap.denominator],
                          'passed': len(covered) * 5 >= len(lines) * 4 and regions['covered'] * 5 >= regions['count'] * 4 and crap <= 30})
    return {'series': SERIES, 'functions': functions, 'exclusions': excluded, 'definition_inventory': definitions,
            'source_inventory': [production_sources[p] | {'compiler_loaded': p in source_seen} for p in sorted(production_sources)],
            'coverage': {'lines': {'count': len(global_lines), 'covered': len(covered_lines)},
                         'regions': {k: sum(f['regions'][k] for f in functions) for k in ('count', 'covered')},
                         'functions': {'count': len(functions), 'covered': sum(f['blocks'][0] > 0 for f in functions)}},
            'passed': all(f['passed'] for f in functions)}


def main():
    if len(sys.argv) > 1 and not sys.argv[1].startswith('-') and Path(sys.argv[1]).name == 'rustc':
        return wrapper(sys.argv[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for kind in ('fixture', 'cargo'):
        action = sub.add_parser(kind)
        action.add_argument('--source', type=Path, required=True)
        action.add_argument('--output', type=Path, required=True)
        action.add_argument('--driver', type=Path, required=True)
        action.add_argument('--sysroot', type=Path, required=True)
        if kind == 'cargo':
            action.add_argument('--sample', action='append', required=True)
            action.add_argument('--feature', action='append', default=[])
        else:
            action.add_argument('--cfg', action='append', default=[])
    action = sub.add_parser('certify')
    action.add_argument('--evidence', type=Path, required=True)
    action.add_argument('--anchor', required=True)
    action.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'certify':
        report = certify(args.evidence, args.anchor)
        write_json(args.output, report)
        return 0 if report['passed'] else 1
    elif args.action == 'fixture':
        print(collect_fixture(args.source, args.output, args.driver, args.sysroot, args.cfg))
    else:
        print(collect_cargo(args.source, args.output, args.driver, args.sysroot, args.sample, args.feature))
    return 0


if __name__ == '__main__':
    sys.exit(main())
