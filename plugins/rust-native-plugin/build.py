#!/usr/bin/env python3
"""Build the standalone code-only native plugin; never downloads dependencies."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tomllib

HERE = Path(__file__).resolve().parent
QUALITY = HERE
DRIVER_MANIFEST = Path(os.environ.get(
    'HARNESS_GATE_NATIVE_DRIVER_MANIFEST', HERE.parent / 'rust-native-driver/Cargo.toml'))
MODULES = ('rust_native_driver.py', 'rust_native_classify.py', 'rust_native_policy.py', 'rust_native_config.py',
           'rust_collector_project.py', 'harness_evidence.py', 'project_model.py', 'quality_evidence.py')
ASSETS = {'x86_64-unknown-linux-gnu': 'harness-gate-rust-collector-linux-amd64',
          'x86_64-apple-darwin': 'harness-gate-rust-collector-macos-amd64',
          'aarch64-apple-darwin': 'harness-gate-rust-collector-macos-arm64',
          'x86_64-pc-windows-msvc': 'harness-gate-rust-collector-windows-amd64.exe'}


FROZEN_MODULES = Path(os.environ.get('HARNESS_GATE_FROZEN_MODULES_DIR', ''))


def module_path(name):
    local = HERE / name
    if local.is_file():
        return local
    frozen = FROZEN_MODULES / name
    if FROZEN_MODULES.is_dir() and frozen.is_file():
        return frozen
    raise ValueError('missing runtime module: ' + name)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def licenses(output, rustc, target):
    # Reuse the repository's locked-archive/source verification; this is build
    # preparation only and is not part of either measurement engine.
    verifier = module('locked_notices', HERE / 'locked_notices.py')
    version = subprocess.check_output([str(rustc), '-vV'], text=True)
    if 'commit-hash: 8bab26f4f68e0e26f0bb7960be334d5b520ea452\n' not in version:
        raise ValueError('build launcher with the same pinned Rust 1.97.1 compiler as the driver')
    sysroot = Path(subprocess.check_output([str(rustc), '--print', 'sysroot'], text=True).strip())
    manifest = DRIVER_MANIFEST
    if not manifest.is_file():
        raise ValueError('missing driver manifest: set HARNESS_GATE_NATIVE_DRIVER_MANIFEST')
    cargo = sysroot / 'bin' / ('cargo.exe' if target.endswith('windows-msvc') else 'cargo')
    metadata = json.loads(subprocess.check_output([str(cargo), 'metadata',
        '--manifest-path', str(manifest), '--locked', '--offline', '--format-version', '1',
        '--filter-platform', target]))
    lock = {(p['name'], p['version'], p.get('source')): p
            for p in tomllib.loads(manifest.with_name('Cargo.lock').read_text())['package']}
    sections = [(QUALITY.parents[1] / 'LICENSE').read_text()]
    for package in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
        if package['source']:
            notices, _ = verifier.registry_notices(package, lock)
            sections.extend(f'{package["name"]} {package["version"]} / {name}\n{text}'
                            for name, text in sorted(notices.items()))
    sections.append('Rust standard library 1.97.1\n' +
                    (sysroot / 'share/doc/rust/COPYRIGHT-library.html').read_text())
    path = output / 'LICENSE'
    path.write_text(('\n\n' + '=' * 72 + '\n\n').join(sections))
    metadata_path = output / 'cargo-metadata.json'
    metadata_path.write_text(json.dumps(metadata))
    return path, metadata_path


def build(driver, output, rustc, target=None):
    version_info = subprocess.check_output([str(rustc), '-vV'], text=True)
    host = next(line.removeprefix('host: ') for line in version_info.splitlines() if line.startswith('host: '))
    target = target or host
    if target not in ASSETS or target != host:
        raise ValueError('build the native plugin on its matching supported compiler host')
    driver = driver.resolve(strict=True)
    magic = driver.read_bytes()[:4]
    if not ((target.endswith('linux-gnu') and magic == b'\x7fELF') or
            (target.endswith('apple-darwin') and magic == b'\xcf\xfa\xed\xfe') or
            (target.endswith('windows-msvc') and magic[:2] == b'MZ')):
        raise ValueError('precompiled native driver format differs from target')
    version = tomllib.loads((HERE / 'Cargo.toml').read_text())['package']['version']
    output.mkdir(parents=True, exist_ok=False)
    notice, metadata = licenses(output, rustc, target)
    original_driver_sha256 = hashlib.sha256(driver.read_bytes()).hexdigest()
    staged_driver = output / 'native-driver'
    shutil.copyfile(driver, staged_driver)
    if target.endswith('linux-gnu'):
        subprocess.run(['strip', '--strip-unneeded', str(staged_driver)], check=True)
    elif target.endswith('apple-darwin'):
        subprocess.run(['strip', '-S', '-x', str(staged_driver)], check=True)
        subprocess.run(['codesign', '--force', '--sign', '-', str(staged_driver)], check=True)
    driver = staged_driver.resolve()
    suffix = '.exe' if target.endswith('windows-msvc') else ''
    payload = {'bin/harness-gate-rust-native-driver' + suffix: (driver, 0o755),
               'app/native_external.py': (HERE / 'native_external.py', 0o644)}
    payload.update({'app/' + name: (module_path(name), 0o644) for name in MODULES})
    schemas = {}
    for directory in (FROZEN_MODULES / 'schema', QUALITY / 'schema'):
        for path in sorted(directory.glob('*.json')):
            if path.name in schemas:
                # Allow duplicate schema names if content is identical
                if path.read_bytes() != schemas[path.name].read_bytes():
                    raise ValueError('schema name conflict with different content: ' + path.name)
            else:
                schemas[path.name] = path
    payload.update({'app/schema/' + name: (path, 0o644) for name, path in schemas.items()})
    payload['LICENSE'] = (notice, 0o644)
    inventory = {name: {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'bytes': path.stat().st_size, 'mode': mode}
                 for name, (path, mode) in payload.items()}
    identity = hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()
    embedded = output / 'payload.rs'
    rows = ',\n'.join(f'({json.dumps(name)}, include_bytes!({json.dumps(path.as_posix())}), {mode})'
                     for name, (path, mode) in sorted(payload.items()))
    embedded.write_text(f'const VERSION: &str = {json.dumps(version)};\nconst PAYLOAD_ID: &str = {json.dumps(identity)};\n'
                        f'const PAYLOAD: &[(&str, &[u8], u32)] = &[\n{rows}\n];\n')
    binary = output / ASSETS[target]
    subprocess.run([str(rustc), '--edition=2021', '-C', 'opt-level=s', '-C', 'strip=symbols',
                    str(HERE / 'launcher.rs'), '-o', str(binary)], check=True,
                   env=os.environ | {'HARNESS_GATE_NATIVE_PAYLOAD': str(embedded.resolve())})
    if inventory != {name: {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'bytes': path.stat().st_size, 'mode': mode}
                     for name, (path, mode) in payload.items()}:
        raise ValueError('plugin inputs changed during build')
    record = {'schema': 'native-external-plugin-build/v1', 'version': version, 'target': target, 'payload': inventory,
              'original_driver_sha256': original_driver_sha256,
              'payload_id': identity, 'binary': str(binary), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'external_dependencies': ['Rust 1.97.1 8bab26f4f68e0e26f0bb7960be334d5b520ea452',
                  'matching rustc_driver/LLVM libraries and sysroot', 'LLVM coverage tools 22.1.6', 'Python >=3.12', 'system linker'],
              'bundled_toolchains': False, 'measurement_engine': 'rust-native-production-mir-block/1'}
    (output / 'build.json').write_text(json.dumps(record, indent=2) + '\n')
    sbom_path = output / (ASSETS[target].removesuffix('.exe') + '.sbom.cdx.json')
    sbom_tool_path = os.environ.get('HARNESS_GATE_SBOM_TOOL')
    if not sbom_tool_path or not Path(sbom_tool_path).is_file():
        raise ValueError('missing pinned generate-sbom tool: set HARNESS_GATE_SBOM_TOOL')
    sbom_tool = module('sbom', Path(sbom_tool_path))
    sbom_tool.run(metadata, DRIVER_MANIFEST.with_name('Cargo.lock'), sbom_path)
    sbom = json.loads(sbom_path.read_text())
    sbom['metadata']['component'] = sbom_tool.component({'name': 'harness-gate-rust-collector', 'version': version})
    sbom['metadata']['properties'].extend([
        {'name': 'native.external-build', 'value': json.dumps(record, sort_keys=True)},
        {'name': 'license.location', 'value': 'embedded LICENSE; run the executable with --licenses'}])
    sbom_path.write_text(json.dumps(sbom, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'binary': str(binary), 'bytes': binary.stat().st_size, 'sha256': record['binary_sha256']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, default=Path(shutil.which('rustc') or 'rustc'))
    parser.add_argument('--target', choices=sorted(ASSETS))
    args = parser.parse_args()
    build(args.driver, args.output.resolve(), args.rustc, args.target)
