"""Observed delivery preflight for host-authenticated generic requests.

The host pins independently verified manifest/matrix bytes in the signed capture
binding. This module is not an installer, signature verifier or capture authority.
"""
import json
import os
from pathlib import Path
import platform
import subprocess

import harness_evidence as evidence
import rust_collector_contract as contract
import rust_native_driver as native


PROTOCOL = {'request': 'harness-collector-request/v1', 'response': 'harness-collector-response/v1',
            'evidence': 'harness-evidence/v1', 'project_request': 'harness-project-collector-request/v1',
            'project_response': 'harness-project-collector-response/v1', 'adapter_result_schema_version': '1'}


def pinned(reference):
    path = Path(reference['path'])
    native.require(path.is_absolute() and not path.is_symlink(), 'unsafe delivery reference')
    raw = path.read_bytes()
    native.require(native.digest(raw) == reference['sha256'], 'delivery reference digest mismatch')
    return json.loads(raw, object_pairs_hook=evidence._unique_object)


def version(path, *args):
    result = subprocess.run([str(path), *args], capture_output=True, text=True, timeout=30)
    native.require(result.returncode == 0, 'runtime version probe failed: ' + str(path))
    # Delivery schemas use the evidence JSON domain (no control characters).
    # Byte hashes retain exact identity; join version lines deterministically.
    return ' | '.join(result.stdout.strip().splitlines())


def observe(root, core_path, core_id):
    """Hash before execution; the signed release identity maps bytes to commit."""
    native.require(native.file_hash(core_path) == core_id['sha256'], 'wrong released Core bytes')
    native.require(version(core_path, '--version') == 'harness-gate ' + core_id['version'],
                   'wrong released Core version')
    inventory = json.loads((root / 'runtime.json').read_text())
    libraries = {k: native.file_hash(v['source']) for k, v in inventory['host']['libraries'].items()}
    native.require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'unsupported host ABI')
    host = {'target': 'x86_64-unknown-linux-gnu', 'glibc': os.confstr('CS_GNU_LIBC_VERSION'),
            'kernel': platform.release(), 'runtime_dependencies_sha256': contract.fingerprint(libraries)}
    compiler_libraries = list((root / 'rust/lib').glob('librustc_driver-*.so'))
    native.require(len(compiler_libraries) == 1, 'missing/ambiguous rustc driver library')
    llvm = root / 'rust/lib/rustlib/x86_64-unknown-linux-gnu/bin'
    paths = {'driver': root / 'bin/harness-gate-rust-native-driver',
             'rustc': root / 'rust/bin/rustc', 'rustc-driver-library': compiler_libraries[0],
             'llvm-cov': llvm / 'llvm-cov', 'llvm-profdata': llvm / 'llvm-profdata',
             'python': root / 'python/bin/python3'}
    tools = []
    for name, path in paths.items():
        digest = native.file_hash(path)
        # Libraries and the inventory driver have no version CLI; their version
        # is explicitly their byte identity, never an invented semantic version.
        observed_version = 'sha256:' + digest if name in ('driver', 'rustc-driver-library') else \
            version(path, '-vV' if name == 'rustc' else '--version')
        tools.append({'name': name, 'sha256': digest, 'version': observed_version})
    return {'core': core_id, 'protocol': PROTOCOL, 'host_abi': host, 'tools': tools}, paths


def preflight(root, binding):
    delivery = binding.get('delivery')
    native.require(delivery is not None, 'unknown tested Core/protocol/ABI combination; sampling blocked')
    manifest = pinned(delivery['manifest'])
    contract.validate_manifest(manifest)
    matrix = pinned(delivery['matrix'])
    native.require(manifest['collector'] == binding['input']['collector'], 'wrong delivered collector identity')
    # The host installer owns these inert distribution records. They are not
    # executable runtime payload. Legacy versions may still include the archive.
    controls = {'.delivery/' + name for name in ('collector.tar', 'manifest.json',
        'sbom.spdx.json', 'provenance.json', 'release-inventory.json', 'release-inventory.sig',
        'archive-receipt.json')}
    payload = {p.relative_to(root).as_posix(): native.file_hash(p)
               for p in root.rglob('*') if p.is_file() and p.relative_to(root).as_posix() not in controls}
    native.require(not any(p.is_symlink() for p in root.rglob('*')), 'symlink in delivered runtime')
    native.require(payload == {p['path']: p['sha256'] for p in manifest['payloads']},
                   'wrong delivered payload inventory')
    observed, paths = observe(root, Path(delivery['core_path']), delivery['core'])
    native.require(all(root / t['path'] == paths[t['name']] for t in manifest['tools']),
                   'wrong delivered tool path')
    receipt = contract.preflight(manifest, matrix, observed)
    pinned(receipt)
    require_measurement_identity(root, manifest, binding)
    states = {c['metric']: c['state'] for c in manifest['capabilities']}
    native.require(all(states.get(c['metric']) == c['state'] for c in binding['capabilities']),
                   'capability differs from delivered contract')
    return receipt


def require_measurement_identity(root, manifest, binding):
    identity = manifest['measurement']
    native.require(identity['native_series'] == native.SERIES
                   and identity['compiler_commit'] == native.RUSTC_COMMIT
                   and identity['llvm_version'] == '22.1.6'
                   and identity['compiler_inventory_schema'] == native.SCHEMA
                   and identity['adapter_sha256'] == native.file_hash(root / 'app/rust_native_driver.py')
                   and identity['projection_sha256'] == native.file_hash(root / 'app/rust_collector_project.py')
                   and identity['classifier_sha256'] == native.file_hash(root / 'app/rust_native_classify.py'),
                   'wrong delivered measurement identity')
    if manifest['schema'] == 'rust-collector-delivery/v1':
        native.require(binding['series']['id'] in identity['normalized_series'] and
                       identity['configuration_sha256'] == binding['config_digest'],
                       'wrong delivered measurement identity')
    else:
        native.require(manifest['schema'] == 'rust-collector-delivery/v2' and
                       identity['configuration_authority'] == 'quality-trusted-state/v1',
                       'unknown project configuration authority')
        # Core authenticates the exact project/config/series in its request.
        # load_binding binds the same digest, claims and context; project_report
        # independently matches this native identity to the certified capture.
        # The package continues to pin the actual normalization implementation.
        native.require(binding['native_identity']['projection_sha256'] == identity['projection_sha256'] and
                       binding['series']['normalization']['version'] == identity['projection_sha256'] and
                       binding['series']['runtime']['version'] == identity['compiler_commit'],
                       'wrong host-bound normalization identity')


def capture_paths(root, directory):
    capture = json.loads((directory / 'capture.json').read_text())
    native.require(all(Path(t['path']).resolve().is_relative_to(root) for t in capture['tools'].values()),
                   'capture uses tools outside this private runtime; no relocation equivalence')
