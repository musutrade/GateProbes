"""Independent Docker lifecycle package; no historical runtime identity reuse."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import tomllib

import lifecycle_core
import package_runtime
import package_workload
import plugin_release
import runtime_build

PRODUCT = 'docker-lifecycle'
BINARY = 'gateprobes-docker-lifecycle'
VERSION = '0.1.0'
PROTOCOL_CHECKSUM = '357cf18eb55a7a83d9b8840280e77c6f7efe263a74bdeafc7e132cad7a607e54'
MEMBERS = {BINARY, 'plugin.json', 'README.md', 'Cargo.toml', 'Cargo.lock', 'LICENSE',
           'THIRD_PARTY_NOTICES.txt', 'rust-toolchain.toml', 'build-inputs.json', 'accept.py', 'core-pin.json', 'protocol-LICENSE', 'protocol-license.json'}
MANIFEST = {
    'schema': 'gateprobes-runtime-adapter/v1', 'name': PRODUCT, 'version': VERSION,
    'executable': BINARY, 'protocol': 'gate-runtime/lifecycle-v1', 'authority': 'container-lifecycle/mutate',
    'platforms': ['linux-x86_64'], 'core_versions': ['0.10.0'], 'status': 'release-candidate',
    'capabilities': ['resolve-image', 'create', 'status', 'start', 'stop', 'remove', 'health'],
    'limitations': ['rootless and daemon restart unproven', 'no daemon authentication or OS containment',
                    'Core owns durable lease, recovery and cancellation coordination',
                    'package acceptance uses fake Unix sockets only; real-engine package acceptance unproven'],
}



def protocol_notice(root, package, source, checksum):
    """Narrow fallback for the one immutable crate missing its upstream MIT text."""
    pin = {
        'schema': 'gateprobes-source-license/v1', 'package': 'gatehouse-runtime-protocol',
        'version': '0.3.0', 'crate_sha256': PROTOCOL_CHECKSUM, 'license_expression': 'MIT',
        'repository': 'https://github.com/musutrade/GateHouse',
        'source_commit': 'd8505fc25b777ae8cb45e9131e6144ad261ef8df',
        'path_in_vcs': 'tools/harness-gate/runtime-protocol', 'license_path': 'LICENSE',
        'license_sha256': '5b9835780a3cd7518d7637c6730a26c1141d24a00a413364264c2a4091c0e6d9',
        'reason': 'Immutable published crate declares MIT but omits license text; preserve the exact corresponding source repository license.',
    }
    if (package['name'], package['version'], package.get('license'), checksum) != (
            pin['package'], pin['version'], pin['license_expression'], pin['crate_sha256']):
        raise ValueError('unapproved missing dependency license')
    provenance = json.loads(package_workload.checked_file(root, f'plugins/{PRODUCT}/native/protocol-license.json'))
    license_text = package_workload.checked_file(root, f'plugins/{PRODUCT}/native/protocol-LICENSE')
    vcs = json.loads((source / '.cargo_vcs_info.json').read_text())
    if (provenance != pin or hashlib.sha256(license_text).hexdigest() != pin['license_sha256']
            or vcs != {'git': {'sha1': pin['source_commit']}, 'path_in_vcs': pin['path_in_vcs']}):
        raise ValueError('protocol source license provenance mismatch')
    return {'upstream-LICENSE@' + pin['source_commit']: license_text.decode('utf-8')}


def validate(root):
    product = root / 'plugins' / PRODUCT
    manifest = json.loads(package_workload.checked_file(root, f'plugins/{PRODUCT}/plugin.json'))
    cargo = tomllib.loads((product / 'native/Cargo.toml').read_text())
    lock = tomllib.loads((product / 'native/Cargo.lock').read_text())
    if manifest != MANIFEST or (cargo['package']['name'], cargo['package']['version']) != (BINARY, VERSION):
        raise ValueError('lifecycle product identity mismatch')
    if cargo['dependencies']['gatehouse-runtime-protocol'] != '=0.3.0' or 'patch' in cargo or 'replace' in cargo:
        raise ValueError('lifecycle requires published protocol without patches')
    entries = [p for p in lock['package'] if p['name'] == 'gatehouse-runtime-protocol']
    if len(entries) != 1 or (entries[0]['version'], entries[0].get('source'), entries[0].get('checksum')) != (
            '0.3.0', 'registry+https://github.com/rust-lang/crates.io-index', PROTOCOL_CHECKSUM):
        raise ValueError('lifecycle protocol lock mismatch')
    if tomllib.loads((product / 'native/rust-toolchain.toml').read_text())['toolchain']['channel'] != runtime_build.TOOLCHAIN:
        raise ValueError('lifecycle toolchain mismatch')
    lifecycle_core.contract(root)
    return product, lock


def extract(data, destination, prefix):
    """Only the bounded exact regular-file product layout may be extracted."""
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members = archive.getmembers()
        if len(members) != len(MEMBERS) or {m.name for m in members} != {prefix + '/' + n for n in MEMBERS}:
            raise ValueError('lifecycle archive members differ')
        if sum(m.size for m in members) > 128 * 1024 * 1024:
            raise ValueError('lifecycle archive too large')
        for member in members:
            name = member.name.removeprefix(prefix + '/')
            if not member.isfile() or member.pax_headers or member.size <= 0 or member.mode != (0o755 if name == BINARY else 0o644):
                raise ValueError('unsafe lifecycle archive member')
        archive.extractall(destination, filter='data')
    return destination / prefix


def build(root, output):
    from package_plugin import run
    product, lock = validate(root)
    identity = plugin_release.resolve(PRODUCT, root)
    native = product / 'native'
    sysroot, _ = runtime_build.verify_inputs(root, PRODUCT)
    with tempfile.TemporaryDirectory(prefix='lifecycle-build-') as temporary:
        stage = Path(temporary)
        binaries = []
        for index in range(2):
            target = stage / f'target-{index}'
            env = runtime_build.environment(root, target, stage, sysroot)
            run('cargo', '+' + runtime_build.TOOLCHAIN, 'build', '--locked', '--release', '--target',
                runtime_build.TARGET, '--bin', BINARY, '--manifest-path', str(native / 'Cargo.toml'), env=env)
            binaries.append((target / runtime_build.TARGET / 'release' / BINARY).read_bytes())
        runtime_build.verify_inputs(root, PRODUCT)
        if binaries[0] != binaries[1]:
            raise ValueError('lifecycle clean builds are not byte-identical')
        runtime_build.verify_static_pie(binaries[0])
        files = {BINARY: binaries[0], 'LICENSE': package_workload.checked_file(root, 'LICENSE')}
        for name in MEMBERS - {BINARY, 'LICENSE', 'THIRD_PARTY_NOTICES.txt'}:
            location = 'native/' + name if name in {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'build-inputs.json', 'protocol-LICENSE', 'protocol-license.json'} else name
            files[name] = package_workload.checked_file(root, f'plugins/{PRODUCT}/{location}')
        metadata = json.loads(run('cargo', '+' + runtime_build.TOOLCHAIN, 'metadata', '--locked', '--format-version', '1',
            '--manifest-path', str(native / 'Cargo.toml'), env=env, echo=False))
        spec = importlib.util.spec_from_file_location('lifecycle_notices', root / 'plugins/rust-native-plugin/locked_notices.py')
        notices = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(notices)
        locked = {(p['name'], p['version'], p.get('source')): p for p in lock['package']}
        texts = []
        for dependency in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
            if dependency['source']:
                entries, _ = notices.registry_notices(dependency, locked, missing_notice=lambda package, source, checksum: protocol_notice(root, package, source, checksum))
                texts.extend(f"{dependency['name']} {dependency['version']} / {name}\n{text}" for name, text in sorted(entries.items()))
        texts.append((sysroot / 'share/doc/rust/COPYRIGHT-library.html').read_text())
        files['THIRD_PARTY_NOTICES.txt'] = '\n\n'.join(texts).encode()
        prefix = identity['archive'].removesuffix('.tar.gz')
        data = package_runtime.archive_bytes(prefix, files, BINARY)
        directory = extract(data, stage / 'extracted', prefix)
        for name, expected in files.items():
            if (directory / name).read_bytes() != expected:
                raise ValueError('lifecycle extracted bytes differ')
        (output / identity['archive']).write_bytes(data)
        sbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
            'metadata': {'component': {'type': 'application', 'name': PRODUCT, 'version': VERSION}},
            'components': [{'type': 'file', 'name': name, 'hashes': [{'alg': 'SHA-256', 'content': hashlib.sha256(value).hexdigest()}]}
                           for name, value in sorted(files.items())]}
        sbom['components'] += [{'type': 'library', 'name': p['name'], 'version': p['version'],
                              'hashes': [{'alg': 'SHA-256', 'content': p['checksum']}]} for p in lock['package'] if p.get('checksum')]
        (output / (identity['archive'] + '.sbom.cdx.json')).write_text(json.dumps(sbom, indent=2, sort_keys=True) + '\n')


def package(root, output, core):
    from package_plugin import run
    pin = lifecycle_core.verify(core, root)
    build(root, output)
    identity = plugin_release.resolve(PRODUCT, root)
    archive = output / identity['archive']
    evidence = Path(os.environ.get('HARNESS_GATE_LIFECYCLE_ACCEPTANCE', str(output.parent / (output.name + '-acceptance'))))
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='lifecycle-extracted-') as temporary:
        installed = extract(archive.read_bytes(), Path(temporary), archive.name.removesuffix('.tar.gz'))
        report = evidence / 'docker-lifecycle.json'
        run('python3', str(installed / 'accept.py'), '--core', str(core / 'bin' / pin['binary']),
            '--core-sha256', pin['sha256'], '--binary', str(installed / BINARY), '--version', VERSION, '--report', str(report))
        result = json.loads(report.read_text())
        if result.get('passed') != 14 or len(result.get('cases', [])) != 14 or not all(c.get('passed') for c in result['cases']):
            raise ValueError('lifecycle package acceptance incomplete')
        result.update(archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(), source='extracted-package')
        report.write_text(json.dumps(result, indent=2) + '\n')
        from verify_lifecycle_acceptance import verify
        verify(report, archive)
