"""Linux-only native runtime distribution, with extracted released-Core acceptance."""
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import tomllib

import package_workload
import plugin_release
import runtime_build

TOOLCHAIN = '1.99.1'
BINARY = 'gateprobes-docker-runtime'


def archive_bytes(prefix, files):
    result = io.BytesIO()
    with gzip.GzipFile(fileobj=result, mode='wb', filename='', mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, data in sorted(files.items()):
                if '/' in name or name in ('', '.', '..') or not data:
                    raise RuntimeError('invalid runtime package member')
                info = tarfile.TarInfo(prefix + '/' + name)
                info.size = len(data)
                info.mode = 0o755 if name == BINARY else 0o644
                info.mtime = 0
                archive.addfile(info, io.BytesIO(data))
    return result.getvalue()


def validate_manifest(manifest, version):
    expected = {
        'schema': 'gateprobes-runtime-adapter/v1', 'name': 'docker-runtime',
        'version': version, 'executable': BINARY, 'protocol': 'gate-runtime/v2',
        'authority': 'read-only-runtime-facts', 'platforms': ['linux-x86_64'],
        'core_versions': ['0.7.1'], 'status': 'release-candidate',
        'capabilities': ['inspect'],
        'limitations': [
            'fake-socket acceptance only; real Docker compatibility unproven',
            'no Absent or Remove',
            'no daemon attestation, restart detection or OS sandbox'],
    }
    if manifest != expected:
        raise RuntimeError('runtime manifest identity or scope mismatch')


def package(root: Path, output: Path, core: Path):
    from package_plugin import run
    identity = plugin_release.resolve('docker-runtime', root)
    source = root / 'plugins/docker-runtime'
    native = source / 'native'
    manifest = json.loads(package_workload.checked_file(root, 'plugins/docker-runtime/plugin.json'))
    cargo = tomllib.loads(package_workload.checked_file(root, 'plugins/docker-runtime/native/Cargo.toml').decode())
    if (cargo['package']['name'], cargo['package']['version']) != (BINARY, identity['version']):
        raise RuntimeError('runtime Cargo identity mismatch')
    validate_manifest(manifest, identity['version'])
    if tomllib.loads((native / 'rust-toolchain.toml').read_text())['toolchain']['channel'] != TOOLCHAIN:
        raise RuntimeError('runtime toolchain mismatch')
    pinned_sysroot, _ = runtime_build.verify_inputs(root)
    with tempfile.TemporaryDirectory(prefix='runtime-package-') as temporary:
        stage = Path(temporary)
        builds = []
        for index in range(2):
            target = stage / f'target-{index}'
            env = runtime_build.environment(root, target, stage, pinned_sysroot)
            run('cargo', '+' + TOOLCHAIN, 'build', '--locked', '--release', '--target',
                runtime_build.TARGET, '--manifest-path', str(native / 'Cargo.toml'), env=env)
            builds.append((target / runtime_build.TARGET / 'release' / BINARY).read_bytes())
        runtime_build.verify_inputs(root)
        if builds[0] != builds[1]:
            raise RuntimeError('clean runtime builds are not byte-identical')
        runtime_build.verify_static_pie(builds[0])
        files = {BINARY: builds[0]}
        for name, relative in {'plugin.json': 'plugin.json', 'README.md': 'native/README.md',
                               'Cargo.lock': 'native/Cargo.lock', 'rust-toolchain.toml': 'native/rust-toolchain.toml',
                               'build-inputs.json': 'native/build-inputs.json', 'accept.py': 'accept.py'}.items():
            files[name] = package_workload.checked_file(root, 'plugins/docker-runtime/' + relative)
        files['LICENSE'] = package_workload.checked_file(root, 'LICENSE')
        metadata = json.loads(run('cargo', '+' + TOOLCHAIN, 'metadata', '--locked', '--format-version', '1',
                                 '--manifest-path', str(native / 'Cargo.toml'), env=env, echo=False))
        spec = importlib.util.spec_from_file_location('runtime_notices', root / 'plugins/rust-native-plugin/locked_notices.py')
        notices = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(notices)
        lock = {(p['name'], p['version'], p.get('source')): p for p in tomllib.loads(files['Cargo.lock'].decode())['package']}
        texts = []
        for dependency in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
            if dependency['source']:
                entries, _ = notices.registry_notices(dependency, lock)
                texts.extend(f"{dependency['name']} {dependency['version']} / {name}\n{text}"
                             for name, text in sorted(entries.items()))
        sysroot = Path(run('rustc', '+' + TOOLCHAIN, '--print', 'sysroot').strip())
        texts.append((sysroot / 'share/doc/rust/COPYRIGHT-library.html').read_text())
        files['THIRD_PARTY_NOTICES.txt'] = '\n\n'.join(texts).encode()
        prefix = identity['archive'].removesuffix('.tar.gz')
        archive = archive_bytes(prefix, files)
        if archive != archive_bytes(prefix, files):
            raise RuntimeError('runtime archive normalization is not deterministic')
        (output / identity['archive']).write_bytes(archive)
        extracted = stage / 'extracted'
        with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
            stream.extractall(extracted, filter='data')
        directory = extracted / prefix
        for name, expected in files.items():
            if (directory / name).read_bytes() != expected:
                raise RuntimeError('extracted runtime member differs')
        run('python3', str(directory / 'accept.py'), '--binary', str(directory / BINARY),
            '--core', str(core / 'bin/harness-gate-linux-amd64'), '--version', identity['version'],
            '--report', str(stage / 'acceptance.json'))
        sbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
                'metadata': {'component': {'type': 'application', 'name': 'docker-runtime', 'version': identity['version']}},
                'components': [{'type': 'file', 'name': name, 'hashes': [{'alg': 'SHA-256', 'content': hashlib.sha256(data).hexdigest()}]}
                               for name, data in sorted(files.items())]}
        sbom['components'] += [{'type': 'library', 'name': item['name'], 'version': item['version'],
                               'hashes': [{'alg': 'SHA-256', 'content': item['checksum']}]}
                              for item in lock.values() if item.get('checksum')]
        (output / (identity['archive'] + '.sbom.cdx.json')).write_text(json.dumps(sbom, indent=2, sort_keys=True) + '\n')
