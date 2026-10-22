"""Linux-only native runtime distribution, with extracted released-Core acceptance."""
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
import tarfile
import tempfile
import tomllib

import package_workload
import plugin_release
import runtime_build

TOOLCHAIN = '1.99.1'
BINARY = 'gateprobes-docker-runtime'


def archive_bytes(prefix, files, binary=BINARY):
    result = io.BytesIO()
    with gzip.GzipFile(fileobj=result, mode='wb', filename='', mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, data in sorted(files.items()):
                if '/' in name or name in ('', '.', '..') or not data:
                    raise RuntimeError('invalid runtime package member')
                info = tarfile.TarInfo(prefix + '/' + name)
                info.size = len(data)
                info.mode = 0o755 if name == binary else 0o644
                info.mtime = 0
                archive.addfile(info, io.BytesIO(data))
    return result.getvalue()


def product_profile(product):
    if product == 'docker-runtime':
        return BINARY, 'gate-runtime/v2', ['0.7.1'], ['inspect']
    if product == 'docker-readiness':
        return 'gateprobes-docker-readiness', 'gate-runtime/v3', ['0.9.0'], ['readiness']
    raise RuntimeError('unknown runtime product')


def validate_manifest(manifest, version, product='docker-runtime'):
    binary, protocol, core_versions, capabilities = product_profile(product)
    if product == 'docker-readiness' and version != '0.2.0':
        raise RuntimeError('readiness version mismatch')
    expected = {
        'schema': 'gateprobes-runtime-adapter/v1', 'name': product,
        'version': version, 'executable': binary, 'protocol': protocol,
        'authority': 'read-only-runtime-facts', 'platforms': ['linux-x86_64'],
        'core_versions': core_versions, 'status': 'release-candidate',
        'capabilities': capabilities,
        'limitations': [
            'fake-socket acceptance only; real Docker compatibility unproven',
            'no Absent or Remove',
            'no daemon attestation, restart detection or OS sandbox'],
    }
    if manifest != expected:
        raise RuntimeError('runtime manifest identity or scope mismatch')


def build(root: Path, output: Path, product='docker-runtime'):
    """Build reproducibility evidence only; this does not establish Core acceptance."""
    from package_plugin import run
    identity = plugin_release.resolve(product, root)
    binary, _, _, _ = product_profile(product)
    native = root / 'plugins/docker-runtime/native'
    manifest = json.loads(package_workload.checked_file(root, 'plugins/' + product + '/plugin.json'))
    cargo = tomllib.loads(package_workload.checked_file(root, 'plugins/docker-runtime/native/Cargo.toml').decode())
    if (cargo['package']['name'], cargo['package']['version']) != (BINARY, identity['version']):
        raise RuntimeError('runtime Cargo identity mismatch')
    validate_manifest(manifest, identity['version'], product)
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
                runtime_build.TARGET, '--bin', binary, '--manifest-path', str(native / 'Cargo.toml'), env=env)
            builds.append((target / runtime_build.TARGET / 'release' / binary).read_bytes())
        runtime_build.verify_inputs(root)
        if builds[0] != builds[1]:
            raise RuntimeError('clean runtime builds are not byte-identical')
        runtime_build.verify_static_pie(builds[0])
        files = {binary: builds[0]}
        for name, relative in {'plugin.json': 'plugin.json', 'README.md': 'native/README.md',
                               'Cargo.lock': 'native/Cargo.lock', 'rust-toolchain.toml': 'native/rust-toolchain.toml',
                               'build-inputs.json': 'native/build-inputs.json', 'accept.py': 'accept.py'}.items():
            product_file = name in {'plugin.json', 'accept.py'} or (name == 'README.md' and product == 'docker-readiness')
            relative = name if product_file else relative
            owner = product if product_file else 'docker-runtime'
            files[name] = package_workload.checked_file(root, 'plugins/' + owner + '/' + relative)
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
        archive = archive_bytes(prefix, files, binary)
        if archive != archive_bytes(prefix, files, binary):
            raise RuntimeError('runtime archive normalization is not deterministic')
        (output / identity['archive']).write_bytes(archive)
        extracted = stage / 'extracted'
        with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
            stream.extractall(extracted, filter='data')
        directory = extracted / prefix
        for name, expected in files.items():
            if (directory / name).read_bytes() != expected:
                raise RuntimeError('extracted runtime member differs')
        sbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
                'metadata': {'component': {'type': 'application', 'name': product, 'version': identity['version']}},
                'components': [{'type': 'file', 'name': name, 'hashes': [{'alg': 'SHA-256', 'content': hashlib.sha256(data).hexdigest()}]}
                               for name, data in sorted(files.items())]}
        sbom['components'] += [{'type': 'library', 'name': item['name'], 'version': item['version'],
                               'hashes': [{'alg': 'SHA-256', 'content': item['checksum']}]}
                              for item in lock.values() if item.get('checksum')]
        (output / (identity['archive'] + '.sbom.cdx.json')).write_text(json.dumps(sbom, indent=2, sort_keys=True) + '\n')


def package(root: Path, output: Path, core: Path, product="docker-runtime"):
    """Release entry: always build AND accept with the pinned Core."""
    from package_plugin import run
    build(root, output, product)
    identity = plugin_release.resolve(product, root)
    binary, _, _, _ = product_profile(product)
    with tempfile.TemporaryDirectory(prefix='runtime-accept-') as temporary:
        stage = Path(temporary)
        with tarfile.open(output / identity['archive']) as stream:
            stream.extractall(stage, filter='data')
        directory = stage / identity['archive'].removesuffix('.tar.gz')
        report = stage / 'acceptance.json'
        try:
            run('python3', str(directory / 'accept.py'), '--binary', str(directory / binary),
                '--core', str(core / 'bin/harness-gate-linux-amd64'), '--version', identity['version'],
                '--report', str(report))
        except subprocess.CalledProcessError:
            # This harness uses only disposable fake-socket inputs. Preserve its
            # bounded stderr diagnostics before the temporary stage is removed.
            try:
                for case in json.loads(report.read_text())['cases']:
                    if not case.get('ok'):
                        print('runtime acceptance diagnostic: ' + json.dumps({
                            'case': case.get('case'), 'exit': case.get('exit'),
                            'errors': case.get('errors'), 'stderr': case.get('stderr'),
                        }), file=sys.stderr)
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                print('runtime acceptance report unavailable or malformed', file=sys.stderr)
            raise

        finally:
            if report.is_file():
                evidence = Path(os.environ.get('HARNESS_GATE_RUNTIME_ACCEPTANCE',
                                               str(output.parent / (output.name + '-acceptance'))))
                evidence.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(report, evidence / (product + '.json'))
        if product == 'docker-readiness':
            result = json.loads(report.read_text())
            expected_cases = ['present', 'missing', 'unavailable', 'changed', 'timeout', 'fixed-expected']
            if (result.get('passed') != 6
                    or [case.get('case') for case in result.get('cases', [])] != expected_cases
                    or any(case.get('stderr') != '' or case.get('exit') != (0 if case['case'] == 'present' else 1)
                           for case in result['cases'])
                    or result.get('core_sha256') != hashlib.sha256((core / 'bin/harness-gate-linux-amd64').read_bytes()).hexdigest()
                    or result.get('adapter_sha256') != hashlib.sha256((directory / binary).read_bytes()).hexdigest()):
                raise RuntimeError('incomplete extracted readiness acceptance')
