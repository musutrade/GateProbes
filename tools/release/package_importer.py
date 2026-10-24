"""Deterministic offline importer archive; acceptance runs extracted code only."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

import package_workload
import plugin_release

PRODUCT = 'runtime-importer'
NAMES = ('LICENSE', 'plugins/runtime-importer/README.md',
         'plugins/runtime-importer/plugin.json', 'plugins/runtime-importer/core-pin.json',
         'tools/runtime_import/install.py', 'tools/runtime_import/preflight.py',
         'tools/runtime_import/README.md', 'tools/runtime_import/release-pin.json')


def members(root, version):
    from verify_importer_archive import profile
    _, names = profile(version)
    files = {name: package_workload.checked_file(root, name) for name in names}
    manifest = json.loads(files['plugins/runtime-importer/plugin.json'])
    profiles = {
        '0.7.0': (['0.13.0', '0.14.1'], 'podman-lifecycle-v0.3.0'),
        '0.6.0': (['0.13.0'], 'podman-lifecycle-v0.3.0'),
        '0.5.0': (['0.12.0'], 'podman-lifecycle-v0.2.0'),
        '0.4.0': (['0.11.0'], 'podman-lifecycle-v0.1.0'),
        '0.3.0': (['0.10.0'], 'docker-lifecycle-v0.1.0'),
        '0.2.0': (['0.9.0'], 'docker-readiness-v0.2.0'),
    }
    core_versions, runtime_tag = profiles.get(version, (['0.8.0'], 'docker-runtime-v0.1.1'))
    expected = {'schema': 'gateprobes-runtime-importer-distribution/v1', 'name': PRODUCT,
                'version': version, 'authority': 'offline-installation-only',
                'core_versions': core_versions, 'tested_platforms': ['linux-x86_64'],
                'entrypoint': 'tools/runtime_import/install.py', 'runtime_tag': runtime_tag}
    if manifest != expected:
        raise ValueError('unexpected importer manifest')
    if version in ('0.4.0', '0.5.0', '0.6.0', '0.7.0'):
        from importer_core_podman import contract, runtime_contract
        runtime_contract(root)
    elif version == '0.3.0':
        from importer_core_lifecycle import contract, runtime_contract
        runtime_contract(root)
    elif version == '0.2.0':
        from importer_core_v3 import contract, runtime_contract
        runtime_contract(root)
    else:
        from importer_core import contract
    contract(root)
    return files


def build(root, output):
    identity = plugin_release.resolve(PRODUCT, root)
    files = members(root, identity['version'])
    archive = output / identity['archive']
    prefix = archive.name.removesuffix('.tar.gz')
    with archive.open('wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w', format=tarfile.USTAR_FORMAT) as stream:
            for name, data in sorted(files.items()):
                member = tarfile.TarInfo(f'{prefix}/{name}')
                member.size, member.mode, member.mtime = len(data), 0o644, 0
                stream.addfile(member, io.BytesIO(data))
    sbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
            'metadata': {'component': {'type': 'application', 'name': PRODUCT, 'version': identity['version']}},
            'components': [{'type': 'file', 'name': name, 'hashes': [{'alg': 'SHA-256', 'content': hashlib.sha256(data).hexdigest()}]} for name, data in sorted(files.items())]}
    (output / (archive.name + '.sbom.cdx.json')).write_text(json.dumps(sbom, indent=2) + '\n')
    return archive


def package(root, output, core, assets):
    import tempfile
    from accept_importer import accept
    version = plugin_release.resolve(PRODUCT, root)['version']
    if version in ('0.4.0', '0.5.0', '0.6.0', '0.7.0'):
        return package_podman(root, output, core, assets)
    if version == '0.3.0':
        return package_lifecycle(root, output, core, assets)
    if version == '0.2.0':
        return package_v3(root, output, core, assets)
    from importer_core import verify
    pin = verify(core, root)
    archive = build(root, output)
    with tempfile.TemporaryDirectory(prefix='importer-extracted-', dir=Path.home()) as temporary:
        from verify_importer_archive import extract
        data = archive.read_bytes()
        sbom = Path(str(archive) + '.sbom.cdx.json').read_bytes()
        # Local build identity only; downloaded releases require independently reviewed pins.
        installed = extract(data, sbom, hashlib.sha256(data).hexdigest(),
                            hashlib.sha256(sbom).hexdigest(), Path(temporary) / 'verified')
        if members(installed, plugin_release.resolve(PRODUCT, root)['version']) != members(root, plugin_release.resolve(PRODUCT, root)['version']):
            raise ValueError('extracted importer bytes differ')
        print(json.dumps(accept(installed, core / 'bin' / pin['binary'], assets), sort_keys=True))


def package_v3(root, output, core, assets):
    import os
    from package_plugin import run
    from importer_core_v3 import verify
    pin = verify(core, root)
    archive = build(root, output)
    sbom = Path(str(archive) + '.sbom.cdx.json')
    evidence = Path(os.environ.get('HARNESS_GATE_IMPORTER_ACCEPTANCE', str(output.parent / (output.name + '-acceptance'))))
    evidence.mkdir(parents=True, exist_ok=True)
    report = evidence / 'importer-v3.json'
    run('python3', str(root / 'tools/release/accept_importer_v3.py'),
        '--archive', str(archive), '--sbom', str(sbom),
        '--archive-sha256', hashlib.sha256(archive.read_bytes()).hexdigest(),
        '--sbom-sha256', hashlib.sha256(sbom.read_bytes()).hexdigest(),
        '--core', str(core / 'bin' / pin['binary']), '--assets', str(assets), '--report', str(report))
    result = json.loads(report.read_text())
    cases = ['present', 'missing', 'unavailable', 'changed', 'timeout', 'fixed-expected',
             'tampered-descriptor', 'tampered-executable', 'tampered-schema']
    if (result['passed'] != len(cases) or [case['case'] for case in result['cases']] != cases
            or any(case['exit'] != (0 if case['case'] == 'present' else 1) or case['stderr'] for case in result['cases'])
            or result['importer_archive_sha256'] != hashlib.sha256(archive.read_bytes()).hexdigest()
            or result['importer_sbom_sha256'] != hashlib.sha256(sbom.read_bytes()).hexdigest()
            or result['core_sha256'] != pin['sha256']):
        raise ValueError('incomplete v3 importer acceptance')


def package_lifecycle(root, output, core, assets):
    import os
    from package_plugin import run
    from importer_core_lifecycle import verify
    pin = verify(core, root)
    archive = build(root, output)
    sbom = Path(str(archive) + '.sbom.cdx.json')
    evidence = Path(os.environ.get('HARNESS_GATE_IMPORTER_ACCEPTANCE', str(output) + '-acceptance'))
    evidence.mkdir(parents=True, exist_ok=True)
    run('python3', str(root / 'tools/release/accept_importer_lifecycle.py'),
        '--archive', str(archive), '--sbom', str(sbom),
        '--archive-sha256', hashlib.sha256(archive.read_bytes()).hexdigest(),
        '--sbom-sha256', hashlib.sha256(sbom.read_bytes()).hexdigest(),
        '--core', str(core / 'bin' / pin['binary']), '--assets', str(assets),
        '--report', str(evidence / 'importer-lifecycle.json'))
    report = json.loads((evidence / 'importer-lifecycle.json').read_bytes())
    expected_cases = ['normal', 'health-failure', 'host-digest', 'host-symlink', 'host-mode',
                      'installation-product', 'installation-version', 'installation-protocol',
                      'config-schema', 'config-principal', 'config-engine', 'executable-digest',
                      'executable-mode', 'descriptor-symlink']
    if (report['passed'] != 14 or [c['case'] for c in report['cases']] != expected_cases
            or not all(c['passed'] for c in report['cases'])
            or any(c['requests'] for c in report['cases'][2:])
            or report['core_sha256'] != pin['sha256']
            or report['importer_archive_sha256'] != hashlib.sha256(archive.read_bytes()).hexdigest()
            or report['importer_sbom_sha256'] != hashlib.sha256(sbom.read_bytes()).hexdigest()):
        raise ValueError('incomplete lifecycle importer acceptance')


def package_podman(root, output, core, assets):
    import os
    from package_plugin import run
    from importer_core_podman import verify
    version = plugin_release.resolve(PRODUCT, root)['version']
    pin = verify(core, root, version)
    archive = build(root, output)
    sbom = Path(str(archive) + '.sbom.cdx.json')
    evidence = Path(os.environ.get('HARNESS_GATE_IMPORTER_ACCEPTANCE', str(output) + '-acceptance'))
    evidence.mkdir(parents=True, exist_ok=True)
    if version in ('0.6.0', '0.7.0'):
        if version == '0.6.0':
            from accept_importer_podman06 import verify_report
            script, name = 'accept_importer_podman06.py', 'importer-podman06.json'
        else:
            from accept_importer_podman07 import verify_report
            script, name = 'accept_importer_podman07.py', 'importer-podman07.json'
        report = evidence / name
        run('python3', str(root / 'tools/release' / script),
            '--archive', str(archive), '--sbom', str(sbom),
            '--archive-sha256', hashlib.sha256(archive.read_bytes()).hexdigest(),
            '--sbom-sha256', hashlib.sha256(sbom.read_bytes()).hexdigest(),
            '--core', str(core / 'bin' / pin['binary']), '--assets', str(assets),
            '--report', str(report))
        verify_report(json.loads(report.read_bytes()), archive.read_bytes(), sbom.read_bytes(), core)
        return
    from accept_importer_podman import verify_report
    report = evidence / 'importer-podman.json'
    run('python3', str(root / 'tools/release/accept_importer_podman.py'),
        '--archive', str(archive), '--sbom', str(sbom),
        '--archive-sha256', hashlib.sha256(archive.read_bytes()).hexdigest(),
        '--sbom-sha256', hashlib.sha256(sbom.read_bytes()).hexdigest(),
        '--core', str(core / 'bin' / pin['binary']), '--assets', str(assets),
        '--report', str(report))
    verify_report(json.loads(report.read_bytes()), archive.read_bytes(), sbom.read_bytes())
