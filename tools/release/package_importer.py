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
    files = {name: package_workload.checked_file(root, name) for name in NAMES}
    manifest = json.loads(files['plugins/runtime-importer/plugin.json'])
    expected = {'schema': 'gateprobes-runtime-importer-distribution/v1', 'name': PRODUCT,
                'version': version, 'authority': 'offline-installation-only',
                'core_versions': ['0.8.0'], 'tested_platforms': ['linux-x86_64'],
                'entrypoint': 'tools/runtime_import/install.py', 'runtime_tag': 'docker-runtime-v0.1.1'}
    if manifest != expected:
        raise ValueError('unexpected importer manifest')
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
    from importer_core import verify
    pin = verify(core, root)
    archive = build(root, output)
    with tempfile.TemporaryDirectory(prefix='importer-extracted-', dir=Path.home()) as temporary:
        work = Path(temporary)
        with tarfile.open(archive) as stream:
            stream.extractall(work, filter='data')
        installed = work / archive.name.removesuffix('.tar.gz')
        if members(installed, plugin_release.resolve(PRODUCT, root)['version']) != members(root, plugin_release.resolve(PRODUCT, root)['version']):
            raise ValueError('extracted importer bytes differ')
        print(json.dumps(accept(installed, core / 'bin' / pin['binary'], assets), sort_keys=True))
