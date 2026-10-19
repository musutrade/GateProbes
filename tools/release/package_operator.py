"""Independent operator binary package; reuse release inventory and SBOM tools."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import tomllib

import plugin_release

MEMBERS = ('gateprobes-operator', 'README.md', 'LICENSE', 'plugin.json', 'Cargo.lock',
           'THIRD_PARTY_NOTICES.txt')
# Reviewed crates that declare a license but ship no license file in the published
# archive. They receive an identity/expression/checksum notice instead of text.
METADATA_ONLY_NOTICES = {('r-efi', '6.0.0')}


def package(root: Path, output: Path, core: Path):
    from package_plugin import run
    identity = plugin_release.resolve('operator-lifecycle', root)
    version = identity['version']
    source = root / 'plugins/operator-lifecycle'
    with tempfile.TemporaryDirectory(prefix='operator-package-') as tmp:
        stage = Path(tmp)
        env = dict(os.environ, CARGO_TARGET_DIR=str(stage / 'target'))
        manifest = source / 'Cargo.toml'
        run('cargo', 'build', '--locked', '--release', '--manifest-path', str(manifest), env=env)
        run('cargo', 'test', '--locked', '--manifest-path', str(manifest), env=env)
        built = stage / 'target/release/gateprobes-operator'
        check_version(run(str(built), '--version').strip(), version)
        directory = stage / identity['archive'].removesuffix('.tar.gz')
        directory.mkdir()
        for name in MEMBERS:
            if name == 'THIRD_PARTY_NOTICES.txt':
                continue
            target = directory / name
            if name == 'gateprobes-operator':
                shutil.copy2(built, target)
            else:
                shutil.copy2(source / name, target)
            if target.stat().st_size == 0:
                raise RuntimeError('empty operator package member: ' + name)
        metadata = stage / 'metadata.json'
        metadata.write_text(run('cargo', 'metadata', '--locked', '--format-version', '1',
                                '--manifest-path', str(manifest), env=env, echo=False))
        spec = importlib.util.spec_from_file_location('notices', root / 'plugins/rust-native-plugin/locked_notices.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        lock = {(p['name'], p['version'], p.get('source')): p for p in
                tomllib.loads((source / 'Cargo.lock').read_text())['package']}
        notices = []
        for dependency in json.loads(metadata.read_text())['packages']:
            if dependency['source']:
                try:
                    texts, _ = module.registry_notices(dependency, lock)
                    notices.extend(f"{dependency['name']} {dependency['version']} / {name}\n{text}"
                                   for name, text in sorted(texts.items()))
                except ValueError as error:
                    key = (dependency['name'], dependency['version'])
                    if 'missing crate license notices' not in str(error) or key not in METADATA_ONLY_NOTICES:
                        raise
                    digest = lock[(dependency['name'], dependency['version'], dependency['source'])]['checksum']
                    notices.append(
                        f"{dependency['name']} {dependency['version']} / metadata-only\n"
                        f"declared license: {dependency['license']}\n"
                        f"crate sha256: {digest}\n"
                        "This upstream crate does not bundle license files; the declared "
                        "expression and locked archive digest are recorded here.\n")
        sysroot = Path(run('rustc', '--print', 'sysroot').strip())
        notices.append((sysroot / 'share/doc/rust/COPYRIGHT-library.html').read_text())
        (directory / 'THIRD_PARTY_NOTICES.txt').write_text('\n\n'.join(notices))
        if (directory / 'THIRD_PARTY_NOTICES.txt').stat().st_size < 1024:
            raise RuntimeError('third-party notices are unexpectedly small')
        archive = output / identity['archive']
        with tarfile.open(archive, 'w:gz') as stream:
            stream.add(directory, arcname=directory.name)
        with tarfile.open(archive) as stream:
            expected = {directory.name + '/' + name for name in MEMBERS}
            members = stream.getmembers()
            names = {member.name for member in members}
            if names != expected | {directory.name}:
                raise RuntimeError('operator archive members differ: ' + repr(sorted(names ^ (expected | {directory.name}))))
            for member in members:
                if member.name == directory.name:
                    if not member.isdir():
                        raise RuntimeError('operator archive root is not a directory')
                    continue
                if not member.isfile():
                    raise RuntimeError('operator archive contains a non-file member: ' + member.name)
                parts = Path(member.name).parts
                if len(parts) != 2 or any(part in ('', '.', '..') for part in parts):
                    raise RuntimeError('unsafe absolute operator archive member: ' + member.name)
            stream.extractall(stage / 'extracted', filter='data')
        extracted = stage / 'extracted' / directory.name
        if not (extracted / 'gateprobes-operator').stat().st_mode & 0o111:
            raise RuntimeError('packaged operator binary is not executable')
        check_version(run(str(extracted / 'gateprobes-operator'), '--version').strip(), version)
        run('python3', str(source / 'accept.py'), '--binary',
            str(extracted / 'gateprobes-operator'),
            '--core', str(core / 'bin/harness-gate-linux-amd64'))
        sbom_path = output / (archive.name + '.sbom.cdx.json')
        run('python3', str(core / 'tools/release/generate-sbom.py'), '--metadata', str(metadata),
            '--lockfile', str(source / 'Cargo.lock'), '--output', str(sbom_path))
        sbom = json.loads(sbom_path.read_text())
        component = sbom['metadata']['component']
        if (component['name'], component['version']) != ('gateprobes-operator', version):
            raise RuntimeError('SBOM component identity mismatch')
        if not any((c.get('name'), c.get('version')) == ('gateprobes-operator', version)
                   for c in sbom['components']):
            raise RuntimeError('SBOM component list omits the packaged operator')


def check_version(text: str, version: str) -> None:
    if text != 'gateprobes-operator ' + version:
        raise RuntimeError('operator version output mismatch: ' + text)
