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


def package(root: Path, output: Path, core: Path):
    from package_plugin import run
    identity = plugin_release.resolve('operator-lifecycle', root)
    source = root / 'plugins/operator-lifecycle'
    with tempfile.TemporaryDirectory(prefix='operator-package-') as tmp:
        stage = Path(tmp)
        env = dict(os.environ, CARGO_TARGET_DIR=str(stage / 'target'))
        manifest = source / 'Cargo.toml'
        run('cargo', 'build', '--locked', '--release', '--manifest-path', str(manifest), env=env)
        run('cargo', 'test', '--locked', '--manifest-path', str(manifest), env=env)
        directory = stage / identity['archive'].removesuffix('.tar.gz')
        directory.mkdir()
        shutil.copy2(stage / 'target/release/gateprobes-operator', directory / 'gateprobes-operator')
        for name in ('README.md', 'LICENSE', 'plugin.json', 'Cargo.lock'):
            shutil.copy2(source / name, directory / name)
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
                texts, _ = module.registry_notices(dependency, lock)
                notices.extend(f"{dependency['name']} {dependency['version']} / {name}\n{text}"
                               for name, text in sorted(texts.items()))
        sysroot = Path(run('rustc', '--print', 'sysroot').strip())
        notices.append((sysroot / 'share/doc/rust/COPYRIGHT-library.html').read_text())
        (directory / 'THIRD_PARTY_NOTICES.txt').write_text('\n\n'.join(notices))
        archive = output / identity['archive']
        with tarfile.open(archive, 'w:gz') as stream:
            stream.add(directory, arcname=directory.name)
        with tarfile.open(archive) as stream:
            stream.extractall(stage / 'extracted', filter='data')
        run('python3', str(source / 'accept.py'), '--binary',
            str(stage / 'extracted' / directory.name / 'gateprobes-operator'),
            '--core', str(core / 'bin/harness-gate-linux-amd64'))
        run('python3', str(core / 'tools/release/generate-sbom.py'), '--metadata', str(metadata),
            '--lockfile', str(source / 'Cargo.lock'), '--output', str(output / (archive.name + '.sbom.cdx.json')))
