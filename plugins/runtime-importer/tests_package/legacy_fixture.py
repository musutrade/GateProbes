"""Explicit historical test fixture; never selected by publication dispatch."""
import json
import shutil
from pathlib import Path
import package_importer

LEGACY_MANIFEST = {'schema': 'gateprobes-runtime-importer-distribution/v1', 'name': 'runtime-importer', 'version': '0.1.0', 'authority': 'offline-installation-only', 'core_versions': ['0.8.0'], 'tested_platforms': ['linux-x86_64'], 'entrypoint': 'tools/runtime_import/install.py', 'runtime_tag': 'docker-runtime-v0.1.1'}

def create(source, destination):
    destination.mkdir(parents=True)
    for name in package_importer.NAMES:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    (destination / 'plugins/runtime-importer/plugin.json').write_text(json.dumps(LEGACY_MANIFEST))
    shutil.copyfile(source / 'plugins/releases.json', destination / 'plugins/releases.json')
    return destination
