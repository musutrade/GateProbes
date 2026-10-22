"""Explicit historical readiness fixture; never used by current publication dispatch."""
import json
import shutil
from verify_importer_archive import profile


def create(source, destination):
    destination.mkdir(parents=True)
    for name in profile('0.2.0')[1] | {'plugins/releases.json', 'tools/runtime_import/preflight.py'}:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    manifest = {'schema': 'gateprobes-runtime-importer-distribution/v1', 'name': 'runtime-importer',
                'version': '0.2.0', 'authority': 'offline-installation-only', 'core_versions': ['0.9.0'],
                'tested_platforms': ['linux-x86_64'], 'entrypoint': 'tools/runtime_import/install.py',
                'runtime_tag': 'docker-readiness-v0.2.0'}
    (destination / 'plugins/runtime-importer/plugin.json').write_text(json.dumps(manifest))
    return destination
