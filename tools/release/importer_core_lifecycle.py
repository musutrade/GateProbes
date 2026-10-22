"""Binary-only Core pin for the importer0.3; historical importer0.1 pins remain unchanged."""
import argparse
import hashlib
import json
import importlib.util
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {
    'schema': 'gateprobes-importer-core/v2', 'repository': 'musutrade/GateHouse',
    'release': 'v0.10.0', 'version': '0.10.0',
    'source_commit': 'd8505fc25b777ae8cb45e9131e6144ad261ef8df',
    'binary': 'harness-gate-linux-amd64',
    'sha256': 'fa7a3a355d136267765c017f48b59acf0a6e1bcc581cc57cac67107beb8c6ab8',
}


def contract(root=ROOT):
    value = json.loads((root / 'plugins/runtime-importer/core-pin-lifecycle.json').read_text())
    if value != EXPECTED:
        raise ValueError('unexpected importer Core pin')
    return value


def verify(directory, root=ROOT):
    pin = contract(root)
    binary = directory / 'bin' / pin['binary']
    if binary.is_symlink() or not binary.is_file() or hashlib.sha256(binary.read_bytes()).hexdigest() != pin['sha256']:
        raise ValueError('importer Core digest mismatch')
    result = subprocess.run([str(binary.resolve()), '--version'], capture_output=True, text=True, timeout=15, check=True)
    if result.stdout.strip() != 'harness-gate ' + pin['version'] or result.stderr:
        raise ValueError('importer Core version mismatch')
    return pin


def runtime_contract(root=ROOT):
    # Load verifier only from the trusted checkout, never from a downloaded archive.
    spec = importlib.util.spec_from_file_location('trusted_importer_v3_preflight',
                                                 root / 'tools/runtime_import/preflight.py')
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    value = validator.pin((root / 'tools/runtime_import/release-pin-lifecycle.json').read_bytes())
    if value != {'schema': 'gateprobes-runtime-release-pin/v1', 'repository': 'https://github.com/musutrade/GateProbes', 'tag': 'docker-lifecycle-v0.1.0', 'version': '0.1.0', 'source_commit': '8ca5958ba462727612b9c9ec21f6fe49aeddda0b', 'archive_sha256': '77695bdbbe4eff4fb8fc65c2b9998cbaa639f002582601c6fc703c16639fb821', 'sbom_sha256': '6a86202cad79b1d2bb643b3ebb3e7c697a31095df06a32df3ebf940476d56b64', 'inventory_sha256': 'e40b05f499463b594a1db2ca69802e76d6aa9d6db6c566d5fa1afb51dc278753', 'checksums_sha256': 'e924c50f32aa3af9afde78103c61479c9820e60560892462031aafa87b23aa82', 'executable_sha256': '305b5ec670891e351d1222fbe6469b381a6f310e8aa628c6810d6a3b0693ee9d'}:
        raise ValueError('importer0.3 requires the reviewed lifecycle0.1 release')
    return value, validator


def prepare(directory, root=ROOT):
    pin = contract(root)
    runtime, validator = runtime_contract(root)
    directory.mkdir(parents=True, exist_ok=False)
    binary = directory / 'bin' / pin['binary']
    binary.parent.mkdir()
    url = f"https://github.com/{pin['repository']}/releases/download/{pin['release']}/{pin['binary']}"
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(128 * 1024 * 1024 + 1)
    if len(data) > 128 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != pin['sha256']:
        raise ValueError('downloaded importer Core digest mismatch')
    binary.write_bytes(data)
    binary.chmod(0o500)
    verify(directory, root)
    assets = directory / 'runtime-assets'
    assets.mkdir()
    names = {'gateprobes-docker-lifecycle-0.1.0-linux-amd64.tar.gz': 'archive_sha256',
             'gateprobes-docker-lifecycle-0.1.0-linux-amd64.tar.gz.sbom.cdx.json': 'sbom_sha256',
             'release-inventory.json': 'inventory_sha256', 'SHA256SUMS': 'checksums_sha256'}
    for name, field in names.items():
        url = f"https://github.com/musutrade/GateProbes/releases/download/docker-lifecycle-v0.1.0/{name}"
        with urllib.request.urlopen(url, timeout=60) as response:
            payload = response.read(16 * 1024 * 1024 + 1)
        if len(payload) > 16 * 1024 * 1024 or hashlib.sha256(payload).hexdigest() != runtime[field]:
            raise ValueError('importer runtime input digest mismatch')
        (assets / name).write_bytes(payload)
    validator.validate((root / 'tools/runtime_import/release-pin-lifecycle.json').read_bytes(),
                       *[(assets / name).read_bytes() for name in names])
    (directory / 'contract.json').write_text(json.dumps(pin, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    prepare(parser.parse_args().output.resolve())
