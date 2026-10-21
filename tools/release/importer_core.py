"""Binary-only Core pin for the standalone importer; no global contract change."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {
    'schema': 'gateprobes-importer-core/v1', 'repository': 'musutrade/GateHouse',
    'release': 'v0.8.0', 'version': '0.8.0',
    'source_commit': '1fe08f79a46426027023fb921c9d5fa05d499922',
    'binary': 'harness-gate-linux-amd64',
    'sha256': '2b9748bd7ab66d201129922d9e46bfbef1d068fc6a10810666674529ddbd5693',
}


def contract(root=ROOT):
    value = json.loads((root / 'plugins/runtime-importer/core-pin.json').read_text())
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


def prepare(directory, root=ROOT):
    pin = contract(root)
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
    runtime = json.loads((root / 'tools/runtime_import/release-pin.json').read_text())
    names = {'gateprobes-docker-runtime-0.1.1-linux-amd64.tar.gz': 'archive_sha256',
             'gateprobes-docker-runtime-0.1.1-linux-amd64.tar.gz.sbom.cdx.json': 'sbom_sha256',
             'release-inventory.json': 'inventory_sha256', 'SHA256SUMS': 'checksums_sha256'}
    for name, field in names.items():
        url = f"https://github.com/musutrade/GateProbes/releases/download/docker-runtime-v0.1.1/{name}"
        with urllib.request.urlopen(url, timeout=60) as response:
            payload = response.read(16 * 1024 * 1024 + 1)
        if len(payload) > 16 * 1024 * 1024 or hashlib.sha256(payload).hexdigest() != runtime[field]:
            raise ValueError('importer runtime input digest mismatch')
        (assets / name).write_bytes(payload)
    (directory / 'contract.json').write_text(json.dumps(pin, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    prepare(parser.parse_args().output.resolve())
