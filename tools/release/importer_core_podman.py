"""Binary-only Core pin for the importer0.4; historical importer0.1 pins remain unchanged."""
import argparse
import hashlib
import json
import importlib.util
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {'schema': 'gateprobes-importer-core/v2', 'repository': 'musutrade/GateHouse', 'release': 'v0.11.0', 'version': '0.11.0', 'source_commit': 'ddd950af6cfb703bee17d6f942165837b15f0deb', 'binary': 'harness-gate-linux-amd64', 'sha256': '912a65b17353226becf955de8e74a9c4b7389bf5b273c9a935c6fd68797b18f2'}


def contract(root=ROOT):
    value = json.loads((root / 'plugins/runtime-importer/core-pin-podman.json').read_text())
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
    value = validator.pin((root / 'tools/runtime_import/release-pin-podman.json').read_bytes())
    if value != {'schema': 'gateprobes-runtime-release-pin/v1', 'repository': 'https://github.com/musutrade/GateProbes', 'tag': 'podman-lifecycle-v0.1.0', 'version': '0.1.0', 'source_commit': '4b79bc13391fb015c51d9ac77959dfd2072d892d', 'executable_sha256': '88208b6fb4182f008851c1706d780ef2d4edd812ba54196accedb77939267bda', 'archive_sha256': '7869c259f640fb6de7580debd748fa5467c5291f88bc16b20bab74603024772f', 'sbom_sha256': 'e216d89025a73d59edc72e833b4665aa792d2317c8b05a6e0068f2c99feffff4', 'inventory_sha256': 'ef91e1d00226208dc793084ad59d38504af76988c285c4786b19a53775ae8e9b', 'checksums_sha256': '84be3f4cb64e468a21077dc787ce1a0d787122335f300acdf2e8bc63896ccee2'}:
        raise ValueError('importer0.4 requires the reviewed lifecycle0.1 release')
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
    names = {'gateprobes-podman-lifecycle-0.1.0-linux-amd64.tar.gz': 'archive_sha256',
             'gateprobes-podman-lifecycle-0.1.0-linux-amd64.tar.gz.sbom.cdx.json': 'sbom_sha256',
             'release-inventory.json': 'inventory_sha256', 'SHA256SUMS': 'checksums_sha256'}
    for name, field in names.items():
        url = f"https://github.com/musutrade/GateProbes/releases/download/podman-lifecycle-v0.1.0/{name}"
        with urllib.request.urlopen(url, timeout=60) as response:
            payload = response.read(16 * 1024 * 1024 + 1)
        if len(payload) > 16 * 1024 * 1024 or hashlib.sha256(payload).hexdigest() != runtime[field]:
            raise ValueError('importer runtime input digest mismatch')
        (assets / name).write_bytes(payload)
    validator.validate((root / 'tools/runtime_import/release-pin-podman.json').read_bytes(),
                       *[(assets / name).read_bytes() for name in names])
    (directory / 'contract.json').write_text(json.dumps(pin, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    prepare(parser.parse_args().output.resolve())
