"""Binary-only Core pin for the Podman importer0.5; historical importer pins remain unchanged."""
import argparse
import hashlib
import json
import importlib.util
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {'schema': 'gateprobes-importer-core/v2', 'repository': 'musutrade/GateHouse', 'release': 'v0.12.0', 'version': '0.12.0', 'source_commit': '84a306e8f35674b79aaafa0a0fecd05d6087ac24', 'binary': 'harness-gate-linux-amd64', 'sha256': '6890e4465c9d86f53cffe8c58103a650babd03db895e27ae99928659c4f1d1d6'}


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
    if value != {'schema': 'gateprobes-runtime-release-pin/v1', 'repository': 'https://github.com/musutrade/GateProbes', 'tag': 'podman-lifecycle-v0.2.0', 'version': '0.2.0', 'source_commit': 'e376df9a8021f9351525da630c5e3bb1ad83c767', 'executable_sha256': 'c14a30f4f91c54ce2f0a46f60de6293cbc3b225b9f5cf5dc286ac98b2b032f7b', 'archive_sha256': 'e3112a8dffb289a5e88de9aed8c1f6bfc3eae91169a1bbd45d05db63a22e1874', 'sbom_sha256': '16b22c74068895817a356abf58199137d59da03a552402e2fce63fc36688040d', 'inventory_sha256': '3b8f677ad84efcc3f03c62123772f2f442242a20f9dbaa253b85a627be6000e8', 'checksums_sha256': '20c462222d9ca52abf1f9ae14cba1a84504240d626a0f8e39fa1039008cb6845'}:
        raise ValueError('importer0.5 requires the reviewed Podman0.2 release')
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
    names = {'gateprobes-podman-lifecycle-0.2.0-linux-amd64.tar.gz': 'archive_sha256',
             'gateprobes-podman-lifecycle-0.2.0-linux-amd64.tar.gz.sbom.cdx.json': 'sbom_sha256',
             'release-inventory.json': 'inventory_sha256', 'SHA256SUMS': 'checksums_sha256'}
    for name, field in names.items():
        url = f"https://github.com/musutrade/GateProbes/releases/download/podman-lifecycle-v0.2.0/{name}"
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
