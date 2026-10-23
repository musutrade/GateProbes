"""Binary-only Core pin for the lifecycle adapter; no global contract change."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {'schema': 'gateprobes-podman-lifecycle-core/v1', 'repository': 'musutrade/GateHouse', 'release': 'v0.11.0', 'version': '0.11.0', 'source_commit': 'ddd950af6cfb703bee17d6f942165837b15f0deb', 'binary': 'harness-gate-linux-amd64', 'sha256': '912a65b17353226becf955de8e74a9c4b7389bf5b273c9a935c6fd68797b18f2'}


def contract(root=ROOT):
    value = json.loads((root / 'plugins/podman-lifecycle/core-pin.json').read_text())
    if value != EXPECTED:
        raise ValueError('unexpected lifecycle Core pin')
    return value


def verify(directory, root=ROOT):
    pin = contract(root)
    binary = directory / 'bin' / pin['binary']
    if binary.is_symlink() or not binary.is_file() or hashlib.sha256(binary.read_bytes()).hexdigest() != pin['sha256']:
        raise ValueError('lifecycle Core digest mismatch')
    result = subprocess.run([str(binary.resolve()), '--version'], capture_output=True, text=True, timeout=15, check=True)
    if result.stdout.strip() != 'harness-gate ' + pin['version'] or result.stderr:
        raise ValueError('lifecycle Core version mismatch')
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
        raise ValueError('downloaded lifecycle Core digest mismatch')
    binary.write_bytes(data)
    binary.chmod(0o500)
    verify(directory, root)
    (directory / 'contract.json').write_text(json.dumps(pin, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    prepare(parser.parse_args().output.resolve())
