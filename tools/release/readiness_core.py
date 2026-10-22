"""Binary-only Core pin for the readiness adapter; no global contract change."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {
    'schema': 'gateprobes-readiness-core/v1', 'repository': 'musutrade/GateHouse',
    'release': 'v0.9.0', 'version': '0.9.0',
    'source_commit': '0a7bd647aec05c1da835a7abcf4a7cb7e9d9aef5',
    'binary': 'harness-gate-linux-amd64',
    'sha256': '58d58b639952bf7c78aef63e15e245a8825ce3d8731f7a4980e3ea9ce578ad79',
}


def contract(root=ROOT):
    value = json.loads((root / 'plugins/docker-readiness/core-pin.json').read_text())
    if value != EXPECTED:
        raise ValueError('unexpected readiness Core pin')
    return value


def verify(directory, root=ROOT):
    pin = contract(root)
    binary = directory / 'bin' / pin['binary']
    if binary.is_symlink() or not binary.is_file() or hashlib.sha256(binary.read_bytes()).hexdigest() != pin['sha256']:
        raise ValueError('readiness Core digest mismatch')
    result = subprocess.run([str(binary.resolve()), '--version'], capture_output=True, text=True, timeout=15, check=True)
    if result.stdout.strip() != 'harness-gate ' + pin['version'] or result.stderr:
        raise ValueError('readiness Core version mismatch')
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
        raise ValueError('downloaded readiness Core digest mismatch')
    binary.write_bytes(data)
    binary.chmod(0o500)
    verify(directory, root)
    (directory / 'contract.json').write_text(json.dumps(pin, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    prepare(parser.parse_args().output.resolve())
