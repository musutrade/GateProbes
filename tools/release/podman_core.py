"""Binary-only Core pin for the lifecycle adapter; no global contract change."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
def product_core_versions(root=ROOT):
    manifest = json.loads((root / 'plugins/podman-lifecycle/plugin.json').read_text())
    versions = manifest.get('core_versions')
    if not isinstance(versions, list) or not versions or not all(isinstance(v, str) for v in versions):
        raise ValueError('invalid lifecycle product core versions')
    return versions


EXPECTED_0_2 = {'schema': 'gateprobes-podman-lifecycle-core/v1', 'repository': 'musutrade/GateHouse', 'release': 'v0.12.0', 'version': '0.12.0', 'source_commit': '84a306e8f35674b79aaafa0a0fecd05d6087ac24', 'binary': 'harness-gate-linux-amd64', 'sha256': '6890e4465c9d86f53cffe8c58103a650babd03db895e27ae99928659c4f1d1d6'}


def contract(root=ROOT, core_versions=None):
    value = json.loads((root / 'plugins/podman-lifecycle/core-pin.json').read_text())
    versions = product_core_versions(root) if core_versions is None else core_versions
    if versions == ['0.12.0']:
        if value != EXPECTED_0_2:
            raise ValueError('unexpected historical lifecycle Core pin')
        return value
    if versions != ['0.13.0']:
        raise ValueError('unsupported lifecycle product core_versions')
    if (value.get('schema'), value.get('repository'), value.get('binary'),
            value.get('release'), value.get('version')) != (
            'gateprobes-podman-lifecycle-core/v1', 'musutrade/GateHouse',
            'harness-gate-linux-amd64', 'v0.13.0', '0.13.0'):
        raise ValueError('unexpected lifecycle Core0.13 pin')
    for key in ('source_commit', 'sha256'):
        if not isinstance(value.get(key), str) or not value[key]:
            raise ValueError('incomplete lifecycle Core0.13 pin')
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
