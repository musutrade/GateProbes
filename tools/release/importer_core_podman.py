"""Binary-only Core pins for the Podman importer0.5/0.6/0.7; historical pins remain unchanged."""
import argparse
import hashlib
import json
import importlib.util
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {'schema': 'gateprobes-importer-core/v2', 'repository': 'musutrade/GateHouse', 'release': 'v0.12.0', 'version': '0.12.0', 'source_commit': '84a306e8f35674b79aaafa0a0fecd05d6087ac24', 'binary': 'harness-gate-linux-amd64', 'sha256': '6890e4465c9d86f53cffe8c58103a650babd03db895e27ae99928659c4f1d1d6'}
EXPECTED_0_6 = {'schema': 'gateprobes-importer-core/v2', 'repository': 'musutrade/GateHouse', 'release': 'v0.13.0', 'version': '0.13.0', 'source_commit': '565e622f77659e48604cfb9508adee14765de323', 'binary': 'harness-gate-linux-amd64', 'sha256': '1800325ea2f541dd9b011c03dc93c3dac341e839ece6289ebe778275dcaacf75'}
EXPECTED_0_7 = {'schema': 'gateprobes-importer-core/v2', 'repository': 'musutrade/GateHouse', 'release': 'v0.14.1', 'version': '0.14.1', 'source_commit': 'c22a12e25a5ea6f617d4afb9dd4e2410dc14f267', 'binary': 'harness-gate-linux-amd64', 'sha256': '6b4f36d432266e43e22d82776729d76f04098c5cf63ae2295f508359a37e060c'}
RUNTIME_0_3 = {'schema': 'gateprobes-runtime-release-pin/v1', 'repository': 'https://github.com/musutrade/GateProbes', 'tag': 'podman-lifecycle-v0.3.0', 'version': '0.3.0', 'source_commit': 'c802fffaee9fdbea1ce9d4642ac14cb998882b20', 'executable_sha256': 'efca5ba3b8e8bbbf0d7cce0efdce12b3f58fba190e01ba790bac81650c972d9d', 'archive_sha256': '044a1e9d6d7be82ca8e83b8f810ce6c266825a793d77f418d14efd13a69d69a0', 'sbom_sha256': 'f66dbe03e8c7b1f8cc20f93b1ad3857ec908b6f4158073965a2b515a64bbf262', 'inventory_sha256': '8713afa1cb1fa52509d36541ffc8d0098a6defc00f2ba1bc4e5beb8793a5bc4b', 'checksums_sha256': '389c309ec6deb477815e25c6919616f17cbcbdfd27acfc9c27dba76a902bf12c'}
PROFILES = {
    '0.5.0': {'core': '0.12.0', 'runtime_tag': 'podman-lifecycle-v0.2.0', 'runtime_version': '0.2.0'},
    '0.6.0': {'core': '0.13.0', 'runtime_tag': 'podman-lifecycle-v0.3.0', 'runtime_version': '0.3.0'},
    '0.7.0': {'core': '0.14.1', 'runtime_tag': 'podman-lifecycle-v0.3.0', 'runtime_version': '0.3.0'},
}


def profile(version):
    try:
        return {'version': version, **PROFILES[version]}
    except KeyError:
        raise ValueError('unsupported Podman importer version') from None


def plugin_version(root=ROOT):
    manifest = json.loads((root / 'plugins/runtime-importer/plugin.json').read_text())
    return profile(manifest['version'])['version']


def contract(root=ROOT, version=None):
    version = plugin_version(root) if version is None else version
    value = json.loads((root / 'plugins/runtime-importer/core-pin-podman.json').read_text())
    if version == '0.5.0' and value != EXPECTED:
        raise ValueError('unexpected importer Core pin')
    if version == '0.6.0' and value != EXPECTED_0_6:
        raise ValueError('unexpected importer Core0.6 pin')
    if version == '0.7.0' and value != EXPECTED_0_7:
        raise ValueError('unexpected importer Core0.7 pin')
    return value


def verify(directory, root=ROOT, version=None):
    version = plugin_version(root) if version is None else version
    pin = contract(root, version)
    binary = directory / 'bin' / pin['binary']
    if binary.is_symlink() or not binary.is_file() or hashlib.sha256(binary.read_bytes()).hexdigest() != pin['sha256']:
        raise ValueError('importer Core digest mismatch')
    result = subprocess.run([str(binary.resolve()), '--version'], capture_output=True, text=True, timeout=15, check=True)
    if result.stdout.strip() != 'harness-gate ' + pin['version'] or result.stderr:
        raise ValueError('importer Core version mismatch')
    return pin


def runtime_contract(root=ROOT, version=None):
    version = plugin_version(root) if version is None else version
    expected = profile(version)
    # Load verifier only from the trusted checkout, never from a downloaded archive.
    spec = importlib.util.spec_from_file_location('trusted_importer_v3_preflight',
                                                 root / 'tools/runtime_import/preflight.py')
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    value = validator.pin((root / 'tools/runtime_import/release-pin-podman.json').read_bytes())
    if version == '0.5.0' and value != {'schema': 'gateprobes-runtime-release-pin/v1', 'repository': 'https://github.com/musutrade/GateProbes', 'tag': 'podman-lifecycle-v0.2.0', 'version': '0.2.0', 'source_commit': 'e376df9a8021f9351525da630c5e3bb1ad83c767', 'executable_sha256': 'c14a30f4f91c54ce2f0a46f60de6293cbc3b225b9f5cf5dc286ac98b2b032f7b', 'archive_sha256': 'e3112a8dffb289a5e88de9aed8c1f6bfc3eae91169a1bbd45d05db63a22e1874', 'sbom_sha256': '16b22c74068895817a356abf58199137d59da03a552402e2fce63fc36688040d', 'inventory_sha256': '3b8f677ad84efcc3f03c62123772f2f442242a20f9dbaa253b85a627be6000e8', 'checksums_sha256': '20c462222d9ca52abf1f9ae14cba1a84504240d626a0f8e39fa1039008cb6845'}:
        raise ValueError('importer0.5 requires the reviewed Podman0.2 release')
    if version == '0.6.0' and value != RUNTIME_0_3:
        raise ValueError('importer0.6 requires the reviewed Podman0.3 release')
    if version == '0.7.0' and value != RUNTIME_0_3:
        raise ValueError('importer0.7 requires the reviewed Podman0.3 release')
    return value, validator


def prepare(directory, root=ROOT, version=None):
    version = plugin_version(root) if version is None else version
    expected = profile(version)
    pin = contract(root, version)
    runtime, validator = runtime_contract(root, version)
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
    verify(directory, root, version)
    assets = directory / 'runtime-assets'
    assets.mkdir()
    names = {f"gateprobes-podman-lifecycle-{expected['runtime_version']}-linux-amd64.tar.gz": 'archive_sha256',
             f"gateprobes-podman-lifecycle-{expected['runtime_version']}-linux-amd64.tar.gz.sbom.cdx.json": 'sbom_sha256',
             'release-inventory.json': 'inventory_sha256', 'SHA256SUMS': 'checksums_sha256'}
    for name, field in names.items():
        url = f"https://github.com/musutrade/GateProbes/releases/download/{expected['runtime_tag']}/{name}"
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
    parser.add_argument('--version', choices=sorted(PROFILES))
    args = parser.parse_args()
    prepare(args.output.resolve(), version=args.version)
