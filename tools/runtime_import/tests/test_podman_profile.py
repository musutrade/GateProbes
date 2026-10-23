"""Synthetic Podman release evidence: no downloaded-release or execution claims."""
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

import test_preflight as fixture
import preflight
import install

BINARY = 'gateprobes-podman-lifecycle'
NAME = BINARY + '-0.1.0-linux-amd64.tar.gz'


def evidence(manifest_changes=None, binary_name=BINARY, mode=0o755):
    files = dict(fixture.FILES)
    files.update({n: b'fixture' for n in ['Cargo.toml', 'core-pin.json', 'protocol-LICENSE']})
    files[binary_name] = files.pop(preflight.BINARY)
    manifest = dict(name='podman-lifecycle', version='0.1.0', executable=BINARY,
                    protocol='gate-runtime/lifecycle-v2', core_versions=['0.11.0'],
                    authority='read-only-runtime-facts', capabilities=['capture'])
    manifest.update(manifest_changes or {})
    files['plugin.json'] = json.dumps(manifest).encode()
    archive = fixture.tar_bytes([(NAME[:-7] + '/' + n, b, mode if n == binary_name else 0o644)
                                 for n, b in sorted(files.items())])
    sbom = json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.5',
                      'metadata': {'component': {'type': 'application', 'name': 'podman-lifecycle', 'version': '0.1.0'}},
                      'components': [{'type': 'file', 'name': n, 'hashes': [{'alg': 'SHA-256', 'content': fixture.sha(b)}]}
                                     for n, b in files.items()]}).encode()
    assets = {NAME: archive, NAME + '.sbom.cdx.json': sbom}
    inv = json.dumps({'schema_version': 1, 'source': {'repository': 'https://github.com/musutrade/GateProbes', 'commit': fixture.SOURCE},
                      'tag': 'podman-lifecycle-v0.1.0', 'checksum_file': 'SHA256SUMS', 'inventory_file': 'release-inventory.json',
                      'checksum_subjects': sorted([*assets, 'release-inventory.json']),
                      'assets': [{'kind': 'package' if n == NAME else 'sbom', 'name': n, 'sha256': fixture.sha(b), 'size_bytes': len(b)}
                                 for n, b in assets.items()]}).encode()
    sums = ''.join(fixture.sha(b) + '  ' + n + '\n' for n, b in sorted({**assets, 'release-inventory.json': inv}.items())).encode()
    pin = json.loads(fixture.valid()[0])
    pin.update(tag='podman-lifecycle-v0.1.0', version='0.1.0', executable_sha256=fixture.sha(files[binary_name]))
    for key, b in [('archive', archive), ('sbom', sbom), ('inventory', inv), ('checksums', sums)]:
        pin[key + '_sha256'] = fixture.sha(b)
    return json.dumps(pin).encode(), archive, sbom, inv, sums


class PodmanProfileTests(unittest.TestCase):
    def test_exact_members(self):
        self.assertEqual(len(preflight.validate(*evidence())), 12)

    def test_cross_profile_refusal(self):
        for change in [dict(name='docker-readiness'), dict(protocol='gate-runtime/v3'),
                       dict(core_versions=['0.10.0']), dict(version='0.2.0'),
                       dict(authority='mutation'), dict(capabilities=['capture', 'create']),
                       dict(name='docker-lifecycle'), dict(protocol='gate-runtime/lifecycle-v1')]:
            with self.subTest(change=change), self.assertRaises(preflight.InvalidRelease):
                preflight.validate(*evidence(change))

    def test_canonical_protected_install_no_host_or_config(self):
        pin, archive, sbom, inventory, sums = evidence()
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp); root.chmod(0o700)
            assets = root / 'assets'; assets.mkdir(mode=0o700)
            for n, b in [(NAME, archive), (NAME + '.sbom.cdx.json', sbom),
                         ('release-inventory.json', inventory), ('SHA256SUMS', sums)]:
                (assets / n).write_bytes(b)
            pinpath = root / 'pin.json'; pinpath.write_bytes(pin); pinpath.chmod(0o600)
            destination = root / 'installed'
            desc = install.import_release(pinpath, assets, destination)
            expected = {'schema': 'gate-runtime/podman-installation-v1',
                        'product': 'podman-lifecycle', 'version': '0.1.0',
                        'protocol': 'gate-runtime/lifecycle-v2',
                        'executable_path': str(destination / BINARY),
                        'executable_sha256': json.loads(pin)['executable_sha256'],
                        'config_schema': 'gate-runtime/podman-context-v1'}
            self.assertEqual(desc.read_bytes(), json.dumps(expected, sort_keys=False, separators=(',', ':')).encode())
            self.assertEqual(len(list(destination.iterdir())), 13)
            for file in destination.iterdir():
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o500 if file.name == BINARY else 0o400)
            self.assertFalse((destination / 'config.json').exists())
            self.assertFalse((destination / 'host.json').exists())
            with self.assertRaises(install.ImportRejected):
                install.import_release(pinpath, assets, destination)

    def test_lifecycle_wrong_tag_version(self):
        for tag, version in [('podman-lifecycle-v0.2.0', '0.2.0'), ('podman-lifecycle-v0.1.0', '0.1.1'), ('unknown-v0.1.0', '0.1.0')]:
            with self.subTest(tag=tag), self.assertRaises(preflight.InvalidRelease):
                preflight.profile({'tag': tag, 'version': version})

    def test_all_asset_tampering_rejected(self):
        original = evidence()
        for index in range(1, 5):
            changed = list(original); changed[index] += b'tampered'
            with self.subTest(asset=index), self.assertRaises(preflight.InvalidRelease):
                preflight.validate(*changed)

    def test_missing_extra_and_wrong_mode_members(self):
        original = preflight.validate(*evidence())
        for remove, extra, mode in [('protocol-LICENSE', None, 0o755),
                                     (None, 'extra', 0o755), (None, None, 0o644)]:
            files = dict(original)
            if remove: del files[remove]
            if extra: files[extra] = b'extra'
            archive = fixture.tar_bytes([(NAME[:-7] + '/' + n, b, mode if n == BINARY else 0o644)
                                         for n, b in sorted(files.items())])
            with self.subTest(remove=remove, extra=extra, mode=mode), self.assertRaises(preflight.InvalidRelease):
                preflight.unpack(archive, NAME[:-7], BINARY)
