"""Synthetic v3 release evidence: no downloaded-release or execution claims."""
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

import test_preflight as fixture
import preflight
import install

BINARY = 'gateprobes-docker-readiness'
NAME = BINARY + '-0.2.0-linux-amd64.tar.gz'


def evidence(manifest_changes=None, binary_name=BINARY, mode=0o755):
    files = dict(fixture.FILES)
    files[binary_name] = files.pop(preflight.BINARY)
    manifest = dict(name='docker-readiness', version='0.2.0', executable=BINARY,
                    protocol='gate-runtime/v3')
    manifest.update(manifest_changes or {})
    files['plugin.json'] = json.dumps(manifest).encode()
    archive = fixture.tar_bytes([(NAME[:-7] + '/' + n, b, mode if n == binary_name else 0o644)
                                 for n, b in sorted(files.items())])
    sbom = json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.5',
                      'metadata': {'component': {'type': 'application', 'name': 'docker-readiness', 'version': '0.2.0'}},
                      'components': [{'type': 'file', 'name': n, 'hashes': [{'alg': 'SHA-256', 'content': fixture.sha(b)}]}
                                     for n, b in files.items()]}).encode()
    assets = {NAME: archive, NAME + '.sbom.cdx.json': sbom}
    inv = json.dumps({'schema_version': 1, 'source': {'repository': 'https://github.com/musutrade/GateProbes', 'commit': fixture.SOURCE},
                      'tag': 'docker-readiness-v0.2.0', 'checksum_file': 'SHA256SUMS', 'inventory_file': 'release-inventory.json',
                      'checksum_subjects': sorted([*assets, 'release-inventory.json']),
                      'assets': [{'kind': 'package' if n == NAME else 'sbom', 'name': n, 'sha256': fixture.sha(b), 'size_bytes': len(b)}
                                 for n, b in assets.items()]}).encode()
    sums = ''.join(fixture.sha(b) + '  ' + n + '\n' for n, b in sorted({**assets, 'release-inventory.json': inv}.items())).encode()
    pin = json.loads(fixture.valid()[0])
    pin.update(tag='docker-readiness-v0.2.0', version='0.2.0', executable_sha256=fixture.sha(files[binary_name]))
    for key, b in [('archive', archive), ('sbom', sbom), ('inventory', inv), ('checksums', sums)]:
        pin[key + '_sha256'] = fixture.sha(b)
    return json.dumps(pin).encode(), archive, sbom, inv, sums


class ReadinessProfileTests(unittest.TestCase):
    def test_v3_exact_members_and_v2_regression(self):
        files = preflight.validate(*evidence())
        self.assertEqual(set(files), (preflight.MEMBERS - {preflight.BINARY}) | {BINARY})
        self.assertEqual(preflight.validate(*fixture.valid()), fixture.FILES)

    def test_cross_profile_manifest_member_and_mode_rejected(self):
        for changes in [dict(name='docker-runtime'), dict(protocol='gate-runtime/v2'),
                        dict(executable=preflight.BINARY), dict(version='0.1.1')]:
            with self.subTest(changes=changes), self.assertRaises(preflight.InvalidRelease):
                preflight.validate(*evidence(changes))
        for kwargs in [dict(binary_name=preflight.BINARY), dict(mode=0o644)]:
            with self.subTest(kwargs=kwargs), self.assertRaises(preflight.InvalidRelease):
                preflight.validate(*evidence(**kwargs))

    def test_tag_version_and_tamper_rejected(self):
        original = evidence()
        for tag, version in [('docker-runtime-v0.2.0', '0.2.0'), ('docker-readiness-v0.1.1', '0.1.1'),
                             ('docker-readiness-v0.2.1', '0.2.1'), ('unknown-v0.2.0', '0.2.0')]:
            p = json.loads(original[0]); p.update(tag=tag, version=version)
            with self.subTest(tag=tag), self.assertRaises(preflight.InvalidRelease):
                preflight.validate(json.dumps(p).encode(), *original[1:])
        for i in range(1, 5):
            changed = list(original); changed[i] += b'x'
            with self.subTest(asset=i), self.assertRaises(preflight.InvalidRelease):
                preflight.validate(*changed)

    def test_installed_v3_descriptor_modes_and_no_overwrite(self):
        pin, archive, sbom, inventory, sums = evidence()
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp); os.chmod(root, 0o700)
            assets = root / 'assets'; assets.mkdir(mode=0o700)
            for n, b in [(NAME, archive), (NAME + '.sbom.cdx.json', sbom), ('release-inventory.json', inventory), ('SHA256SUMS', sums)]:
                (assets / n).write_bytes(b)
            pinpath = root / 'pin.json'; pinpath.write_bytes(pin); pinpath.chmod(0o600)
            destination = root / 'installed'
            desc = install.import_release(pinpath, assets, destination)
            value = json.loads(desc.read_bytes())
            self.assertEqual(value['tag'], 'docker-readiness-v0.2.0')
            self.assertEqual(value['executable'], {'path': str(destination / BINARY), 'sha256': json.loads(pin)['executable_sha256'], 'version': '0.2.0'})
            self.assertEqual(stat.S_IMODE((destination / BINARY).stat().st_mode), 0o500)
            self.assertFalse((destination / preflight.BINARY).exists())
            with self.assertRaises(install.ImportRejected):
                install.import_release(pinpath, assets, destination)
            self.assertEqual(json.loads(desc.read_bytes()), value)
