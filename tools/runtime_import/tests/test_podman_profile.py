"""Synthetic Podman release evidence: no downloaded-release or execution claims."""
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch

import test_preflight as fixture
import preflight
import install
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'release'))
import importer_core_podman

BINARY = 'gateprobes-podman-lifecycle'
NAME = BINARY + '-0.2.0-linux-amd64.tar.gz'
HISTORICAL = Path(__file__).resolve().parent / 'fixtures/0.5.0'


def evidence(manifest_changes=None, binary_name=BINARY, mode=0o755):
    files = dict(fixture.FILES)
    files.update({n: b'fixture' for n in ['Cargo.toml', 'core-pin.json', 'protocol-LICENSE']})
    files[binary_name] = files.pop(preflight.BINARY)
    manifest = dict(name='podman-lifecycle', version='0.2.0', executable=BINARY,
                    protocol='gate-runtime/lifecycle-v2', core_versions=['0.12.0'],
                    authority='read-only-runtime-facts', capabilities=['capture'])
    manifest.update(manifest_changes or {})
    files['plugin.json'] = json.dumps(manifest).encode()
    archive = fixture.tar_bytes([(NAME[:-7] + '/' + n, b, mode if n == binary_name else 0o644)
                                 for n, b in sorted(files.items())])
    sbom = json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.5',
                      'metadata': {'component': {'type': 'application', 'name': 'podman-lifecycle', 'version': '0.2.0'}},
                      'components': [{'type': 'file', 'name': n, 'hashes': [{'alg': 'SHA-256', 'content': fixture.sha(b)}]}
                                     for n, b in files.items()]}).encode()
    assets = {NAME: archive, NAME + '.sbom.cdx.json': sbom}
    inv = json.dumps({'schema_version': 1, 'source': {'repository': 'https://github.com/musutrade/GateProbes', 'commit': fixture.SOURCE},
                      'tag': 'podman-lifecycle-v0.2.0', 'checksum_file': 'SHA256SUMS', 'inventory_file': 'release-inventory.json',
                      'checksum_subjects': sorted([*assets, 'release-inventory.json']),
                      'assets': [{'kind': 'package' if n == NAME else 'sbom', 'name': n, 'sha256': fixture.sha(b), 'size_bytes': len(b)}
                                 for n, b in assets.items()]}).encode()
    sums = ''.join(fixture.sha(b) + '  ' + n + '\n' for n, b in sorted({**assets, 'release-inventory.json': inv}.items())).encode()
    pin = json.loads(fixture.valid()[0])
    pin.update(tag='podman-lifecycle-v0.2.0', version='0.2.0', executable_sha256=fixture.sha(files[binary_name]))
    for key, b in [('archive', archive), ('sbom', sbom), ('inventory', inv), ('checksums', sums)]:
        pin[key + '_sha256'] = fixture.sha(b)
    return json.dumps(pin).encode(), archive, sbom, inv, sums


class PodmanProfileTests(unittest.TestCase):
    def test_exact_members(self):
        self.assertEqual(len(preflight.validate(*evidence())), 12)
        self.assertEqual(preflight.profile({'tag': 'podman-lifecycle-v0.2.0', 'version': '0.2.0'})[0], 'podman-lifecycle')

    def test_cross_profile_refusal(self):
        for change in [dict(name='docker-readiness'), dict(protocol='gate-runtime/v3'),
                       dict(core_versions=['0.10.0']), dict(version='0.1.0'),
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
                        'product': 'podman-lifecycle', 'version': '0.2.0',
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
        for tag, version in [('podman-lifecycle-v0.2.0', '0.1.0'), ('podman-lifecycle-v0.1.0', '0.1.0'), ('podman-lifecycle-v0.1.0', '0.2.0'), ('unknown-v0.2.0', '0.2.0'), ('podman-lifecycle-v0.2.0', '0.2.1')]:
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


NAME_V3 = BINARY + '-0.3.0-linux-amd64.tar.gz'


def evidence_v3(manifest_changes=None):
    files = dict(fixture.FILES)
    files.pop('accept.py')
    files['accept_lifecycle.py'] = b'# lifecycle acceptance entry\n'
    files.update({n: b'fixture' for n in ['Cargo.toml', 'core-pin.json', 'protocol-LICENSE']})
    files[BINARY] = files.pop(preflight.BINARY)
    manifest = dict(name='podman-lifecycle', version='0.3.0', executable=BINARY,
                    protocol='gate-runtime/lifecycle-v1', core_versions=['0.13.0'],
                    authority='container-lifecycle/mutate',
                    capabilities=['capture', 'resolve-image', 'create', 'status', 'start', 'stop', 'remove', 'health'])
    manifest.update(manifest_changes or {})
    files['plugin.json'] = json.dumps(manifest).encode()
    archive = fixture.tar_bytes([(NAME_V3[:-7] + '/' + n, b, 0o755 if n == BINARY else 0o644)
                                 for n, b in sorted(files.items())])
    sbom = json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.5',
                      'metadata': {'component': {'type': 'application', 'name': 'podman-lifecycle', 'version': '0.3.0'}},
                      'components': [{'type': 'file', 'name': n, 'hashes': [{'alg': 'SHA-256', 'content': fixture.sha(b)}]}
                                     for n, b in files.items()]}).encode()
    assets = {NAME_V3: archive, NAME_V3 + '.sbom.cdx.json': sbom}
    inventory = json.dumps({'schema_version': 1, 'source': {'repository': 'https://github.com/musutrade/GateProbes', 'commit': fixture.SOURCE},
                            'tag': 'podman-lifecycle-v0.3.0', 'checksum_file': 'SHA256SUMS', 'inventory_file': 'release-inventory.json',
                            'checksum_subjects': sorted([*assets, 'release-inventory.json']),
                            'assets': [{'kind': 'package' if n == NAME_V3 else 'sbom', 'name': n, 'sha256': fixture.sha(b), 'size_bytes': len(b)}
                                       for n, b in assets.items()]}).encode()
    sums = ''.join(fixture.sha(b) + '  ' + n + '\n' for n, b in sorted({**assets, 'release-inventory.json': inventory}.items())).encode()
    pin = json.loads(fixture.valid()[0])
    pin.update(tag='podman-lifecycle-v0.3.0', version='0.3.0', executable_sha256=fixture.sha(files[BINARY]))
    for key, b in [('archive', archive), ('sbom', sbom), ('inventory', inventory), ('checksums', sums)]:
        pin[key + '_sha256'] = fixture.sha(b)
    return json.dumps(pin).encode(), archive, sbom, inventory, sums


class PodmanLifecycleV3ProfileTests(unittest.TestCase):
    def test_profile_and_twelve_member_archive(self):
        self.assertEqual(preflight.profile({'tag': 'podman-lifecycle-v0.3.0', 'version': '0.3.0'}),
                         ('podman-lifecycle', BINARY, 'gate-runtime/lifecycle-v1'))
        self.assertEqual(len(preflight.validate(*evidence_v3())), 12)

    def test_install_descriptor_is_v1_sorted_and_config_free(self):
        pin, archive, sbom, inventory, sums = evidence_v3()
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary); root.chmod(0o700)
            assets = root / 'assets'; assets.mkdir(mode=0o700)
            for name, data in [(NAME_V3, archive), (NAME_V3 + '.sbom.cdx.json', sbom),
                               ('release-inventory.json', inventory), ('SHA256SUMS', sums)]:
                (assets / name).write_bytes(data)
            pin_path = root / 'pin.json'; pin_path.write_bytes(pin); pin_path.chmod(0o600)
            destination = root / 'installed'
            descriptor = install.import_release(pin_path, assets, destination)
            expected = {'schema': 'gate-runtime/lifecycle-installation-v1',
                        'product': 'podman-lifecycle', 'version': '0.3.0',
                        'protocol': 'gate-runtime/lifecycle-v1',
                        'executable_path': str(destination / BINARY),
                        'executable_sha256': json.loads(pin)['executable_sha256'],
                        'config_schema': 'gate-runtime/lifecycle-config-v1'}
            self.assertEqual(descriptor.read_bytes(),
                             json.dumps(expected, sort_keys=True, separators=(',', ':')).encode())
            self.assertFalse((destination / 'config.json').exists())
            self.assertFalse((destination / 'host.json').exists())

    def test_mixed_capture_or_core_versions_refused(self):
        for change in [dict(protocol='gate-runtime/lifecycle-v2'),
                       dict(core_versions=['0.12.0']),
                       dict(authority='read-only-runtime-facts'),
                       dict(capabilities=['capture'])]:
            with self.subTest(change=change), self.assertRaises(preflight.InvalidRelease):
                preflight.validate(*evidence_v3(change))

    def test_cross_tag_version_refused(self):
        for tag, version in [('podman-lifecycle-v0.3.0', '0.2.0'),
                             ('podman-lifecycle-v0.2.0', '0.3.0'),
                             ('podman-lifecycle-v0.3.1', '0.3.0')]:
            with self.subTest(tag=tag), self.assertRaises(preflight.InvalidRelease):
                preflight.profile({'tag': tag, 'version': version})


class PodmanImporterVersionOverrideTests(unittest.TestCase):
    def test_historical_core_and_runtime_pins_are_not_reinterpreted_by_current_manifest(self):
        core = importer_core_podman.contract(HISTORICAL, version='0.5.0')
        runtime, _ = importer_core_podman.runtime_contract(HISTORICAL, version='0.5.0')
        self.assertEqual(core['version'], '0.12.0')
        self.assertEqual(runtime['tag'], 'podman-lifecycle-v0.2.0')
        current = importer_core_podman.contract(importer_core_podman.ROOT)
        current_runtime, _ = importer_core_podman.runtime_contract(importer_core_podman.ROOT)
        self.assertEqual(current, importer_core_podman.EXPECTED_0_7)
        self.assertEqual(current['version'], '0.14.1')
        self.assertEqual(current_runtime['tag'], 'podman-lifecycle-v0.3.0')
        historical = importer_core_podman.ROOT / 'tools/runtime_import/tests/fixtures/0.6.0'
        self.assertEqual(importer_core_podman.contract(historical, version='0.6.0'), importer_core_podman.EXPECTED_0_6)
        self.assertEqual(importer_core_podman.runtime_contract(historical, version='0.6.0')[0], importer_core_podman.RUNTIME_0_3)


class PodmanPrepareVersionTests(unittest.TestCase):
    def test_prepare_forwards_explicit_version_to_verify(self):
        import hashlib
        import io
        import importer_core_podman as module
        payload = b'fixture-payload'
        digest = hashlib.sha256(payload).hexdigest()
        pin = {'binary': 'harness-gate-linux-amd64', 'repository': 'musutrade/GateHouse',
               'release': 'v0.12.0', 'version': '0.12.0', 'sha256': digest}
        runtime = {'tag': 'podman-lifecycle-v0.2.0', 'archive_sha256': digest,
                   'sbom_sha256': digest, 'inventory_sha256': digest, 'checksums_sha256': digest}
        validator = Mock()
        seen = []
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            destination = Path(temporary) / 'installed'
            class Reply:
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    return False
                def read(self, _size):
                    return payload
            with patch.object(module, 'contract', return_value=pin), \
                    patch.object(module, 'runtime_contract', return_value=(runtime, validator)), \
                    patch.object(module, 'verify', side_effect=lambda _d, _r, version: seen.append(version)), \
                    patch.object(module.urllib.request, 'urlopen', return_value=Reply()):
                module.prepare(destination, version='0.5.0')
        self.assertEqual(seen, ['0.5.0'])
        validator.validate.assert_called_once()
