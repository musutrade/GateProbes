"""Offline package boundary tests; no engine or native build."""
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
HISTORICAL = Path(__file__).resolve().parent / 'fixtures/0.2.0'
sys.path.insert(0, str(ROOT / 'tools/release'))
import package_podman as package
import package_runtime
import verify_podman_acceptance as verifier

PREFIX = 'gateprobes-podman-lifecycle-0.3.0-linux-amd64'


class PackageTests(unittest.TestCase):
    def archive(self, mutate=None):
        data = package_runtime.archive_bytes(PREFIX, {n: b'fixture' for n in package.MEMBERS}, package.BINARY)
        if mutate is None:
            return data
        out = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(data)) as src, tarfile.open(fileobj=out, mode='w:gz') as dst:
            for m in src.getmembers():
                body = src.extractfile(m).read()
                mutate(m)
                dst.addfile(m, io.BytesIO(body))
        return out.getvalue()

    def copy_historical(self, destination):
        target = Path(destination) / 'fixture'
        shutil.copytree(HISTORICAL, target)
        return target

    def test_exact_twelve_members_and_modes(self):
        with tempfile.TemporaryDirectory() as d:
            root = package.extract(self.archive(), Path(d), PREFIX)
            self.assertEqual({p.name for p in root.iterdir()}, package.MEMBERS)
            self.assertEqual((root / package.BINARY).stat().st_mode & 0o777, 0o755)

    def test_wrong_modes_refused(self):
        for mode in (0o777, 0o4755, 0o600):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError):
                    package.extract(self.archive(lambda m: setattr(m, 'mode', mode)), Path(d), PREFIX)

    def test_owner_and_time_refused(self):
        for field in ('uid', 'gid', 'mtime'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError):
                    package.extract(self.archive(lambda m: setattr(m, field, 1)), Path(d), PREFIX)

    def test_symlink_refused(self):
        def change(m):
            m.type = tarfile.SYMTYPE
            m.linkname = '/etc/passwd'
        with tempfile.TemporaryDirectory() as d, self.assertRaises(ValueError):
            package.extract(self.archive(change), Path(d), PREFIX)

    def test_traversal_refused(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(ValueError):
            package.extract(self.archive(lambda m: setattr(m, 'name', '../outside')), Path(d), PREFIX)

    def test_duplicate_members_refused(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(ValueError):
            package.extract(self.archive(lambda m: setattr(m, 'name', PREFIX + '/LICENSE')), Path(d), PREFIX)

    def test_no_docker_members(self):
        self.assertNotIn('protocol-license.json', package.MEMBERS)
        self.assertNotIn('installation.json', package.MEMBERS)
        self.assertNotIn('host.json', package.MEMBERS)
        self.assertNotIn('accept.py', package.MEMBERS)
        self.assertIn('accept_lifecycle.py', package.MEMBERS)
        self.assertEqual(len(package.MEMBERS), 12)
        self.assertEqual(package.PROFILES['0.3.0']['capabilities'],
                         ['capture', 'resolve-image', 'create', 'status', 'start', 'stop', 'remove', 'health'])

    def test_registry_pin_and_manifest(self):
        product, lock, version = package.load(ROOT)
        self.assertEqual(version, '0.3.0')
        manifest = json.loads((product / 'plugin.json').read_text())
        self.assertEqual(manifest['capabilities'], package.PROFILES['0.3.0']['capabilities'])
        protocol = next(p for p in lock['package'] if p['name'] == 'gatehouse-runtime-protocol')
        self.assertEqual(protocol['version'], '0.6.0')
        self.assertEqual(protocol['checksum'], package.PROFILES['0.3.0']['protocol_checksum'])

    def test_historical_0_2_fixture_remains_exact_and_rejects_mutation_claim(self):
        product, lock, version = package.load(HISTORICAL)
        self.assertEqual(version, '0.2.0')
        manifest = json.loads((product / 'plugin.json').read_text())
        self.assertEqual(manifest['capabilities'], ['capture'])
        protocol = next(p for p in lock['package'] if p['name'] == 'gatehouse-runtime-protocol')
        self.assertEqual((protocol['version'], protocol['checksum']),
                         ('0.5.0', 'f1619c05a4069ca03b477f456ee08f831f873022080c8ed96c850dbe20f6f90b'))
        with tempfile.TemporaryDirectory() as d:
            mutated = self.copy_historical(d)
            plugin = mutated / 'plugins/podman-lifecycle/plugin.json'
            value = json.loads(plugin.read_text())
            value['authority'] = 'container-lifecycle/mutate'
            value['capabilities'] = ['capture', 'remove']
            plugin.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'profile mismatch'):
                package.load(mutated)
        with tempfile.TemporaryDirectory() as d:
            mutated = self.copy_historical(d)
            cargo = mutated / 'plugins/podman-lifecycle/native/Cargo.toml'
            cargo.write_text(cargo.read_text().replace('=0.5.0', '=0.6.0'))
            with self.assertRaisesRegex(ValueError, 'protocol version'):
                package.load(mutated)

    def test_local_patch_wrong_pin_and_mutation_claim_refused(self):
        cases = [('native/Cargo.toml', lambda s: s + '\n[patch.crates-io]\n'),
                 ('native/Cargo.toml', lambda s: s.replace('=0.6.0', '=0.5.0')),
                 ('native/Cargo.lock', lambda s: s.replace(package.PROFILES['0.3.0']['protocol_checksum'], '0' * 64)),
                 ('plugin.json', lambda s: s.replace('"health"', '"exec"'))]
        for name, change in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                product = root / 'plugins/podman-lifecycle'
                for member in ('plugin.json', 'core-pin.json', 'native/Cargo.toml',
                               'native/Cargo.lock', 'native/rust-toolchain.toml', 'native/protocol-LICENSE'):
                    dst = product / member
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / 'plugins/podman-lifecycle' / member, dst)
                target = product / name
                target.write_text(change(target.read_text()))
                with self.assertRaises(ValueError):
                    package.validate(root)

    def test_report_identity_substitution_refused(self):
        with tempfile.TemporaryDirectory() as d:
            archive = Path(d) / (PREFIX + '.tar.gz')
            archive.write_bytes(self.archive())
            report = Path(d) / 'report.json'
            report.write_text(json.dumps({'schema': 'gateprobes-docker-lifecycle-acceptance/v1', 'passed': 21}))
            with self.assertRaisesRegex(ValueError, 'identity'):
                verifier.verify_mutation(report, archive)

    def test_mode_dispatch_accepts_matching_profile_and_refuses_wrong_profile(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = root / (PREFIX + '.tar.gz')
            archive.write_bytes(self.archive())
            archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            binary_sha = hashlib.sha256(b'fixture').hexdigest()
            rows = []
            for case, exit_code, connections, mutations in (
                    ('capture-config-refuses-mutation', 1, 0, 0),
                    ('resolve-image', 0, 3, 0),
                    ('create', 0, 4, 1),
                    ('status', 0, 3, 0),
                    ('start', 0, 5, 1),
                    ('stop', 0, 5, 1),
                    ('remove', 0, 4, 1),
                    ('health', 0, 7, 2)):
                rows.append({'case': case, 'passed': True, 'exit': exit_code, 'connections': connections,
                             'routes': [], 'mutation_attempts': mutations,
                             'stdout_sha256': hashlib.sha256(b'').hexdigest()})
            report = root / 'mutation.json'
            report.write_text(json.dumps({
                'schema': 'gateprobes-podman-lifecycle-mutation-acceptance/v1',
                'product': 'podman-lifecycle', 'version': '0.3.0',
                'archive_sha256': archive_sha, 'core_sha256': verifier.CORE_SHA,
                'executable_sha256': binary_sha, 'passed': 8, 'cases': rows,
                'socket_connections_total': 31, 'mutation_attempts': 6, 'files_created': []}))
            self.assertEqual(verifier.verify_mode('mutation', report, archive)['passed'], 8)
            with self.assertRaisesRegex(ValueError, 'identity'):
                verifier.verify_mode('capture', report, archive)
            wrong = root / 'wrong.json'
            wrong.write_text(json.dumps({'schema': 'gateprobes-podman-lifecycle-acceptance/v1',
                                         'product': 'podman-lifecycle', 'version': '0.2.0',
                                         'core_sha256': verifier.CORE_SHA_0_2,
                                         'archive_sha256': archive_sha, 'passed': 21}))
            with self.assertRaisesRegex(ValueError, 'identity'):
                verifier.verify_mode('mutation', wrong, archive)
            success = subprocess.run([sys.executable, str(Path(verifier.__file__)), '--mode', 'mutation',
                                      '--report', str(report), '--archive', str(archive)],
                                     capture_output=True, text=True, timeout=30)
            self.assertEqual(success.returncode, 0, success.stderr)
            refused = subprocess.run([sys.executable, str(Path(verifier.__file__)), '--mode', 'capture',
                                      '--report', str(report), '--archive', str(archive)],
                                     capture_output=True, text=True, timeout=30)
            self.assertNotEqual(refused.returncode, 0)


if __name__ == '__main__':
    unittest.main()
