"""Offline package boundary tests; no engine or native build."""
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import shutil

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools/release'))
import package_podman as package
import package_runtime
import verify_podman_acceptance as verifier

PREFIX = 'gateprobes-podman-lifecycle-0.2.0-linux-amd64'


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
        self.assertEqual(len(package.MEMBERS), 12)
        self.assertEqual(package.MANIFEST['capabilities'], ['capture'])

    def test_registry_pin_and_manifest(self):
        product, lock = package.validate(ROOT)
        self.assertEqual(product.name, 'podman-lifecycle')
        protocol = next(p for p in lock['package'] if p['name'] == 'gatehouse-runtime-protocol')
        self.assertEqual(protocol['version'], '0.5.0')
        self.assertEqual(protocol['checksum'], package.PROTOCOL_CHECKSUM)

    def test_local_patch_wrong_pin_and_mutation_claim_refused(self):
        cases = [('native/Cargo.toml', lambda s: s + '\n[patch.crates-io]\n'),
                 ('native/Cargo.toml', lambda s: s.replace('=0.5.0', '=0.4.1')),
                 ('native/Cargo.lock', lambda s: s.replace(package.PROTOCOL_CHECKSUM, '0' * 64)),
                 ('plugin.json', lambda s: s.replace('"capture"', '"remove"'))]
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
                verifier.verify(report, archive)


if __name__ == '__main__':
    unittest.main()
