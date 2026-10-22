import copy
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools/release'))
import package_lifecycle as package
import package_runtime
import lifecycle_core
import plugin_release


class PackageTests(unittest.TestCase):
    def archive(self, change=None):
        files = {n: b'fixture' for n in package.MEMBERS}
        data = package_runtime.archive_bytes('product', files, package.BINARY)
        if change is None:
            return data
        out = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as source, tarfile.open(fileobj=out, mode='w:gz') as target:
            for i, member in enumerate(source.getmembers()):
                body = source.extractfile(member).read()
                if i == 0:
                    change(member)
                target.addfile(member, io.BytesIO(body) if member.isfile() else None)
        return out.getvalue()

    def reject(self, change):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                package.extract(self.archive(change), Path(tmp), 'product')
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_current_product_pins_are_valid(self):
        package.validate(ROOT)
        self.assertEqual(plugin_release.resolve('docker-lifecycle', ROOT)['version'], '0.1.0')

    def test_archive_roundtrip_and_reproducibility(self):
        self.assertEqual(self.archive(), self.archive())
        with tempfile.TemporaryDirectory() as tmp:
            p = package.extract(self.archive(), Path(tmp), 'product')
            self.assertEqual({x.name for x in p.iterdir()}, package.MEMBERS)

    def test_symlink(self):
        self.reject(lambda m: setattr(m, 'type', tarfile.SYMTYPE))

    def test_hardlink(self):
        self.reject(lambda m: setattr(m, 'type', tarfile.LNKTYPE))

    def test_fifo(self):
        self.reject(lambda m: setattr(m, 'type', tarfile.FIFOTYPE))

    def test_parent_path(self):
        self.reject(lambda m: setattr(m, 'name', '../escape'))

    def test_absolute_path(self):
        self.reject(lambda m: setattr(m, 'name', '/escape'))

    def test_mode(self):
        self.reject(lambda m: setattr(m, 'mode', 0o777))

    def test_pax(self):
        self.reject(lambda m: setattr(m, 'pax_headers', {'comment': 'extra'}))

    def test_extra_member(self):
        files = {n: b'fixture' for n in package.MEMBERS} | {'docker': b'no'}
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            package.extract(package_runtime.archive_bytes('product', files, package.BINARY), Path(tmp), 'product')

    def test_wrong_prefix(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            package.extract(self.archive(), Path(tmp), 'other')

    def test_core_wrong_binary_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'bin').mkdir()
            (root / 'bin/harness-gate-linux-amd64').write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                lifecycle_core.verify(root, ROOT)

    def test_historical_profiles_are_not_redefined(self):
        self.assertEqual(package_runtime.product_profile('docker-readiness')[2], ['0.9.0'])
        self.assertEqual(package_runtime.product_profile('docker-runtime')[2], ['0.7.1'])
        with self.assertRaises(RuntimeError):
            package_runtime.product_profile('docker-lifecycle')

    def test_manifest_mutation_is_rejected(self):
        from unittest.mock import patch
        wrong = copy.deepcopy(package.MANIFEST)
        wrong['authority'] = 'read-only-runtime-facts'
        with patch.object(package.package_workload, 'checked_file', return_value=json.dumps(wrong).encode()):
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                package.validate(ROOT)


if __name__ == '__main__':
    unittest.main()
