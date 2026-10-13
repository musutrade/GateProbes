"""Portable evidence references and exact inventories, without compiler simulation."""
import json
from pathlib import Path, PureWindowsPath
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rust_native_driver as native


class WindowsRelativePath(type(Path())):
    """Use real host I/O with Windows spelling for relative artifact paths."""
    def relative_to(self, *args, **kwargs):
        return PureWindowsPath(super().relative_to(*args, **kwargs).as_posix())


class NativeArtifactPathTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.name = 'units/fixture/inventory.json'
        self.inventory = self.root / self.name
        self.inventory.parent.mkdir(parents=True)
        self.inventory.write_bytes(b'{"fixture": true}\n')
        native.write_json(self.root / 'capture.json', {'units': [{'inventory': self.name}]})

    def test_windows_seal_matches_capture_references(self):
        with patch.object(native, 'Path', WindowsRelativePath):
            anchor = native.seal(self.root)
            manifest = native.verified_files(self.root, anchor)
        capture = json.loads((self.root / 'capture.json').read_bytes())
        for unit in capture['units']:
            self.assertIn(unit['inventory'], manifest['artifacts'])
        self.assertEqual(set(manifest['artifacts']), {'capture.json', self.name})

    def test_windows_verifies_existing_portable_inventory(self):
        artifacts = {'capture.json': native.file_hash(self.root / 'capture.json'),
                     self.name: native.file_hash(self.inventory)}
        native.write_json(self.root / 'manifest.json',
                          {'schema': 'native-driver-artifacts/1', 'artifacts': artifacts})
        anchor = native.file_hash(self.root / 'manifest.json')
        with patch.object(native, 'Path', WindowsRelativePath):
            self.assertEqual(native.verified_files(self.root, anchor)['artifacts'], artifacts)
            self.inventory.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'artifact tampering'):
                native.verified_files(self.root, anchor)
            self.inventory.unlink()
            with self.assertRaisesRegex(ValueError, 'missing/extra evidence file'):
                native.verified_files(self.root, anchor)

    def test_aliases_are_rejected_even_with_a_new_manifest_anchor(self):
        for alias in ('units\\fixture\\inventory.json',
                      'units/fixture/./inventory.json',
                      'units/fixture/../fixture/inventory.json'):
            with self.subTest(alias=alias):
                artifacts = {'capture.json': native.file_hash(self.root / 'capture.json'),
                             self.name: native.file_hash(self.inventory),
                             alias: native.file_hash(self.inventory)}
                native.write_json(self.root / 'manifest.json',
                                  {'schema': 'native-driver-artifacts/1', 'artifacts': artifacts})
                anchor = native.file_hash(self.root / 'manifest.json')
                with patch.object(native, 'Path', WindowsRelativePath), \
                        self.assertRaisesRegex(ValueError, 'missing/extra evidence file'):
                    native.verified_files(self.root, anchor)


if __name__ == '__main__':
    unittest.main()
