"""A frozen ownership handoff never accepts modified or unclassified inputs."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('legacy_compatibility', ROOT / 'compatibility/legacy-core/run.py')
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.snapshot = self.root / 'snapshot'
        self.test = self.snapshot / 'tools/quality/tests/test_original.py'
        self.test.parent.mkdir(parents=True)
        self.test.write_text('original')
        self.inventory = {'schema': 'legacy-core-compatibility/v1', 'files': {
            'tools/quality/tests/test_original.py': {'sha256': hashlib.sha256(b'original').hexdigest()}}}
        self.save()
        for name, value in [('HERE', self.root), ('SNAPSHOT', self.snapshot)]:
            patched = patch.object(legacy, name, value)
            patched.start(); self.addCleanup(patched.stop)

    def save(self):
        (self.root / 'inventory.json').write_text(json.dumps(self.inventory))

    def test_original_input_is_accepted(self):
        self.assertEqual(legacy.verify(), self.inventory)

    def test_changed_or_missing_original_fails(self):
        self.test.write_text('changed')
        with self.assertRaisesRegex(ValueError, 'changed frozen'):
            legacy.verify()
        self.test.unlink()
        with self.assertRaisesRegex(ValueError, 'changed frozen'):
            legacy.verify()

    def test_unclassified_test_fails(self):
        self.test.with_name('test_new.py').write_text('unclassified')
        with self.assertRaisesRegex(ValueError, 'inventory changed'):
            legacy.verify()

    def test_symlink_is_not_an_original_input(self):
        source = self.root / 'original.py'; source.write_text('original')
        self.test.unlink(); self.test.symlink_to(source)
        with self.assertRaisesRegex(ValueError, 'changed frozen'):
            legacy.verify()

    def test_path_escape_and_wrong_schema_fail(self):
        self.inventory['files']['../escape'] = {'sha256': '0' * 64}
        self.save()
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            legacy.verify()
        self.inventory['schema'] = 'unknown'; self.save()
        with self.assertRaisesRegex(ValueError, 'invalid compatibility'):
            legacy.verify()
