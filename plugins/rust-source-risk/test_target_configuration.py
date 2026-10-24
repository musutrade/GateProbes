import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from capture import compiler_configuration, validate_configuration, validate_environment
from measure import target_configuration

HERE = Path(__file__).resolve().parent
INVENTORY = HERE / 'inventory'


class TargetConfigurationTests(unittest.TestCase):
    def test_canonical_configuration_is_accepted(self):
        value = {'target': 'x86_64-unknown-linux-gnu',
                 'cfg': ['target_os="linux"', 'unix']}
        self.assertEqual(target_configuration(value), value)

    def test_compiler_configuration_is_canonical(self):
        value = compiler_configuration('x86_64-unknown-linux-gnu', Path.cwd())
        self.assertEqual(value['target'], 'x86_64-unknown-linux-gnu')
        self.assertEqual(value['cfg'], sorted(set(value['cfg'])))
        self.assertIn('target_os="linux"', value['cfg'])
        self.assertIn('unix', value['cfg'])

    def test_capture_rejects_cfg_changing_environment_and_cargo_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET',
                         'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS'):
                with patch.dict(os.environ, {name: '--cfg changed'}, clear=False):
                    with self.assertRaisesRegex(ValueError, name):
                        validate_environment(root)
            (root / '.cargo').mkdir()
            home = root / 'cargo-home'
            home.mkdir()
            (root / '.cargo/config.toml').write_text('[build]\nrustflags = ["--cfg", "changed"]\n')
            with patch.dict(os.environ, {'CARGO_HOME': str(home)}):
                with self.assertRaisesRegex(ValueError, 'rustflags'):
                    validate_configuration(root, root)
                (root / '.cargo/config.toml').write_text('[build]\ntarget = "aarch64-unknown-linux-gnu"\n')
                with self.assertRaisesRegex(ValueError, 'target'):
                    validate_configuration(root, root)

    def inventory(self, source, target, arguments=('--target-cfg',)):
        if not INVENTORY.is_file():
            raise RuntimeError('inventory binary is required for this test')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'source.rs'
            path.write_text(source)
            return subprocess.run([str(INVENTORY), str(path), *arguments], input=json.dumps(target),
                                  text=True, capture_output=True)

    def test_inventory_cli_requires_and_validates_target_configuration(self):
        source = '#[cfg_attr(test, derive(Debug))] struct A { value: u8 }\nfn plain() {}\n'
        target = {'target': 'x86_64-unknown-linux-gnu', 'cfg': ['target_os="linux"', 'unix']}
        self.assertEqual(self.inventory(source, target).returncode, 0)
        self.assertNotEqual(self.inventory(source, target, ()).returncode, 0)
        self.assertNotEqual(self.inventory(source, {'target': 'x86_64-unknown-linux-gnu', 'cfg': ['unix']}).returncode, 0)
        self.assertNotEqual(self.inventory(source, {'target': 'x86_64-unknown-linux-gnu', 'cfg': ['unix', 'target_os="linux"']}).returncode, 0)
        self.assertNotEqual(self.inventory(source, {'target': 'x86_64-unknown-windows-msvc', 'cfg': ['target_os="linux"', 'unix']}).returncode, 0)

    def test_missing_or_noncanonical_configuration_is_rejected(self):
        for value in (
            None,
            {},
            {'target': 'x86_64-unknown-linux-gnu'},
            {'target': '', 'cfg': ['unix']},
            {'target': 'x86_64-unknown-linux-gnu', 'cfg': []},
            {'target': 'x86_64-unknown-linux-gnu', 'cfg': ['unix', 'target_os="linux"']},
            {'target': 'x86_64-unknown-linux-gnu', 'cfg': ['unix', 'unix']},
            {'target': 'x86_64-unknown-linux-gnu', 'cfg': ['unix'], 'extra': True},
        ):
            with self.assertRaises(ValueError):
                target_configuration(value)


if __name__ == '__main__':
    unittest.main()
