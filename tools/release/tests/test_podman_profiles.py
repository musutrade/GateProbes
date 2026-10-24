import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import package_podman
import podman_core


class PodmanProfileBoundaryTests(unittest.TestCase):
    def test_historical_protocol_pin_is_exact_and_new_profile_is_explicit(self):
        old = package_podman.PROFILES['0.2.0']
        self.assertEqual(old['protocol_version'], '0.5.0')
        self.assertEqual(old['protocol_checksum'],
                         'f1619c05a4069ca03b477f456ee08f831f873022080c8ed96c850dbe20f6f90b')
        new = package_podman.PROFILES['0.3.0']
        self.assertEqual((new['protocol'], new['protocol_version']), ('gate-runtime/lifecycle-v1', '0.6.0'))

    def test_core_pin_old_identity_is_exact_and_new_version_fails_closed(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary)
            (root / 'plugins/podman-lifecycle').mkdir(parents=True)
            plugin = root / 'plugins/podman-lifecycle/plugin.json'
            pin = root / 'plugins/podman-lifecycle/core-pin.json'
            plugin.write_text(json.dumps({'core_versions': ['0.12.0']}))
            pin.write_text(json.dumps(podman_core.EXPECTED_0_2))
            self.assertEqual(podman_core.contract(root), podman_core.EXPECTED_0_2)
            changed = dict(podman_core.EXPECTED_0_2, sha256='a' * 64)
            pin.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, 'historical lifecycle Core pin'):
                podman_core.contract(root)
            plugin.write_text(json.dumps({'core_versions': ['0.13.0']}))
            pin.write_text(json.dumps(podman_core.EXPECTED_0_2))
            with self.assertRaisesRegex(ValueError, 'Core0.13 pin'):
                podman_core.contract(root)
            pin.write_text(json.dumps(dict(podman_core.EXPECTED_0_2,
                                           release='v0.13.0', version='0.13.0')))
            self.assertEqual(podman_core.contract(root)['version'], '0.13.0')


if __name__ == '__main__':
    unittest.main()
