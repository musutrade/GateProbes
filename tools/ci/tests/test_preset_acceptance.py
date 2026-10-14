"""Installed preset acceptance retains execution and quality assurance."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("preset_accept", ROOT / "tools/presets/accept.py")
accept = importlib.util.module_from_spec(spec)
spec.loader.exec_module(accept)


class GeneratedPresetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / ".harness-gate"
        self.config.mkdir()
        self.flow = '[project]\nname = "fixture"\n[[steps]]\nid = "required"\n'
        self.quality = ('[collectors.measure]\n[policies.required]\n'
                        '[profiles.full]\ncollectors = ["measure"]\npolicies = ["required"]\n'
                        '[profiles.ci]\ncollectors = ["measure"]\npolicies = ["required"]\n')
        (self.root / "seed.toml").write_text(self.flow)
        (self.config / "flow.toml").write_text(self.flow)
        (self.config / "quality.toml").write_text(self.quality)
        (self.root / "recipe.json").write_text(json.dumps([{"pack": "quality", "bindings": {}}]))
        (self.root / "pack.json").write_text(json.dumps({
            "quality": {"collectors": {"measure": {}}, "policies": {"required": {}}},
            "files": {"policy.json": {"crap_limit": 30}},
        }))
        (self.root / "policy.json").write_text('{"crap_limit": 30}')

    def verify(self):
        accept.verify_generated(self.root, {"packs": {"quality": "pack.json"}},
                                {"flow": "seed.toml", "recipe": "recipe.json"}, self.root)

    def test_complete_preset_passes(self):
        self.verify()

    def test_missing_execution_step_blocks(self):
        (self.config / "flow.toml").write_text('[project]\nname = "fixture"\nsteps = []\n')
        with self.assertRaises((KeyError, ValueError)):
            self.verify()

    def test_changed_policy_file_blocks(self):
        (self.root / "policy.json").write_text('{"crap_limit": 999}')
        with self.assertRaises(ValueError):
            self.verify()

    def test_omitted_full_or_ci_collector_blocks(self):
        for profile in ("full", "ci"):
            with self.subTest(profile=profile):
                (self.config / "quality.toml").write_text(self.quality.replace(
                    f'[profiles.{profile}]\ncollectors = ["measure"]',
                    f'[profiles.{profile}]\ncollectors = []'))
                with self.assertRaises(ValueError):
                    self.verify()


if __name__ == "__main__":
    unittest.main()
