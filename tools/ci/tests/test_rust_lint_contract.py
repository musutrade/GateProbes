"""Rust plugins keep the clippy cognitive-complexity contract."""
import json
import sys
import tomllib
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[3]
THRESHOLD = 10


class RustLintContractTests(unittest.TestCase):
    def setUp(self):
        registry = json.loads((ROOT / "plugins/registry.json").read_text())
        self.rust = {name: row for name, row in registry["plugins"].items()
                     if row["language"] == "rust"}

    def test_every_rust_plugin_declares_the_cognitive_threshold(self):
        self.assertTrue(self.rust, "no Rust plugin is registered")
        for name, row in self.rust.items():
            directory = ROOT / row["path"]
            if name == "docker-readiness":
                # This product ships a second binary from the existing native crate.
                self.assertEqual(row["dedicated_ci"], "runtime-wire")
                self.assertIn("../docker-runtime/native/Cargo.toml", row["entries"]["install"])
                directory = ROOT / "plugins/docker-runtime/native"
                native = tomllib.loads((directory / "Cargo.toml").read_text())
                self.assertIn("gateprobes-docker-readiness", [b["name"] for b in native["bin"]])
            with self.subTest(plugin=name):
                clippy = directory / "clippy.toml"
                self.assertTrue(clippy.is_file(), clippy)
                self.assertIn(f"cognitive-complexity-threshold = {THRESHOLD}",
                              clippy.read_text())
                manifest = tomllib.loads((directory / "Cargo.toml").read_text())
                self.assertEqual(
                    manifest.get("lints", {}).get("clippy", {}).get("cognitive_complexity"),
                    "warn")


if __name__ == "__main__":
    unittest.main()
