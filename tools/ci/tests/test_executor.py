"""Only implemented plugin languages pass the executor guard."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import executor

ROOT = Path(__file__).resolve().parents[3]


class ExecutorTests(unittest.TestCase):
    def test_implemented_executors_pass(self):
        for language in ("python", "rust", "typescript"):
            with self.subTest(language=language):
                self.assertEqual(executor.check(language), language)

    def test_unregistered_languages_fail_explicitly(self):
        for language in ("go", "kotlin"):
            with self.subTest(language=language):
                with self.assertRaisesRegex(ValueError, "no executor implemented"):
                    executor.check(language)

    def test_missing_or_invalid_language_fails(self):
        for language in ("", None, 1):
            with self.subTest(language=language):
                with self.assertRaisesRegex(ValueError, "missing or invalid"):
                    executor.check(language)

    def test_every_registered_plugin_language_has_an_executor(self):
        registry = json.loads((ROOT / "plugins/registry.json").read_text())
        for name, row in registry["plugins"].items():
            with self.subTest(plugin=name):
                self.assertEqual(executor.check(row["language"]), row["language"])


if __name__ == "__main__":
    unittest.main()
