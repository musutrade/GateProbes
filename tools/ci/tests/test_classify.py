"""Change classification routes CI tiers and never passes unknown scope."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import classify


class ClassifyTests(unittest.TestCase):
    def test_pure_documentation_routes_to_lightweight_checks(self):
        result = classify.classify(["docs/README.md", "README.md"])
        self.assertEqual(result["classes"],
                         {"docs": True, "plugin": False, "shared": False, "unknown": False})
        self.assertEqual(result["selection"],
                         {"run_docs": True, "run_typescript_risk": False})

    def test_plugin_change_runs_only_that_plugin(self):
        result = classify.classify(["plugins/typescript-risk/measure.cjs"])
        self.assertEqual(result["plugins"], ["typescript-risk"])
        self.assertEqual(result["selection"],
                         {"run_docs": False, "run_typescript_risk": True})

    def test_inputs_and_shared_paths_expand_to_both_tiers(self):
        for path in ("protocol/collector-protocol.schema.json", "docs/ownership.json",
                     "tools/ci/classify.py", ".github/workflows/ci.yml",
                     "LICENSE", "package.json"):
            with self.subTest(path=path):
                result = classify.classify([path])
                self.assertTrue(result["selection"]["run_docs"], path)
                self.assertTrue(result["selection"]["run_typescript_risk"], path)
                self.assertFalse(result["classes"]["docs"], path)

    def test_unknown_path_and_empty_change_fall_back_conservative(self):
        for paths in ([], ["new/tool.xyz"]):
            with self.subTest(paths=paths):
                result = classify.classify(paths)
                self.assertTrue(result["classes"]["unknown"], paths)
                self.assertEqual(result["selection"],
                                 {"run_docs": True, "run_typescript_risk": True})

    def test_mixed_documentation_and_plugin_selects_both_tiers(self):
        result = classify.classify(["docs/README.md", "plugins/typescript-risk/package.json"])
        self.assertEqual(result["selection"],
                         {"run_docs": True, "run_typescript_risk": True})


if __name__ == "__main__":
    unittest.main()
