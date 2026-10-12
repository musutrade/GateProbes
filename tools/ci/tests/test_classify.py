"""Classification routes affected plugins and never passes unknown scope."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import classify

REGISTRY = {
    "schema": "gateprobes-plugin-registry/v1",
    "languages": ["rust", "python", "typescript"],
    "runners": {
        "linux": {"runner": "ubuntu-24.04", "suffix": "", "asset": "collector-linux"},
    },
    "plugins": {
        "typescript-risk": {
            "path": "plugins/typescript-risk",
            "language": "typescript",
            "toolchains": ["typescript"],
            "platforms": ["linux"],
            "entries": {"install": "npm ci", "test": "npm test",
                        "contract": "npm run test:core", "package": "npm pack"},
            "protocols": ["protocol/collector-protocol.schema.json"],
        },
        "sample-rust": {
            "path": "plugins/sample-rust",
            "language": "rust",
            "toolchains": ["rust"],
            "platforms": ["linux"],
            "entries": {"install": "cargo build", "test": "cargo test",
                        "contract": "python3 contract.py", "package": "cargo build"},
            "protocols": ["protocol/collector-protocol.schema.json"],
        },
    },
}


class ClassifyTests(unittest.TestCase):
    def test_pure_documentation_runs_light_checks_only(self):
        result = classify.classify(["docs/README.md", "README.md"], REGISTRY)
        self.assertEqual(result["classes"],
                         {"docs": True, "plugin": False, "shared": False, "unknown": False})
        self.assertTrue(result["selection"]["run_light"])
        self.assertFalse(result["selection"]["run_plugins"])
        self.assertEqual(result["matrix"], {"include": []})

    def test_plugin_change_runs_only_that_plugin(self):
        result = classify.classify(["plugins/typescript-risk/measure.cjs"], REGISTRY)
        self.assertEqual(result["plugins"], ["typescript-risk"])
        self.assertEqual(result["matrix"]["include"],
                         [{"plugin": "typescript-risk", "language": "typescript",
                           "path": "plugins/typescript-risk", "toolchains": ["typescript"],
                           "platform": "linux", "runs_on": "ubuntu-24.04",
                           "asset": "collector-linux", "suffix": "",
                           "entries": {"install": "npm ci", "test": "npm test",
                                       "contract": "npm run test:core",
                                       "package": "npm pack"}}])
        self.assertTrue(result["selection"]["run_light"])
        self.assertTrue(result["selection"]["run_plugins"])

    def test_rename_classifies_both_source_and_target(self):
        paths = classify.parse_name_status(
            "R100\tplugins/typescript-risk/README.md\tdocs/plugin-notes.md\n"
            "M\ttools/ci/classify.py\n")
        self.assertEqual(paths, ["plugins/typescript-risk/README.md", "docs/plugin-notes.md",
                                 "tools/ci/classify.py"])
        result = classify.classify(
            ["plugins/typescript-risk/README.md", "docs/plugin-notes.md"], REGISTRY)
        self.assertTrue(result["classes"]["plugin"])
        self.assertTrue(result["classes"]["docs"])
        self.assertEqual(result["plugins"], ["typescript-risk"])

    def test_source_moved_into_docs_is_unknown_not_documentation(self):
        result = classify.classify(["plugins/typescript-risk/measure.cjs", "docs/measure.cjs"],
                                   REGISTRY)
        self.assertTrue(result["classes"]["plugin"])
        self.assertTrue(result["classes"]["unknown"])
        self.assertEqual(result["plugins"], ["sample-rust", "typescript-risk"])

    def test_registered_protocol_change_affects_its_plugins_only(self):
        result = classify.classify(["protocol/collector-protocol.schema.json"], REGISTRY)
        self.assertEqual(result["plugins"], ["sample-rust", "typescript-risk"])
        languages = sorted(row["language"] for row in result["matrix"]["include"])
        self.assertEqual(languages, ["rust", "typescript"])

    def test_unregistered_shared_change_affects_all_plugins(self):
        result = classify.classify(["tools/ci/classify.py"], REGISTRY)
        self.assertEqual(result["plugins"], ["sample-rust", "typescript-risk"])

    def test_unknown_path_and_empty_change_fall_back_conservative(self):
        for paths in ([], ["new/tool.xyz"]):
            with self.subTest(paths=paths):
                result = classify.classify(paths, REGISTRY)
                self.assertTrue(result["classes"]["unknown"], paths)
                self.assertEqual(result["plugins"], ["sample-rust", "typescript-risk"])

    def test_load_registry_rejects_unknown_platforms_and_runner_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "plugins").mkdir()
            path = root / "plugins" / "registry.json"
            base = {
                "schema": "gateprobes-plugin-registry/v1",
                "languages": ["rust"],
                "runners": {"linux": {"runner": "ubuntu-24.04", "suffix": "", "asset": "a"}},
                "plugins": {"x": {"path": "plugins/x", "language": "rust",
                                  "toolchains": ["rust"], "platforms": ["beos"],
                                  "rust_toolchain": "stable", "rust_components": "rustfmt",
                                  "cargo_checks": True,
                                  "entries": {"install": "i", "test": "t",
                                              "contract": "c", "package": "p"}}},
            }
            path.write_text(json.dumps(base))
            with self.assertRaisesRegex(ValueError, "unknown platform"):
                classify.load_registry(root)
            base["plugins"]["x"]["platforms"] = ["linux"]
            base["runners"]["linux"] = {"runner": "ubuntu-24.04", "asset": "a"}
            path.write_text(json.dumps(base))
            with self.assertRaisesRegex(ValueError, "missing suffix"):
                classify.load_registry(root)

    def test_load_registry_rejects_incomplete_or_unknown_languages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "plugins").mkdir()
            path = root / "plugins" / "registry.json"
            path.write_text(json.dumps({"schema": "other", "languages": [], "plugins": {}}))
            with self.assertRaisesRegex(ValueError, "schema"):
                classify.load_registry(root)
            path.write_text(json.dumps({
                "schema": "gateprobes-plugin-registry/v1",
                "languages": ["typescript"],
                "runners": {"linux": {"runner": "ubuntu-24.04", "suffix": "", "asset": "a"}},
                "plugins": {"x": {"path": "plugins/x", "language": "rust",
                                  "entries": {"test": "t", "package": "p"}}},
            }))
            with self.assertRaisesRegex(ValueError, "language"):
                classify.load_registry(root)


if __name__ == "__main__":
    unittest.main()
