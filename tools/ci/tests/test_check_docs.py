"""Documentation checks accept declarations and reject broken links/artifacts."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import check_docs

OWNERSHIP = {
    "schema": "gateprobes-ownership/v1",
    "source_repository": "https://github.com/musutrade/Harness-Gate",
    "source_commit": "a" * 40,
    "path_map": {"tools/quality/typescript-risk/": "plugins/typescript-risk/"},
    "core_contract": {"release": "v0.4.8", "binary": "harness-gate-linux-amd64",
                      "sha256": "b" * 64, "version": "0.4.8"},
    "plugins": {"demo": {"paths": ["plugins/demo"]}},
}

REGISTRY = {
    "schema": "gateprobes-plugin-registry/v1",
    "languages": ["rust", "python", "typescript"],
    "plugins": {
        "demo": {
            "path": "plugins/demo",
            "language": "typescript",
            "entries": {"install": "npm ci", "test": "npm test",
                        "contract": "npm run test:core", "package": "npm pack"},
            "protocols": ["protocol/demo.schema.json"],
        },
    },
}


class CheckDocsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "docs").mkdir()
        (self.root / "plugins" / "demo").mkdir(parents=True)
        (self.root / "protocol").mkdir()
        (self.root / "docs" / "ownership.json").write_text(json.dumps(OWNERSHIP))
        (self.root / "plugins" / "registry.json").write_text(json.dumps(REGISTRY))
        (self.root / "protocol" / "demo.schema.json").write_text("{}\n")
        (self.root / "plugins" / "demo" / "plugin.json").write_text(
            json.dumps({"name": "demo", "version": "1", "executable": "demo"}))
        (self.root / "README.md").write_text("# Demo\n\n[ownership](docs/ownership.json)\n")

    def test_valid_tree_passes(self):
        self.assertEqual(check_docs.check(self.root), [])

    def test_broken_link_fails(self):
        (self.root / "README.md").write_text("[missing](docs/missing.md)\n")
        failures = check_docs.check(self.root)
        self.assertTrue(any("broken link" in failure for failure in failures), failures)

    def test_incomplete_ownership_fails(self):
        value = dict(OWNERSHIP, source_commit="short")
        (self.root / "docs" / "ownership.json").write_text(json.dumps(value))
        failures = check_docs.check(self.root)
        self.assertTrue(any("source_commit" in failure for failure in failures), failures)

    def test_committed_artifacts_fail(self):
        (self.root / "plugins" / "demo" / "node_modules").mkdir()
        (self.root / "bundle.tgz").write_text("artifact")
        failures = check_docs.check(self.root)
        self.assertTrue(any("node_modules" in failure for failure in failures), failures)
        self.assertTrue(any("bundle.tgz" in failure for failure in failures), failures)

    def test_undeclared_plugin_fails(self):
        (self.root / "plugins" / "other").mkdir()
        (self.root / "plugins" / "other" / "plugin.json").write_text(
            json.dumps({"name": "other", "version": "1", "executable": "other"}))
        failures = check_docs.check(self.root)
        self.assertTrue(any("plugins/other" in failure for failure in failures), failures)

    def test_registry_with_empty_plugin_object_fails(self):
        (self.root / "plugins" / "registry.json").write_text(json.dumps({
            "schema": "gateprobes-plugin-registry/v1",
            "languages": ["typescript"],
            "plugins": {"demo": {}},
        }))
        failures = check_docs.check(self.root)
        self.assertTrue(any("unknown language" in failure for failure in failures), failures)

    def test_registry_missing_entries_and_protocol_fails(self):
        value = json.loads(json.dumps(REGISTRY))
        value["plugins"]["demo"]["entries"] = {"test": "npm test", "package": "npm pack"}
        value["plugins"]["demo"]["protocols"] = ["protocol/missing.schema.json"]
        (self.root / "plugins" / "registry.json").write_text(json.dumps(value))
        failures = check_docs.check(self.root)
        self.assertTrue(any("install entry" in failure for failure in failures), failures)
        self.assertTrue(any("contract entry" in failure for failure in failures), failures)
        self.assertTrue(any("protocol is missing" in failure for failure in failures), failures)


if __name__ == "__main__":
    unittest.main()
