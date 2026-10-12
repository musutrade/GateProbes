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


class CheckDocsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "docs").mkdir()
        (self.root / "plugins" / "demo").mkdir(parents=True)
        (self.root / "docs" / "ownership.json").write_text(json.dumps(OWNERSHIP))
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


if __name__ == "__main__":
    unittest.main()
