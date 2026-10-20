"""Documentation checks accept declarations and reject broken links/artifacts."""
import hashlib
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
    "path_map": {"tools/quality/demo/": "plugins/demo/"},
    "core_contract": {"release": "v0.4.8", "binary": "harness-gate-linux-amd64",
                      "sha256": "b" * 64, "version": "0.4.8",
                      "platforms": {"linux": {"binary": "harness-gate-linux-amd64",
                                              "sha256": "c" * 64}}},
    "plugins": {"demo": {"paths": ["plugins/demo"],
                         "contract_test": "plugins/demo/plugin.json"}},
    "inputs": ["plugins/registry.json", "plugins/demo/plugin.json"],
}

REGISTRY = {
    "schema": "gateprobes-plugin-registry/v1",
    "languages": ["rust", "python", "typescript"],
    "runners": {
        "linux": {"runner": "ubuntu-24.04", "suffix": "", "asset": "collector-linux",
                  "target": "x86_64-unknown-linux-gnu"},
    },
    "plugins": {
        "demo": {
            "path": "plugins/demo",
            "language": "typescript",
            "toolchains": ["typescript"],
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
        (self.root / "tools" / "release").mkdir(parents=True)
        self.generated = (self.root / "tools" / "release" / "demo.py")
        self.generated.write_bytes(b"#!/usr/bin/env python3\n")
        ownership = json.loads(json.dumps(OWNERSHIP))
        ownership["generated_copies"] = {
            "tools/release/demo.py": {
                "source_repository": "https://example.invalid/Harness-Gate",
                "source_path": "tools/release/demo.py",
                "source_revision": "d" * 40,
                "sha256": hashlib.sha256(self.generated.read_bytes()).hexdigest(),
            },
        }
        (self.root / "docs" / "ownership.json").write_text(json.dumps(ownership))
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

    def test_entrypoint_instead_of_executable_is_accepted(self):
        (self.root / "plugins" / "demo" / "plugin.json").write_text(
            json.dumps({"name": "demo", "version": "1", "entrypoint": "plugin.py"}))
        self.assertEqual(check_docs.check(self.root), [])

    def test_unreleased_plugin_directory_is_not_registration(self):
        other = self.root / "plugins" / "other"
        other.mkdir()
        (other / "UNRELEASED").write_text("This directory is not a published plugin.\n")
        self.assertEqual(check_docs.check(self.root), [])

    def test_registered_plugin_marker_does_not_hide_missing_manifest(self):
        plugin = self.root / "plugins" / "demo"
        (plugin / "UNRELEASED").write_text("candidate marker\n")
        (plugin / "plugin.json").unlink()
        failures = check_docs.check(self.root)
        self.assertTrue(any("plugins/demo: missing plugin.json" in failure for failure in failures), failures)

    def test_registered_plugin_marker_does_not_hide_bad_manifest(self):
        plugin = self.root / "plugins" / "demo"
        (plugin / "UNRELEASED").write_text("candidate marker\n")
        (plugin / "plugin.json").write_text("{bad json")
        failures = check_docs.check(self.root)
        self.assertTrue(any("plugins/demo/plugin.json" in failure for failure in failures), failures)

    def test_declared_only_candidate_marker_is_not_exempt(self):
        candidate = self.root / "plugins" / "candidate"
        candidate.mkdir()
        (candidate / "UNRELEASED").write_text("candidate marker\n")
        ownership = json.loads((self.root / "docs" / "ownership.json").read_text())
        ownership["plugins"]["candidate"] = {
            "paths": ["plugins/candidate"],
            "contract_test": "plugins/candidate/plugin.json",
        }
        (self.root / "docs" / "ownership.json").write_text(json.dumps(ownership))
        failures = check_docs.check(self.root)
        self.assertTrue(any("plugins/candidate: missing plugin.json" in failure for failure in failures), failures)

    def test_unregistered_manifest_candidate_marker_is_not_exempt(self):
        candidate = self.root / "plugins" / "candidate"
        candidate.mkdir()
        (candidate / "UNRELEASED").write_text("candidate marker\n")
        (candidate / "plugin.json").write_text(
            json.dumps({"name": "candidate", "version": "1", "executable": "candidate"}))
        failures = check_docs.check(self.root)
        self.assertTrue(any("plugins/candidate: not declared" in failure for failure in failures), failures)
        self.assertTrue(any("plugins/candidate: not registered" in failure for failure in failures), failures)

    def test_empty_unreleased_directory_is_allowed(self):
        candidate = self.root / "plugins" / "candidate"
        candidate.mkdir()
        (candidate / "UNRELEASED").write_text("candidate marker\n")
        self.assertEqual(check_docs.check(self.root), [])

    def test_undeclared_plugin_fails(self):
        (self.root / "plugins" / "other").mkdir()
        (self.root / "plugins" / "other" / "plugin.json").write_text(
            json.dumps({"name": "other", "version": "1", "executable": "other"}))
        failures = check_docs.check(self.root)
        self.assertTrue(any("plugins/other" in failure for failure in failures), failures)

    def test_missing_platform_core_mapping_fails(self):
        value = json.loads(json.dumps(OWNERSHIP))
        value["core_contract"]["platforms"] = {}
        (self.root / "docs" / "ownership.json").write_text(json.dumps(value))
        failures = check_docs.check(self.root)
        self.assertTrue(any("core_contract.platforms is required" in failure
                            for failure in failures), failures)

    def test_registry_ownership_parity_fails(self):
        value = json.loads(json.dumps(OWNERSHIP))
        value["plugins"] = {}
        (self.root / "docs" / "ownership.json").write_text(json.dumps(value))
        failures = check_docs.check(self.root)
        self.assertTrue(any("differ from plugins/registry.json" in failure for failure in failures), failures)

    def test_missing_contract_test_and_input_fail(self):
        value = json.loads(json.dumps(OWNERSHIP))
        value["plugins"]["demo"]["contract_test"] = "plugins/demo/missing.py"
        value["inputs"] = ["plugins/registry.json", "plugins/demo/missing.json"]
        (self.root / "docs" / "ownership.json").write_text(json.dumps(value))
        failures = check_docs.check(self.root)
        self.assertTrue(any("contract_test is missing" in failure for failure in failures), failures)
        self.assertTrue(any("declared input is missing" in failure for failure in failures), failures)

    def test_registry_with_empty_plugin_object_fails(self):
        (self.root / "plugins" / "registry.json").write_text(json.dumps({
            "schema": "gateprobes-plugin-registry/v1",
            "languages": ["typescript"],
            "plugins": {"demo": {}},
        }))
        failures = check_docs.check(self.root)
        self.assertTrue(any("unknown language" in failure for failure in failures), failures)

    def test_generated_copy_digest_mismatch_fails(self):
        self.generated.write_bytes(b"#!/usr/bin/env python3\n# tampered\n")
        failures = check_docs.check(self.root)
        self.assertTrue(any("generated copy digest mismatch" in failure
                            for failure in failures), failures)

    def test_missing_generated_copy_fails(self):
        self.generated.unlink()
        failures = check_docs.check(self.root)
        self.assertTrue(any("generated copy is missing" in failure
                            for failure in failures), failures)

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
