"""Independent tags retain Core's eligibility and exact integrity boundaries."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/release"))
import package_plugin
import pinned_core
import plugin_release
import release_inventory as inventory
import release_policy as policy


class PluginIdentityTests(unittest.TestCase):
    def test_independent_tags_resolve_exact_manifest_versions(self):
        for name in plugin_release.releases():
            row = plugin_release.resolve(name)
            self.assertEqual(plugin_release.resolve_tag(row["tag"]), row)
            self.assertIn(row["version"], row["archive"])
        self.assertEqual(plugin_release.resolve("rust-measure")["version"], "0.3.1")

    def test_unknown_stale_or_malformed_tags_fail(self):
        for tag in ("v0.4.8", "rust-collector-v0.1.0-rc.8", "typescript-risk-v0.0.1",
                    "typescript-risk-v0.1.0-rc.4/evil", "rust-measure-v03.3.1"):
            with self.subTest(tag=tag), self.assertRaises(policy.PolicyError):
                plugin_release.resolve_tag(tag)

    def test_manifest_or_lock_version_disagreement_fails(self):
        for filename in ("package.json", "npm-shrinkwrap.json"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "plugins").mkdir()
                shutil.copy2(ROOT / "plugins/releases.json", root / "plugins/releases.json")
                target = root / "plugins/typescript-risk"
                target.mkdir()
                for manifest in plugin_release.releases()["typescript-risk"]["manifests"]:
                    shutil.copy2(ROOT / "plugins/typescript-risk" / manifest, target / manifest)
                path = target / filename
                value = json.loads(path.read_text())
                value["version"] = "0.0.1"
                path.write_text(json.dumps(value))
                with self.assertRaises(policy.PolicyError):
                    plugin_release.resolve("typescript-risk", root)

    @patch.dict(os.environ, {"GH_TOKEN": "test-token"})
    def test_real_tag_and_exact_commit_are_passed_to_shared_checks(self):
        tag = plugin_release.resolve("typescript-risk")["tag"]
        commit = "a" * 40
        with patch.object(policy, "verify_git_state", return_value=commit) as git, \
                patch.object(policy, "verify_ci_run", return_value={"run_id": 123}) as ci:
            result = plugin_release.verify(tag, commit, "musutrade/GateProbes")
        git.assert_called_once_with(ROOT, tag, commit, "refs/remotes/origin/main")
        self.assertEqual(ci.call_args.args[1:], (commit, "main"))
        self.assertEqual(result["tag"], tag)
        self.assertEqual(result["ci"]["run_id"], 123)

    @patch.dict(os.environ, {"GH_TOKEN": "test-token"})
    def test_ineligible_ci_is_never_reclassified_as_success(self):
        tag = plugin_release.resolve("rust-measure")["tag"]
        with patch.object(policy, "verify_git_state", return_value="a" * 40), \
                patch.object(policy, "verify_ci_run", side_effect=policy.PolicyError("failed CI")), \
                self.assertRaisesRegex(policy.PolicyError, "failed CI"):
            plugin_release.verify(tag, "a" * 40, "musutrade/GateProbes")


class PackageInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dist = Path(self.temp.name)
        self.row = plugin_release.resolve("http-json-contract")
        for name in (self.row["archive"], self.row["archive"] + ".sbom.cdx.json"):
            (self.dist / name).write_text("fixture")

    def generate(self):
        return plugin_release.generate_inventory(self.dist, self.row["tag"], "a" * 40,
                                                  "https://github.com/musutrade/GateProbes")

    def seal(self):
        value = self.generate()
        inventory.write_checksums(self.dist, value)
        # Crypto is exercised by the publication workflow. The shared verifier
        # independently requires a complete signature and attestation subject set.
        for name in value["signature_products"]:
            (self.dist / name).write_text("signature fixture")
        return value

    def test_package_only_inventory_uses_shared_full_verifier(self):
        value = self.seal()
        self.assertEqual({asset["kind"] for asset in value["assets"]}, {"package", "sbom"})
        inventory.verify(self.dist, self.dist / inventory.INVENTORY_FILE, value["integrity_subjects"])

    def test_unlisted_asset_cannot_enter_the_signed_inventory(self):
        (self.dist / "unexpected-program").write_text("unreviewed")
        with self.assertRaisesRegex(inventory.InventoryError, "unlisted"):
            self.generate()

    def test_changed_package_fails_shared_verification(self):
        value = self.seal()
        (self.dist / self.row["archive"]).write_text("modified")
        with self.assertRaisesRegex(inventory.InventoryError, "modified"):
            inventory.verify(self.dist, self.dist / inventory.INVENTORY_FILE, value["integrity_subjects"])

    def test_missing_attestation_fails_shared_verification(self):
        value = self.seal()
        with self.assertRaisesRegex(inventory.InventoryError, "unattested"):
            inventory.verify(self.dist, self.dist / inventory.INVENTORY_FILE,
                             value["integrity_subjects"][:-1])

    def test_symlink_package_is_rejected(self):
        archive = self.dist / self.row["archive"]
        archive.unlink()
        archive.symlink_to(self.row["archive"] + ".sbom.cdx.json")
        with self.assertRaisesRegex(inventory.InventoryError, "regular file"):
            self.generate()


class PackagingBoundaryTests(unittest.TestCase):
    def test_core_digest_is_checked_before_executing_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bin/harness-gate-linux-amd64"
            binary.parent.mkdir()
            binary.write_bytes(b"wrong binary")
            with patch.object(pinned_core.subprocess, "run") as run, \
                    self.assertRaisesRegex(ValueError, "digest mismatch"):
                pinned_core.verify(root)
            run.assert_not_called()

    def test_core_version_mismatch_fails_after_digest_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bin/harness-gate-linux-amd64"
            binary.parent.mkdir()
            binary.write_bytes(b"fixture")
            contract = pinned_core.contract()
            contract["platforms"]["linux"]["sha256"] = hashlib.sha256(b"fixture").hexdigest()
            with patch.object(pinned_core, "contract", return_value=contract), \
                    patch.object(pinned_core.subprocess, "run") as run:
                run.return_value.stdout = "harness-gate 0.0.1\n"
                with self.assertRaisesRegex(ValueError, "version mismatch"):
                    pinned_core.verify(root)

    def test_source_risk_incomplete_archive_fails_before_any_test_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "incomplete.tar.gz"
            with tarfile.open(archive, "w:gz"):
                pass
            with patch.object(package_plugin, "run") as run, \
                    self.assertRaisesRegex(RuntimeError, "incomplete Rust collector archive"):
                package_plugin.accept_rust_archive(archive, root, root / "consumer", root)
            run.assert_not_called()

    @patch.dict(os.environ, {"HARNESS_GATE_TYPESCRIPT_ACCEPTANCE": "/tmp/evidence"})
    def test_source_and_installed_acceptance_preserve_distinct_evidence(self):
        source = package_plugin.node_test_environment(ROOT, "source")
        installed = package_plugin.node_test_environment(ROOT, "installed")
        self.assertNotEqual(source["HARNESS_GATE_TYPESCRIPT_ACCEPTANCE"],
                            installed["HARNESS_GATE_TYPESCRIPT_ACCEPTANCE"])

    @patch.dict(os.environ, {"NODE_PATH": "/untrusted/source/node_modules"})
    def test_installed_runtime_cannot_inherit_source_dependency_search(self):
        env = package_plugin.node_test_environment(ROOT, "installed")
        self.assertEqual(env["NODE_PATH"], "")

    def test_only_test_tool_import_is_replaced_in_copied_harness(self):
        with tempfile.TemporaryDirectory() as directory:
            installed = Path(directory)
            source = ROOT / "plugins/typescript-risk"
            package_plugin.copy_node_tests(source, installed, ["test.cjs", "test-core.cjs"])
            for filename in ("test.cjs", "test-core.cjs"):
                copied = (installed / filename).read_text()
                self.assertIn('require("typescript")', copied)
                self.assertIn('require("./measure.cjs")', copied)
                self.assertNotIn('require("istanbul-lib-instrument")', copied)
                self.assertIn(str(source / "node_modules/istanbul-lib-instrument"), copied)


class PostgresPackagingTests(unittest.TestCase):
    def test_incompatible_schema_blocks_before_plugin_build(self):
        def export(*args, **kwargs):
            (kwargs["cwd"] / "flow.schema.json").write_text('{"properties": {}}')
            return ""
        with patch.object(package_plugin, "run", side_effect=export) as run, \
                self.assertRaisesRegex(RuntimeError, "pinned released Core lacks"):
            package_plugin.postgres_package(Path("/unused/output"), Path("/unused/core"), Path("/pinned/core"))
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], "/pinned/core")

    def test_incomplete_archive_blocks_before_contract_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "gateprobes-postgres-0.1.1-linux-amd64.tar.gz"
            with tarfile.open(archive, "w:gz"):
                pass
            with patch.object(package_plugin, "run") as run, \
                    self.assertRaisesRegex(RuntimeError, "incomplete Postgres archive"):
                package_plugin.accept_postgres_archive(archive, ROOT / "plugins/postgres-service",
                    root / "consumer", Path("/pinned/core"), root / "report.json")
            run.assert_not_called()


class IndependentWorkflowTests(unittest.TestCase):
    def test_publication_is_tag_only_and_uses_the_complete_trust_chain(self):
        text = (ROOT / ".github/workflows/collector-release.yml").read_text()
        for row in plugin_release.releases().values():
            self.assertIn("'" + row["tag_prefix"] + "*'", text)
        self.assertNotIn("pull_request:", text)
        self.assertNotIn("branches:", text)
        self.assertIn("needs: [policy, package]", text)
        self.assertEqual(text.count("plugin_release.py verify"), 2)
        self.assertIn('git fetch --no-tags origin main:refs/remotes/origin/main \"refs/tags/$TAG:$remote_tag_ref\"', text)
        self.assertIn('remote release tag does not match expected commit', text)
        self.assertIn('--target "$GITHUB_SHA"', text)
        for boundary in ("environment: release", "id-token: write", "attestations: write",
                         "plugin_release.py verify", "plugin_release.py inventory",
                         "pinned_core.py --output", "package_plugin.py --plugin",
                         "cosign verify-blob", "gh attestation verify", '--attested "$name"',
                         "already exists; refusing to overwrite", "--verify-tag"):
            self.assertIn(boundary, text)
        identity = ".github/workflows/collector-release.yml"
        self.assertIn(f'{identity}@${{GITHUB_REF}}', text)
        self.assertIn(f'--signer-workflow "$GITHUB_REPOSITORY/{identity}"', text)
        for line in text.splitlines():
            if "uses:" in line:
                self.assertRegex(line.strip(), r"uses:\s+\S+@[0-9a-f]{40}\s*(#.*)?$")


if __name__ == "__main__":
    unittest.main()
