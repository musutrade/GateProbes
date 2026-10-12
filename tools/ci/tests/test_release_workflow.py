"""The release workflow keeps one fail-closed signed publication identity."""
import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github" / "workflows" / "native-collector-release.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
OWNERSHIP = ROOT / "docs" / "ownership.json"

PINNED_ACTION = re.compile(r"uses:\s+\S+@[0-9a-f]{40}\s*(#.*)?$")
SECRET = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")
WORKFLOW_PATH = ".github/workflows/native-collector-release.yml"


class ReleaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text()

    def test_every_action_is_pinned_to_a_full_commit(self):
        for line in self.text.splitlines():
            if "uses:" in line:
                self.assertRegex(line.strip(), PINNED_ACTION, line)

    def test_publication_uses_keyless_identity_and_environment(self):
        self.assertIn("tags: ['rust-collector-v*']", self.text)
        self.assertEqual(self.text.count(
            "if: startsWith(github.ref, 'refs/tags/rust-collector-v')"), 2)
        self.assertIn("environment: release", self.text)
        self.assertIn("id-token: write", self.text)
        self.assertIn("attestations: write", self.text)
        self.assertIn("contents: write", self.text)

    def test_no_long_lived_secret_is_referenced(self):
        names = set(SECRET.findall(self.text))
        self.assertEqual(names, {"GITHUB_TOKEN"})

    def test_signature_identity_names_this_repository_workflow(self):
        self.assertIn(
            f'--certificate-identity "https://github.com/${{GITHUB_REPOSITORY}}/{WORKFLOW_PATH}@${{GITHUB_REF}}"',
            self.text)
        self.assertIn(
            f'--signer-workflow "$GITHUB_REPOSITORY/{WORKFLOW_PATH}"', self.text)

    def test_policy_runs_the_shared_gatehouse_checker(self):
        self.assertIn("python3 tools/release/release_policy.py verify", self.text)
        self.assertIn("--tag-prefix rust-collector-v", self.text)
        self.assertIn("plugins/rust-native-plugin/Cargo.toml", self.text)

    def test_matrix_is_derived_from_the_registry(self):
        self.assertIn("plugins/registry.json", self.text)
        self.assertIn("fromJSON(needs.platforms.outputs.matrix)", self.text)
        self.assertIn('"target": runner["target"]', self.text)
        self.assertIn('print("matrix=" + json.dumps({"include": rows}', self.text)

    def test_publish_uses_the_inventory_and_refuses_overwrite(self):
        self.assertIn("tools/release/release_inventory.py generate", self.text)
        self.assertIn(
            "verify_args=(verify --dist dist --inventory dist/release-inventory.json)",
            self.text)
        self.assertIn('--attested "$name"', self.text)
        self.assertIn("already exists; refusing to overwrite", self.text)
        self.assertIn("--verify-tag", self.text)

    def test_ci_aggregate_still_guards_the_publish_identity(self):
        ci = CI_WORKFLOW.read_text()
        self.assertIn("name: Required Quality Aggregate", ci)

    def test_generated_release_copies_match_the_recorded_digests(self):
        ownership = json.loads(OWNERSHIP.read_text())
        copies = ownership.get("generated_copies", {})
        self.assertEqual(set(copies), {
            "tools/release/release_policy.py",
            "tools/release/release_inventory.py",
        })
        for destination, row in copies.items():
            path = ROOT / destination
            self.assertTrue(path.is_file(), destination)
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(actual, row["sha256"], destination)
            self.assertRegex(row["source_revision"], r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
