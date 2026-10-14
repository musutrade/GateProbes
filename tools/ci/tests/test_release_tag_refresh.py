"""Run the actual publication ref-refresh block against real local Git remotes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class ReleaseTagRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.remote = self.root / 'remote.git'
        self.repo = self.root / 'checkout'
        self.git(self.root, 'init', '--bare', '-q', str(self.remote))
        self.git(self.root, 'init', '-q', '-b', 'main', str(self.repo))
        self.git(self.repo, 'config', 'user.name', 'Release regression')
        self.git(self.repo, 'config', 'user.email', 'release@example.invalid')
        (self.repo / 'source').write_text('first')
        self.git(self.repo, 'add', '.')
        self.git(self.repo, 'commit', '-qm', 'first')
        self.first = self.git(self.repo, 'rev-parse', 'HEAD')
        self.tag = 'postgres-service-v0.1.1'
        self.git(self.repo, 'tag', '-a', self.tag, '-m', 'immutable release')
        self.git(self.repo, 'remote', 'add', 'origin', str(self.remote))
        self.git(self.repo, 'push', '-q', 'origin', 'main', 'refs/tags/' + self.tag)
        self.remote_object = self.git(self.remote, 'rev-parse', 'refs/tags/' + self.tag)
        self.assertNotEqual(self.remote_object, self.first)
        self.git(self.repo, 'tag', '-d', self.tag)

    @staticmethod
    def git(root, *args):
        return subprocess.run(['git', *args], cwd=root, check=True,
                              text=True, capture_output=True).stdout.strip()

    def refresh(self, expected):
        workflow = (ROOT / '.github/workflows/collector-release.yml').read_text()
        block = workflow.split('      - name: Reverify the current tag and release eligibility before publication\n', 1)[1]
        block = block.split('        run: |\n', 1)[1]
        # Execute the production binding logic; the later GitHub eligibility
        # call has its own existing tests and needs no network in this fixture.
        block = block.split('          python3 tools/release/plugin_release.py verify', 1)[0]
        script = '\n'.join(line[10:] for line in block.splitlines())
        return subprocess.run(['bash', '--noprofile', '--norc', '-c', script],
                              cwd=self.repo, env=dict(os.environ, TAG=self.tag, COMMIT=expected),
                              text=True, capture_output=True)

    def test_annotated_remote_with_checkout_peeled_tag_is_verified_without_rewriting(self):
        self.git(self.repo, 'tag', self.tag, self.first)
        result = self.refresh(self.first)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git(self.repo, 'rev-parse', 'refs/tags/' + self.tag), self.first)
        self.assertEqual(self.git(self.remote, 'rev-parse', 'refs/tags/' + self.tag), self.remote_object)

    def test_changed_remote_commit_blocks_publication_even_when_local_tag_matches(self):
        (self.repo / 'source').write_text('second')
        self.git(self.repo, 'commit', '-qam', 'second')
        second = self.git(self.repo, 'rev-parse', 'HEAD')
        self.git(self.repo, 'push', '-q', 'origin', 'main')
        self.git(self.repo, 'tag', self.tag, second)
        result = self.refresh(second)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('remote release tag does not match expected commit', result.stderr)
        self.assertEqual(self.git(self.repo, 'rev-parse', 'refs/tags/' + self.tag), second)
        self.assertEqual(self.git(self.remote, 'rev-parse', 'refs/tags/' + self.tag), self.remote_object)
