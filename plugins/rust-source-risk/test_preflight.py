"""Compatibility diagnostics must precede expensive compilation and tests."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from measure import source_inventories

HERE = Path(__file__).resolve().parent


class SourcePreflightTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='source-preflight-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        (self.repo / 'src').mkdir()
        (self.repo / 'Cargo.toml').write_text('[package]\nname="fixture"\nversion="0.1.0"\n')
        # A marker distinguishes no cargo execution from cargo failing quickly.
        tools = self.root / 'bin'
        tools.mkdir()
        cargo = tools / 'cargo'
        self.marker = self.root / 'cargo-started'
        cargo.write_text('#!/bin/sh\nprintf started > "$CARGO_MARKER"\nexit 77\n')
        cargo.chmod(0o755)
        self.env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                        CARGO_MARKER=str(self.marker))

    def capture(self):
        return subprocess.run([
            sys.executable, str(HERE / 'capture.py'), '--repository', str(self.repo),
            '--output', str(self.root / 'capture'), '--target-dir', str(self.root / 'target'),
            '--input', 'Cargo.toml', '--input', 'src', '--source-root', 'src',
        ], env=self.env, capture_output=True, text=True)

    def test_all_source_errors_precede_any_cargo_execution(self):
        (self.repo / 'src/a.rs').write_text('''#[derive(Serialize)]
struct A {
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<u32>,
    #[serde(serialize_with = "custom")]
    y: u32,
}
''')
        (self.repo / 'src/b.rs').write_text('''#[derive(Serialize)]
struct B { #[serde(serialize_with = "other")] x: u32 }
''')
        (self.repo / 'src/c.rs').write_text('fn malformed( {')
        result = self.capture()
        self.assertNotEqual(result.returncode, 0)
        for name in ('src/a.rs', 'src/b.rs', 'src/c.rs'):
            self.assertIn(name, result.stderr)
        self.assertGreaterEqual(result.stderr.count('unsupported Serde metadata'), 3)
        self.assertFalse(self.marker.exists(), 'cargo must not start for incompatible source')
        self.assertFalse((self.root / 'capture/bundle.json').exists())
        self.assertFalse((self.root / 'capture/cargo-coverage.json').exists())

    def test_supported_source_proceeds_to_cargo(self):
        (self.repo / 'src/lib.rs').write_text('pub fn value() -> u32 { 42 }')
        result = self.capture()
        self.assertTrue(self.marker.exists(), result.stderr)
        self.assertNotEqual(result.returncode, 0, 'cargo failure must still propagate')
        self.assertFalse((self.root / 'capture/bundle.json').exists())

    def test_unsafe_paths_remain_immediate_errors(self):
        outside = self.root / 'outside.rs'
        outside.write_text('pub fn outside() {}')
        (self.repo / 'src/link.rs').symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'source escapes root'):
            source_inventories(self.repo, ['src/link.rs'], HERE / 'inventory')
        for path in ('../outside.rs', '/outside.rs', 'src/../outside.rs'):
            with self.assertRaisesRegex(ValueError, 'noncanonical'):
                source_inventories(self.repo, [path], HERE / 'inventory')


if __name__ == '__main__':
    unittest.main()
