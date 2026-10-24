import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from capture import validate_effective_cfg_sources

HERE = Path(__file__).resolve().parent
CAPTURE = HERE / 'capture.py'


class CaptureEnvironmentTests(unittest.TestCase):
    def repository(self, root):
        repo = root / 'repo'
        (repo / 'src').mkdir(parents=True)
        (repo / 'Cargo.toml').write_text('[package]\nname="fixture"\nversion="0.1.0"\nedition="2024"\n')
        (repo / 'src/lib.rs').write_text('pub fn plain() -> usize { 1 }\n')
        return repo

    def capture(self, root, repo, env=None, out=None):
        out = out or (root / 'out')
        command = [sys.executable, str(CAPTURE), '--repository', str(repo), '--output', str(out),
                   '--target-dir', str(root / 'target'), '--input', 'Cargo.toml', '--input', 'src',
                   '--source-root', 'src']
        return subprocess.run(command, env=env, text=True, capture_output=True)

    def marker_environment(self, root):
        tools = root / 'bin'
        tools.mkdir()
        marker = root / 'cargo-ran'
        cargo = tools / 'cargo'
        cargo.write_text('#!/bin/sh\nprintf ran > "' + str(marker) + '"\nexit 77\n')
        cargo.chmod(0o755)
        env = self.clean_environment(root)
        env['PATH'] = str(tools) + os.pathsep + env['PATH']
        return env, marker

    def clean_environment(self, root):
        home = root / 'cargo-home'
        home.mkdir()
        env = dict(os.environ, CARGO_HOME=str(home))
        for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET', 'CARGO_BUILD_RUSTFLAGS',
                     'RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'):
            env.pop(name, None)
        return env

    def assert_rejected(self, result, text):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(text, result.stderr)

    def test_repository_cargo_config_overrides_are_rejected(self):
        for content, expected in (
            ('[build]\nrustc = "/tmp/different-rustc"\n', 'rustc'),
            ('[env]\nCARGO_BUILD_RUSTFLAGS = "--cfg changed"\n', 'CARGO_BUILD_RUSTFLAGS'),
            ('[env]\nRUSTC_WRAPPER = "/tmp/wrapper"\n', 'RUSTC_WRAPPER'),
            ('[env]\nCARGO_BUILD_RUSTC_WRAPPER = "/tmp/wrapper"\n', 'CARGO_BUILD_RUSTC_WRAPPER'),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                repo = self.repository(root)
                (repo / '.cargo').mkdir()
                (repo / '.cargo/config.toml').write_text(content)
                result = self.capture(root, repo, self.clean_environment(root))
                self.assert_rejected(result, expected)

    def test_ancestor_cargo_config_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self.repository(root)
            out = root / 'out'
            (out / '.cargo').mkdir(parents=True)
            (out / '.cargo/config.toml').write_text('[build]\nrustc = "/tmp/different-rustc"\n')
            result = self.capture(root, repo, self.clean_environment(root), out / 'capture')
            self.assert_rejected(result, 'rustc')

    def test_global_cargo_config_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self.repository(root)
            home = root / 'cargo-home'
            home.mkdir()
            (home / 'config.toml').write_text('[env]\nRUSTC_WRAPPER = "/tmp/wrapper"\n')
            result = self.capture(root, repo, dict(os.environ, CARGO_HOME=str(home)))
            self.assert_rejected(result, 'RUSTC_WRAPPER')

    def test_build_script_cfg_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self.repository(root)
            (repo / 'build.rs').write_text('fn main() { println!("cargo:rustc-cfg=custom"); }\n')
            result = self.capture(root, repo, self.clean_environment(root))
            self.assert_rejected(result, 'build script')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self.repository(root)
            (repo / 'Cargo.toml').write_text('[package]\nname="fixture"\nversion="0.1.0"\nedition="2024"\nbuild = "scripts/build.rs"\n')
            result = self.capture(root, repo, self.clean_environment(root))
            self.assert_rejected(result, 'custom build script')

    def test_no_space_custom_build_and_cargo_wrapper_env_are_rejected_before_cargo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self.repository(root)
            (repo / 'Cargo.toml').write_text('[package]\nname="fixture"\nversion="0.1.0"\nedition="2024"\nbuild="custom.rs"\n')
            (repo / 'custom.rs').write_text('fn main() {}\n')
            env, marker = self.marker_environment(root)
            result = self.capture(root, repo, env)
            self.assert_rejected(result, 'custom build script')
            self.assertFalse(marker.exists(), 'cargo ran before rejecting the custom build')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self.repository(root)
            env, marker = self.marker_environment(root)
            env['CARGO_BUILD_RUSTC_WRAPPER'] = '/tmp/probe-wrapper'
            result = self.capture(root, repo, env)
            self.assert_rejected(result, 'CARGO_BUILD_RUSTC_WRAPPER')
            self.assertFalse(marker.exists(), 'cargo ran before rejecting the wrapper environment')

    def test_build_false_and_snapshot_only_build_script_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self.repository(root)
            (repo / 'Cargo.toml').write_text('[package]\nname="fixture"\nversion="0.1.0"\nedition="2024"\nbuild=false\n')
            (repo / 'build.rs').write_text('fn main() {}\n')
            validate_effective_cfg_sources(repo, repo)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self.repository(root)
            snapshot = root / 'snapshot'
            snapshot.mkdir()
            (snapshot / 'build.rs').write_text('fn main() {}\n')
            with self.assertRaisesRegex(ValueError, 'build script'):
                validate_effective_cfg_sources(repo, snapshot)

    def test_different_snapshot_toolchain_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self.repository(root)
            out = root / 'out'
            out.mkdir()
            (out / 'rust-toolchain.toml').write_text('[toolchain]\nchannel = "1.85.0"\n')
            result = self.capture(root, repo, self.clean_environment(root), out / 'capture')
            self.assert_rejected(result, 'rustc version differs between repository and snapshot cwd')


if __name__ == '__main__':
    unittest.main()
