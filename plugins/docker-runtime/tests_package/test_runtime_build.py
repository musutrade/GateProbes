"""Test-only regressions for the pinned musl build-input verifier."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

# repo/plugins/docker-runtime/tests_package -> repo
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/release"))

import runtime_build  # noqa: E402


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Inputs:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="runtime-build-test-")
        self.root = Path(self.temporary.name)
        self.sysroot = self.root / "toolchain"
        self.target_lib = (
            self.sysroot / "lib/rustlib/x86_64-unknown-linux-musl/lib"
        )
        self.files = {
            "bin/rustc": b"rustc",
            "bin/cargo": b"cargo",
            "lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld": b"lld",
            "lib/rustlib/x86_64-unknown-linux-musl/lib/libstd.rlib": b"std",
            "share/doc/rust/COPYRIGHT-library.html": b"copyright",
        }
        for relative, data in self.files.items():
            path = self.sysroot / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.verbose = "rustc fake\nbinary: rustc\n"
        self.lock = {
            "schema": "gateprobes-runtime-build/v1",
            "toolchain": "1.99.1",
            "target": "x86_64-unknown-linux-musl",
            "rustc_verbose": self.verbose,
            "files": {
                relative: sha(self.sysroot / relative)
                for relative in self.files
            },
        }
        self.write_lock()

    def write_lock(self):
        path = self.root / "plugins/docker-runtime/native/build-inputs.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.lock))

    def check_output(self, args, **_kwargs):
        if args[-2:] == ["--print", "sysroot"]:
            return str(self.sysroot) + "\n"
        if "-vV" in args:
            return self.verbose
        raise AssertionError(f"unexpected subprocess call: {args!r}")

    def verify(self):
        with mock.patch.object(
            runtime_build.subprocess, "check_output", side_effect=self.check_output
        ):
            return runtime_build.verify_inputs(self.root)

    def close(self):
        self.temporary.cleanup()


class BuildInputs(unittest.TestCase):
    def setUp(self):
        self.inputs = Inputs()

    def tearDown(self):
        self.inputs.close()

    def test_exact_inputs_pass(self):
        sysroot, lock = self.inputs.verify()
        self.assertEqual(sysroot, self.inputs.sysroot)
        self.assertEqual(lock, self.inputs.lock)

    def test_compiler_identity_and_file_hash_mismatch_fail(self):
        self.inputs.verbose = "rustc different\n"
        with self.assertRaisesRegex(RuntimeError, "compiler identity"):
            self.inputs.verify()
        self.inputs.verbose = "rustc fake\nbinary: rustc\n"
        self.inputs.lock["files"]["bin/rustc"] = "0" * 64
        self.inputs.write_lock()
        with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
            self.inputs.verify()

    def test_extra_target_library_is_rejected(self):
        (self.inputs.target_lib / "extra.rlib").write_bytes(b"extra")
        with self.assertRaisesRegex(RuntimeError, "target library set"):
            self.inputs.verify()

    def test_unsafe_input_path_is_rejected(self):
        self.inputs.lock["files"]["../escape"] = "0" * 64
        self.inputs.write_lock()
        with self.assertRaisesRegex(RuntimeError, "unsafe"):
            self.inputs.verify()

    def test_identity_schema_and_target_are_strict(self):
        for key, value in (
            ("schema", "other/v1"),
            ("toolchain", "1.99.0"),
            ("target", "x86_64-unknown-linux-gnu"),
        ):
            with self.subTest(key=key):
                changed = dict(self.inputs.lock)
                changed[key] = value
                original = self.inputs.lock
                self.inputs.lock = changed
                self.inputs.write_lock()
                with self.assertRaisesRegex(RuntimeError, "build identity"):
                    self.inputs.verify()
                self.inputs.lock = original
                self.inputs.write_lock()


class Environment(unittest.TestCase):
    def test_ambient_overrides_are_removed_and_pinned_flags_are_encoded(self):
        hostile = {
            "RUSTFLAGS": "-Copt-level=0",
            "CARGO_ENCODED_RUSTFLAGS": "-Cdebuginfo=2",
            "RUSTC": "/tmp/fake-rustc",
            "RUSTC_WRAPPER": "/tmp/wrapper",
            "RUSTC_WORKSPACE_WRAPPER": "/tmp/workspace-wrapper",
            "CARGO_TARGET_DIR": "/tmp/ambient-target",
            "CARGO_PROFILE_RELEASE_DEBUG": "2",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER": "/tmp/ambient-linker",
        }
        with mock.patch.dict(os.environ, hostile, clear=False):
            env = runtime_build.environment(
                Path("/repo"), Path("/target"), Path("/stage"), Path("/sysroot")
            )
        self.assertNotIn("RUSTFLAGS", env)
        self.assertNotEqual(env["CARGO_ENCODED_RUSTFLAGS"], hostile["CARGO_ENCODED_RUSTFLAGS"])
        for key in (
            "RUSTC",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_PROFILE_RELEASE_DEBUG",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER",
        ):
            self.assertNotIn(key, env)
        flags = env["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
        self.assertIn(
            "-Clinker=/sysroot/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld",
            flags,
        )
        self.assertIn("-Clink-self-contained=yes", flags)
        self.assertIn("--remap-path-prefix=/repo=/gateprobes", flags)
        self.assertIn("--remap-path-prefix=/target=/target", flags)
        self.assertIn("--remap-path-prefix=/stage=/build", flags)
        self.assertEqual(env["CARGO_TARGET_DIR"], "/target")


class StaticPie(unittest.TestCase):
    @staticmethod
    def elf(programs, dynamic=((0, 0),)):
        count = len(programs)
        dynamic_offset = 64 + count * 56
        data = bytearray(dynamic_offset + len(dynamic) * 16)
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HHI", data, 16, 3, 62, 1)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, count)
        for index, program in enumerate(programs):
            kind, flags, offset, size = program
            struct.pack_into(
                "<IIQQQQQQ", data, 64 + index * 56,
                kind, flags, offset, 0, 0, size, size, 1,
            )
        for index, (tag, value) in enumerate(dynamic):
            struct.pack_into("<QQ", data, dynamic_offset + index * 16, tag, value)
        return bytes(data)

    def test_static_pie_positive(self):
        runtime_build.verify_static_pie(
            self.elf([(0x6474E552, 0, 0, 0), (0x6474E551, 0, 0, 0), (2, 0, 232, 16)])
        )

    def test_interpreter_needed_exec_stack_and_missing_relro_fail(self):
        cases = {
            "interp": [(3, 0, 0, 0), (0x6474E552, 0, 0, 0), (0x6474E551, 0, 0, 0)],
            "exec-stack": [(0x6474E552, 0, 0, 0), (0x6474E551, 1, 0, 0)],
            "missing-relro": [(0x6474E551, 0, 0, 0)],
            "missing-stack": [(0x6474E552, 0, 0, 0)],
        }
        for name, programs in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(RuntimeError):
                    runtime_build.verify_static_pie(self.elf(programs))
        with self.assertRaisesRegex(RuntimeError, "needed"):
            runtime_build.verify_static_pie(
                self.elf(
                    [(0x6474E552, 0, 0, 0), (0x6474E551, 0, 0, 0), (2, 0, 232, 16)],
                    dynamic=((1, 1), (0, 0)),
                )
            )


if __name__ == "__main__":
    unittest.main()
