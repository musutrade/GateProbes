"""Test-only checks for the repo-owned Docker runtime acceptance CLI."""
from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PLUGIN = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN / "accept.py"
SPEC = importlib.util.spec_from_file_location("docker_runtime_accept", SCRIPT)
accept = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(accept)


class InputValidation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="docker-accept-test-")
        self.root = Path(self.temporary.name)
        self.binary = self.root / "adapter"
        self.core = self.root / "harness-gate"
        self.report = self.root / "report.json"
        for path in (self.binary, self.core):
            path.write_bytes(b"\x7fELF" + b"\0" * 16)
            path.chmod(0o755)
        self.report.touch()

    def tearDown(self):
        self.temporary.cleanup()

    def args(self, **changes):
        values = {
            "binary": str(self.binary),
            "core": str(self.core),
            "version": "0.1.0",
            "report": str(self.report),
        }
        values.update(changes)
        return argparse.Namespace(**values)

    def test_accepts_explicit_canonical_inputs(self):
        binary, core, version, report = accept.validate_inputs(self.args())
        self.assertEqual(binary, self.binary)
        self.assertEqual(core, self.core)
        self.assertEqual(version, "0.1.0")
        self.assertEqual(report, self.report)

    def test_requires_absolute_paths(self):
        with self.assertRaisesRegex(accept.AcceptanceError, "absolute"):
            accept.validate_inputs(self.args(binary="adapter"))
        with self.assertRaisesRegex(accept.AcceptanceError, "absolute"):
            accept.validate_inputs(self.args(report="report.json"))

    def test_rejects_symlinks(self):
        link = self.root / "adapter-link"
        link.symlink_to(self.binary)
        with self.assertRaisesRegex(accept.AcceptanceError, "symlink"):
            accept.validate_inputs(self.args(binary=str(link)))

    def test_rejects_non_elf_and_non_executable(self):
        self.binary.write_bytes(b"not an elf")
        with self.assertRaisesRegex(accept.AcceptanceError, "ELF"):
            accept.validate_inputs(self.args())
        self.binary.write_bytes(b"\x7fELF" + b"\0" * 16)
        self.binary.chmod(0o644)
        with self.assertRaisesRegex(accept.AcceptanceError, "executable"):
            accept.validate_inputs(self.args())

    def test_rejects_invalid_version(self):
        for version in ("0.1", "v0.1.0", "0.1.0\n", ""):
            with self.subTest(version=version):
                with self.assertRaisesRegex(accept.AcceptanceError, "SemVer"):
                    accept.validate_inputs(self.args(version=version))

    def test_rejects_missing_or_ambiguous_report(self):
        with self.assertRaisesRegex(accept.AcceptanceError, "parent"):
            accept.validate_inputs(
                self.args(report=str(self.root / "missing" / "report.json"))
            )
        with self.assertRaisesRegex(accept.AcceptanceError, "overwrite"):
            accept.validate_inputs(self.args(report=str(self.binary)))

    def test_rejects_same_binary_and_core(self):
        with self.assertRaisesRegex(accept.AcceptanceError, "distinct"):
            accept.validate_inputs(self.args(core=str(self.binary)))

    def test_cli_help_and_missing_arguments(self):
        help_result = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("--binary", help_result.stdout)
        missing = subprocess.run(
            [sys.executable, str(SCRIPT), "--binary", str(self.binary)],
            capture_output=True,
            text=True,
            check=False,
            env={
                "GATEHOUSE_CORE": str(self.core),
                "HARNESS_GATE_BINARY": str(self.core),
                "GATEPROBES_NATIVE_ADAPTER_VERSION": "0.1.0",
            },
        )
        self.assertEqual(missing.returncode, 2)
        self.assertIn("--core", missing.stderr)
        self.assertIn("--version", missing.stderr)
        self.assertIn("--report", missing.stderr)


if __name__ == "__main__":
    unittest.main()
