"""Test-only guarantees for the build-only/full-release package split."""
from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/release"))

import package_runtime  # noqa: E402

IDENTITY = {
    "archive": "gateprobes-docker-runtime-0.1.0-linux-amd64.tar.gz",
    "version": "0.1.0",
}


def archive(output: Path) -> None:
    prefix = IDENTITY["archive"].removesuffix(".tar.gz")
    output.joinpath(IDENTITY["archive"]).write_bytes(
        package_runtime.archive_bytes(
            prefix,
            {
                "accept.py": b"# acceptance entry",
                "gateprobes-docker-runtime": b"native",
            },
        )
    )


class FullPackage(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="runtime-wrapper-test-")
        self.root = Path(self.temporary.name) / "repo"
        self.output = Path(self.temporary.name) / "output"
        self.root.mkdir()
        self.output.mkdir()
        self.build = mock.patch.object(
            package_runtime, "build", side_effect=lambda _root, output, product: archive(output)
        )
        self.resolve = mock.patch.object(
            package_runtime.plugin_release, "resolve", return_value=IDENTITY
        )
        self.build.start()
        self.resolve.start()
        self.addCleanup(self.resolve.stop)
        self.addCleanup(self.build.stop)
        self.addCleanup(self.temporary.cleanup)

    def run_acceptance(self, report_writer=None):
        original = subprocess.CalledProcessError(17, ["acceptance-sentinel"])
        def fake_run(*args, **kwargs):
            report = Path(args[args.index("--report") + 1])
            if report_writer is not None:
                report_writer(report)
            raise original

        with mock.patch("package_plugin.run", side_effect=fake_run) as run:
            error = None
            stderr = io.StringIO()
            try:
                with mock.patch("sys.stderr", stderr):
                    package_runtime.package(self.root, self.output, self.root / "core")
            except subprocess.CalledProcessError as raised:
                error = raised
            self.assertIs(error, original)
            return run, error, stderr.getvalue()

    def test_package_always_calls_build_then_extracted_acceptance(self):
        calls = []

        def fake_run(*args, **kwargs):
            calls.append(args)
            return ""

        with mock.patch("package_plugin.run", side_effect=fake_run):
            package_runtime.package(self.root, self.output, self.root / "core")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "python3")
        self.assertIn("accept.py", calls[0][1])
        self.assertIn("--binary", calls[0])
        self.assertIn("--core", calls[0])
        self.assertIn("--version", calls[0])
        self.assertIn("--report", calls[0])

    def test_nonzero_acceptance_propagates_and_logs_failed_case(self):
        report = {
            "cases": [
                {
                    "case": "present",
                    "ok": False,
                    "exit": 1,
                    "errors": ["expected failure"],
                    "stderr": "bounded diagnostic",
                }
            ]
        }
        run, error, output = self.run_acceptance(
            lambda path: path.write_text(json.dumps(report))
        )
        self.assertIsInstance(error, subprocess.CalledProcessError)
        self.assertIn("runtime acceptance diagnostic", output)
        self.assertIn('"case": "present"', output)
        self.assertIn("bounded diagnostic", output)
        self.assertEqual(run.call_count, 1)

    def test_missing_report_preserves_original_failure(self):
        run, error, output = self.run_acceptance()
        self.assertIsInstance(error, subprocess.CalledProcessError)
        self.assertIn("runtime acceptance report unavailable or malformed", output)
        self.assertEqual(run.call_count, 1)

    def test_malformed_report_preserves_original_failure(self):
        run, error, output = self.run_acceptance(
            lambda path: path.write_text("{not-json")
        )
        self.assertIsInstance(error, subprocess.CalledProcessError)
        self.assertIn("runtime acceptance report unavailable or malformed", output)
        self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
