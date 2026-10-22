"""Readiness release trust and extracted-product dispatch boundaries."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools/release'))
import readiness_core
import package_runtime


class ReadinessDelivery(unittest.TestCase):
    def test_pin_is_exact_and_modified_pin_is_rejected(self):
        pin = readiness_core.contract(ROOT)
        self.assertEqual(pin['version'], '0.9.0')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / 'plugins/docker-readiness/core-pin.json'
            path.parent.mkdir(parents=True)
            pin['source_commit'] = '0' * 40
            path.write_text(json.dumps(pin))
            with self.assertRaises(ValueError):
                readiness_core.contract(root)

    def test_bad_digest_and_symlink_never_execute(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'bin').mkdir()
            binary = root / 'bin/harness-gate-linux-amd64'
            binary.write_bytes(b'untrusted')
            with mock.patch.object(readiness_core.subprocess, 'run') as run:
                with self.assertRaises(ValueError): readiness_core.verify(root)
                binary.unlink(); binary.symlink_to('/bin/true')
                with self.assertRaises(ValueError): readiness_core.verify(root)
                run.assert_not_called()

    def test_verified_bytes_still_require_exact_version_and_empty_stderr(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'bin').mkdir()
            binary = root / 'bin/harness-gate-linux-amd64'; binary.write_bytes(b'fixture')
            pin = dict(readiness_core.EXPECTED, sha256=hashlib.sha256(b'fixture').hexdigest())
            with mock.patch.object(readiness_core, 'contract', return_value=pin):
                for stdout, stderr in [('harness-gate 0.8.0\n', ''), ('harness-gate 0.9.0\n', 'warning')]:
                    with mock.patch.object(readiness_core.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout, stderr)):
                        with self.assertRaises(ValueError): readiness_core.verify(root)

    def test_download_digest_rejection_precedes_execution(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(readiness_core.urllib.request, 'urlopen', return_value=io.BytesIO(b'bad')), mock.patch.object(readiness_core.subprocess, 'run') as run:
            with self.assertRaises(ValueError): readiness_core.prepare(Path(temp) / 'core')
            run.assert_not_called()
            self.assertFalse((Path(temp) / 'core/contract.json').exists())

    def test_package_accepts_only_extracted_readiness_and_retains_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); output = root / 'out'; output.mkdir()
            core = root / 'core'; (core / 'bin').mkdir(parents=True)
            (core / 'bin/harness-gate-linux-amd64').write_bytes(b'core')
            archive = 'gateprobes-docker-readiness-0.2.0-linux-amd64.tar.gz'
            binary = 'gateprobes-docker-readiness'
            identity = {'archive': archive, 'version': '0.2.0'}
            def build(repo, out, product):
                self.assertEqual(product, 'docker-readiness')
                (out / archive).write_bytes(package_runtime.archive_bytes(archive[:-7], {binary:b'ELF', 'accept.py':b'accept'}, binary))
            invalid = None
            def run(*args, **kwargs):
                script = Path(args[1]); adapter = Path(args[args.index('--binary')+1])
                self.assertEqual(script.read_bytes(), b'accept')
                self.assertEqual(adapter.name, binary)
                self.assertEqual(adapter.read_bytes(), b'ELF')
                self.assertEqual(args[args.index('--version')+1], '0.2.0')
                report = {'passed':6, 'cases':[{'case':c, 'stderr':'', 'exit':0 if c == 'present' else 1} for c in ['present','missing','unavailable','changed','timeout','fixed-expected']], 'core_sha256':hashlib.sha256(b'core').hexdigest(), 'adapter_sha256':hashlib.sha256(b'ELF').hexdigest()}
                if invalid == 'count': report['passed'] = 5
                if invalid == 'core': report['core_sha256'] = '0' * 64
                if invalid == 'adapter': report['adapter_sha256'] = '0' * 64
                if invalid == 'exit': report['cases'][1]['exit'] = 0
                if invalid == 'stderr': report['cases'][0]['stderr'] = 'warning'
                Path(args[args.index('--report')+1]).write_text(json.dumps(report))
            with mock.patch.object(package_runtime, 'build', side_effect=build), mock.patch.object(package_runtime.plugin_release, 'resolve', return_value=identity), mock.patch('package_plugin.run', side_effect=run), mock.patch.dict('os.environ', {'HARNESS_GATE_RUNTIME_ACCEPTANCE':str(root/'evidence')}):
                package_runtime.package(ROOT, output, core, 'docker-readiness')
                for invalid in ['count', 'core', 'adapter', 'exit', 'stderr']:
                    with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                        package_runtime.package(ROOT, output, core, 'docker-readiness')
            self.assertEqual(json.loads((root/'evidence/docker-readiness.json').read_text())['passed'], 6)
