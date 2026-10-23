import argparse
import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("plugin_manager", Path(__file__).with_name("plugin_manager.py"))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.key = self.root / "private.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.key)], check=True)
        self.prepared = self.root / "prepared"
        self.lock = self.root / "new.json"
        m.prepare(argparse.Namespace(source=m.ROOT, catalog="products/onboarding/products.json", product=["rust-minimal", "python-minimal"],
                                    output=self.prepared, signing_key=self.key, key_id="operator", lock_output=self.lock))
        self.active = self.root / "project/.harness-gate/plugins.lock.json"
        self.store = self.root / "installed"
        self.plan = self.root / "plan.json"
        self.receipt = self.root / "receipt.json"
        with contextlib.redirect_stdout(io.StringIO()):
            m.plan(argparse.Namespace(lock=self.lock, active_lock=self.active, store=self.store, prepared=self.prepared, output=self.plan))
        self.apply_args = argparse.Namespace(plan=self.plan, receipt=self.receipt, core=self.root / "core", trusted_key=[self.root / "operator.json"])

    def test_explicit_apply_and_rollback_retain_material_and_never_replace_system_tools(self):
        with patch.object(m, "preflight") as preflight, contextlib.redirect_stdout(io.StringIO()):
            m.apply(self.apply_args)
            self.assertEqual(preflight.call_count, 2)
            self.assertEqual(preflight.call_args_list[0].args[-1], self.apply_args.trusted_key)
            self.assertEqual(self.active.read_bytes(), self.lock.read_bytes())
            installed = self.store / "rust-minimal/1.0.8/plugin.json"
            before = installed.read_bytes()
            m.rollback(argparse.Namespace(receipt=self.receipt))
            self.assertFalse(self.active.exists())
            self.assertEqual(installed.read_bytes(), before)
            self.assertEqual(m.decode(self.receipt.read_bytes())["state"], "rolled-back")

    def test_rejecting_core_keeps_lock_unchanged_and_receipt_recoverable(self):
        with patch.object(m, "preflight", side_effect=ValueError("HGPLUGIN-SIGNATURE")):
            with self.assertRaisesRegex(ValueError, "HGPLUGIN-SIGNATURE"):
                m.apply(self.apply_args)
        self.assertFalse(self.active.exists())
        self.assertFalse(self.store.exists())
        self.assertEqual(m.decode(self.receipt.read_bytes())["state"], "prepared")
        with contextlib.redirect_stdout(io.StringIO()):
            m.rollback(argparse.Namespace(receipt=self.receipt))

    def test_stale_plan_and_misleading_change_list_are_rejected_before_mutation(self):
        value = m.decode(self.plan.read_bytes())
        value["changes"] = []
        self.plan.write_bytes(m.encode(value))
        with self.assertRaisesRegex(ValueError, "reviewed pins"):
            m.apply(self.apply_args)
        self.assertFalse(self.receipt.exists())
        value["changes"] = [{**row, "action": "install"} for row in value["selection"]["plugins"]]
        self.plan.write_bytes(m.encode(value))
        self.active.parent.mkdir(parents=True, exist_ok=True)
        self.active.write_text("unrelated newer lock")
        with self.assertRaisesRegex(ValueError, "stale or modified"):
            m.apply(self.apply_args)
        self.assertEqual(self.active.read_text(), "unrelated newer lock")

    def test_changed_store_is_rejected_after_copy_before_activating_lock(self):
        with patch.object(m, "preflight", side_effect=[None, ValueError("HGPLUGIN-DIGEST")]):
            with self.assertRaisesRegex(ValueError, "HGPLUGIN-DIGEST"):
                m.apply(self.apply_args)
        self.assertFalse(self.active.exists())
        self.assertTrue(self.store.exists())
        self.assertTrue(self.receipt.is_file())

    def test_rollback_restores_exact_previous_lock_and_refuses_unrelated_edits(self):
        previous = b'{"old":"exact bytes"}\n'
        self.active.parent.mkdir(parents=True)
        self.active.write_bytes(previous)
        value = m.decode(self.plan.read_bytes())
        value["previous_lock"] = base64.b64encode(previous).decode()
        self.plan.write_bytes(m.encode(value))
        with patch.object(m, "preflight"), contextlib.redirect_stdout(io.StringIO()):
            m.apply(self.apply_args)
            self.active.write_bytes(b"later edit")
            with self.assertRaisesRegex(ValueError, "unrelated work"):
                m.rollback(argparse.Namespace(receipt=self.receipt))
            self.active.write_bytes(self.lock.read_bytes())
            m.rollback(argparse.Namespace(receipt=self.receipt))
        self.assertEqual(self.active.read_bytes(), previous)

    def test_operator_signature_binds_exact_manifest_and_domain(self):
        package = self.prepared / "rust-minimal/1.0.8"
        payload = self.root / "payload"
        payload.write_bytes(m.DOMAIN + (package / "plugin.json").read_bytes())
        signature = m.decode((package / "plugin.sig").read_bytes())
        sigfile = self.root / "signature"
        sigfile.write_bytes(base64.b64decode(signature["signature"]))
        public = self.root / "public.pem"
        subprocess.run(["openssl", "pkey", "-in", str(self.key), "-pubout", "-out", str(public)], check=True)
        command = ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public), "-sigfile", str(sigfile), "-in", str(payload)]
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
        payload.write_bytes(b"tampered")
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

    def test_path_traversal_duplicate_and_overwrite_are_refused(self):
        for path in ("../outside", "/absolute", "a/../b", "a\\b", "a:b"):
            with self.assertRaises(ValueError):
                m.relative(m.ROOT, path)
        with self.assertRaises(ValueError):
            m.relative(self.root, str(self.plan))
        with self.assertRaises(ValueError):
            m.pins(b'{"schema":"harness-plugin-lock/v1","plugins":[{"name":"../outside","version":"1.0.0"}]}')
        with self.assertRaises(ValueError):
            m.decode('{"schema":"a","schema":"b"}')
        with self.assertRaises(FileExistsError):
            m.exclusive(self.plan, b"overwrite")

    def test_preflight_requires_host_key_and_structured_core_success(self):
        self.apply_args.core.write_text("placeholder")
        self.apply_args.trusted_key[0].write_text("operator key")
        with patch.object(m.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b'{"valid":true,"diagnostics":[]}', b"")) as run:
            m.preflight(self.apply_args.core, self.lock, self.prepared, self.apply_args.trusted_key)
            args = run.call_args.args[0]
            self.assertIn("--plugin-trusted-key", args)
            self.assertEqual(args[-1], "--json")
        for result in (subprocess.CompletedProcess([],1,b"HGPLUGIN-SIGNATURE",b""), subprocess.CompletedProcess([],0,b'{"valid":false}',b"")):
            with patch.object(m.subprocess, "run", return_value=result):
                with self.assertRaises(ValueError):
                    m.preflight(self.apply_args.core, self.lock, self.prepared, self.apply_args.trusted_key)


if __name__ == "__main__":
    unittest.main()
