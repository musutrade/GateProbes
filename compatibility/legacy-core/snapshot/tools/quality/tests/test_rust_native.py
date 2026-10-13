"""Native positives compile real Rust; mutated data is used only for negatives."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

QUALITY = Path(__file__).resolve().parents[1]
ROOT = QUALITY.parents[1]
sys.path.insert(0, str(QUALITY))
import rust_native as native


class NativeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("rustc"):
            raise unittest.SkipTest("rustc unavailable: real native fixture cannot run")
        version = subprocess.check_output(["rustc", "-vV"], text=True)
        if native.SUPPORTED_COMMIT not in version:
            raise unittest.SkipTest("native MIR adapter does not support this rustc commit")
        base = ROOT / "target/gh-220/native-tests"
        base.mkdir(parents=True, exist_ok=True)
        cls.work = Path(tempfile.mkdtemp(dir=base))
        target = ROOT / "target/gh-220/analyzer"
        env = {**os.environ, "CARGO_TARGET_DIR": str(target),
               "LLVM_PROFILE_FILE": str(cls.work / "build-%m-%p.profraw")}
        result = subprocess.run(["cargo", "build", "--locked", "--manifest-path",
                                 str(QUALITY / "rust-measure/Cargo.toml")], env=env, capture_output=True)
        (cls.work / "build.stdout").write_bytes(result.stdout)
        (cls.work / "build.stderr").write_bytes(result.stderr)
        if result.returncode:
            raise RuntimeError(f"native analyzer build failed: {cls.work / 'build.stderr'}")
        cls.analyzer = target / "debug/harness-gate-rust-measure"
        cls.evidence = cls.work / "complete"
        cls.anchor = native.collect(QUALITY / "fixtures/rust-native/complete.rs", cls.evidence, cls.analyzer)
        cls.report = native.certify(cls.evidence, cls.anchor)
        native.write_json(cls.evidence / "report.json", cls.report)
        cls.owners, _ = native.mir_inventory(cls.evidence / "raw/mir")
        cls.llvm = json.loads((cls.evidence / "raw/llvm.stdout").read_text())
        for function in cls.llvm["data"][0]["functions"]:
            function["filenames"] = ["source.rs"]
        cls.demangled = json.loads((cls.evidence / "raw/demangle.stdout").read_text())

    def test_real_closure_async_generic_and_macro_mapping(self):
        report = self.report
        self.assertTrue(report["certified_llvm_mapping"])
        self.assertFalse(report["backend_complete"])
        self.assertFalse(report["source_provenance_complete"])
        rows = {r["name"]: r for r in report["functions"]}
        self.assertEqual(rows["future"]["count"], 1)
        self.assertEqual(rows["future::{closure#0}"]["count"], 0)
        self.assertEqual(len(rows["generic"]["instances"]), 2)
        self.assertNotEqual(rows["first"]["regions"][0]["context"], rows["second"]["regions"][0]["context"])
        self.assertEqual(report["coverage"]["regions"], {"count": 36, "covered": 28})
        self.assertEqual(rows["future::{closure#0}"]["crap_exact"], [6, 1])
        self.assertIn("future::{closure#0}", report["threshold_failures"])
        self.assertNotIn("excluded_test", str(rows))

    def test_duplicate_omitted_ambiguous_and_unowned_regions(self):
        cases = []
        llvm = copy.deepcopy(self.llvm)
        llvm["data"][0]["functions"][0]["regions"].append(copy.deepcopy(llvm["data"][0]["functions"][0]["regions"][0]))
        cases.append((self.owners, llvm, self.demangled, "duplicate LLVM region"))
        llvm = copy.deepcopy(self.llvm)
        llvm["data"][0]["functions"].append(copy.deepcopy(llvm["data"][0]["functions"][0]))
        cases.append((self.owners, llvm, self.demangled + self.demangled[:1], "duplicate LLVM function"))
        llvm = copy.deepcopy(self.llvm)
        index = self.demangled.index("native_probe::future")
        llvm["data"][0]["functions"].pop(index)
        cases.append((self.owners, llvm, self.demangled[:index] + self.demangled[index + 1:], "missing LLVM owner"))
        cases.append((self.owners + self.owners[:1], self.llvm, self.demangled, "ambiguous MIR owner"))
        llvm = copy.deepcopy(self.llvm)
        llvm["data"][0]["functions"][0]["regions"][0][0] += 100
        cases.append((self.owners, llvm, self.demangled, "empty/reversed|unowned"))
        for owners, llvm, names, error in cases:
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                native.map_functions(owners, llvm, names)

    def changed_evidence(self, name, change, *, reanchor=False):
        target = self.work / name
        shutil.copytree(self.evidence, target)
        change(target / "raw")
        if reanchor:
            native.write_json(target / "evidence.json", {"artifacts": {
                str(p.relative_to(target / "raw")): native.digest(p.read_bytes())
                for p in (target / "raw").rglob("*") if p.is_file()}})
        return target, native.digest((target / "evidence.json").read_bytes())

    def test_tampering_and_new_hash_cannot_invent_native_counts(self):
        def change(raw):
            path = raw / "llvm.stdout"
            value = json.loads(path.read_text())
            value["data"][0]["functions"][0]["count"] += 1
            native.write_json(path, value)
        path, anchor = self.changed_evidence("tamper", change)
        with self.assertRaisesRegex(ValueError, "tampering"):
            native.certify(path, anchor)
        path, anchor = self.changed_evidence("reanchored", change, reanchor=True)
        with self.assertRaisesRegex(ValueError, "differs from native artifacts"):
            native.certify(path, anchor)

    def test_mir_omission_with_new_manifest_is_rejected(self):
        path, anchor = self.changed_evidence("omitted-mir", lambda raw: next((raw / "mir").glob("*after.mir")).unlink(), reanchor=True)
        with self.assertRaisesRegex(ValueError, "MIR inventory omission"):
            native.certify(path, anchor)

    def test_cfg_selection_and_history_identity(self):
        path = self.work / "cfg"
        anchor = native.collect(QUALITY / "fixtures/rust-native/complete.rs", path, self.analyzer, ['feature="extra"'])
        report = native.certify(path, anchor)
        native.write_json(path / "report.json", report)
        self.assertEqual(report["coverage"]["functions"]["count"], 9)
        self.assertTrue(any(r["name"] == "conditional" for r in report["functions"]))
        with self.assertRaisesRegex(ValueError, "incompatible history"):
            native.compatible(self.report, report)
        with self.assertRaisesRegex(ValueError, "test cfg"):
            native.compiler_flags(["test"])
        for key in ("series", "tools", "flags", "test_selection"):
            other = copy.deepcopy(self.report)
            other[key] = "changed"
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "incompatible history"):
                native.compatible(self.report, other)
        native.compatible(self.report, copy.deepcopy(self.report))

    def test_real_derive_cannot_claim_generated_functions_are_absent(self):
        path = self.work / "derived"
        anchor = native.collect(QUALITY / "fixtures/rust-native/derived-gap.rs", path, self.analyzer)
        owners, _ = native.mir_inventory(path / "raw/mir")
        self.assertTrue(any("clone" in r["name"] and not r["regions"] for r in owners))
        with self.assertRaisesRegex(ValueError, "MIR inventory omission|unobserved compiler function"):
            native.certify(path, anchor)

    def test_expansion_context_omission_is_rejected(self):
        text = (self.evidence / "raw/expansion.stdout").read_text()
        text = "\n".join(line for line in text.splitlines() if not line.startswith("#4: parent:"))
        with self.assertRaisesRegex(ValueError, "missing/cyclic syntax context|incomplete expansion graph"):
            native.expansion_contexts(text, self.owners)

    def test_retained_native_artifacts_replay_after_relocation(self):
        path = self.work / "relocated"
        shutil.copytree(self.evidence, path)
        report = native.certify(path, self.anchor)
        self.assertEqual(report["functions"], self.report["functions"])


if __name__ == "__main__":
    unittest.main()
