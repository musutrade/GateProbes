"""Real rustc/LLVM regression tests for source-owned closure entry mapping."""
import json
import os
from pathlib import Path
import unittest

from measure import measure
from test_toolchain_compatibility import logged_run, retained_measure, retained_root, tool_identity

HERE = Path(__file__).resolve().parent


class ClosureNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root, cls.tmp = retained_root('rust-source-closures-')
        if cls.tmp:
            cls.addClassCleanup(cls.tmp.cleanup)
        cls.inventory = Path(os.environ.get("RUST_SOURCE_INVENTORY", HERE / "inventory"))
        tools = tool_identity(cls.root)['tools']
        for name in ("closures", "closure_without_counter"):
            source = cls.root / (name + ".rs")
            source.write_text((HERE / "fixtures" / source.name).read_text())
            binary = cls.root / name
            logged_run(cls.root, name + '-compile', ["rustc", "--edition=2024", "-C", "instrument-coverage",
                                                    source, "-o", binary])
            raw = cls.root / (name + ".profraw")
            logged_run(cls.root, name + '-execute', [binary], env=dict(os.environ, LLVM_PROFILE_FILE=str(raw)))
            profile = cls.root / (name + ".profdata")
            logged_run(cls.root, name + '-merge', [tools['llvm-profdata']['path'], "merge", "-sparse", raw,
                                                  "-o", profile])
            exported = logged_run(cls.root, name + '-export', [tools['llvm-cov']['path'], "export",
                                                              "-instr-profile=" + str(profile), binary])
            (cls.root / (name + '.json')).write_bytes(exported.stdout)

    def result(self, name="closures", llvm=None):
        result = retained_measure(self.root, self._testMethodName,
                                  lambda: measure(self.root, [name + ".rs"], llvm or self.root / (name + ".json"),
                                                  self.inventory))
        return result['functions']

    def row(self, rows, binding):
        lines = (self.root / "closures.rs").read_text().splitlines()
        line = next(i + 1 for i, text in enumerate(lines) if "let " + binding + " =" in text)
        return next(row for row in rows if row["kind"] == "closure" and row["start"][0] == line)

    def test_source_shapes_map_and_decisions_stay_owned(self):
        rows = self.result()
        self.assertEqual(len(rows), 21)
        for binding in ("tuple", "negate", "arithmetic", "array", "structure", "paren",
                        "cast", "call", "nested", "block", "binary", "condition", "short"):
            with self.subTest(binding=binding):
                self.assertEqual(self.row(rows, binding)["coverage.function"]["numerator"], 1)
        self.assertEqual(self.row(rows, "tuple")["complexity"], 2)
        self.assertEqual(self.row(rows, "negate")["complexity"], 1)
        self.assertEqual(self.row(rows, "condition")["complexity"], 2)
        self.assertEqual(self.row(rows, "short")["complexity"], 2)
        self.assertEqual(self.row(rows, "outer")["complexity"], 1)
        inner = next(row for row in rows if row["kind"] == "closure"
                     and row["start"][0] == self.row(rows, "outer")["start"][0]
                     and row["start"] != self.row(rows, "outer")["start"])
        self.assertEqual(inner["complexity"], 2)

    def test_uncalled_closure_does_not_borrow_parent_execution(self):
        row = self.row(self.result(), "uncalled")
        for metric in ("coverage.function", "coverage.line", "coverage.region"):
            self.assertEqual(row[metric]["numerator"], 0)
            self.assertGreater(row[metric]["denominator"], 0)

    def test_async_factory_is_not_poll_execution(self):
        rows = self.result()
        factory = self.row(rows, "future")
        self.assertEqual(factory["coverage.function"]["numerator"], 1)
        poll = next(row for row in rows if row["kind"] == "async-block")
        for metric in ("coverage.function", "coverage.line", "coverage.region"):
            self.assertEqual(poll[metric]["numerator"], 0)
            self.assertGreater(poll[metric]["denominator"], 0)

    def test_missing_compiler_counter_remains_an_error(self):
        with self.assertRaisesRegex(ValueError, "source callable missing native mapping"):
            self.result("closure_without_counter")

    def test_all_missing_source_owners_are_reported(self):
        rows = self.result()
        removed = [self.row(rows, binding) for binding in ("tuple", "negate")]
        lines = {row["start"][0] for row in removed}
        data = json.loads((self.root / "closures.json").read_text())
        for unit in data["data"]:
            unit["functions"] = [function for function in unit["functions"]
                                 if function["regions"][0][0] not in lines]
        path = self.root / "missing-owners.json"
        path.write_text(json.dumps(data))
        with self.assertRaises(ValueError) as error:
            self.result(llvm=path)
        for row in removed:
            self.assertIn(f'closures.rs:{row["start"]} (closure)', str(error.exception))
        self.assertIn("parent execution is not a substitute", str(error.exception))

    def test_later_tuple_element_is_not_an_entry_anchor(self):
        row = self.row(self.result(), "tuple")
        data = json.loads((self.root / "closures.json").read_text())
        source = self.root / "closures.rs"
        changed = 0
        for unit in data["data"]:
            for function in unit["functions"]:
                first = function["regions"][0]
                if function["filenames"][first[5]] == str(source) and first[0] == row["start"][0]:
                    changed += 1
                    line = source.read_text().splitlines()[first[0] - 1]
                    start = line.index(", x") + 3
                    function["regions"][0] = [first[0], start, first[0], start + 1, first[4], 0, 0, 0]
        self.assertGreater(changed, 0)
        path = self.root / "invalid-entry.json"
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "exact source anchor"):
            self.result(llvm=path)


if __name__ == "__main__":
    unittest.main()
