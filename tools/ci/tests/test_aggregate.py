"""The fixed aggregate never accepts a missing or invalid selection."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import aggregate


class AggregateTests(unittest.TestCase):
    def test_selected_tasks_succeed(self):
        self.assertEqual(
            aggregate.evaluate("success", "true", "true", "success", "success",
                               "success", "success"), [])

    def test_selected_preset_failure_skip_or_missing_result_blocks(self):
        for result in ("failure", "cancelled", "skipped", ""):
            with self.subTest(result=result):
                failures = aggregate.evaluate("success", "true", "true", "success",
                                              "success", "success", result)
                self.assertTrue(any("preset checks selected" in failure for failure in failures))

    def test_classification_failure_fails_the_aggregate(self):
        failures = aggregate.evaluate("failure", "", "", "", "", "", "success")
        self.assertTrue(any("classification" in failure for failure in failures), failures)

    def test_missing_or_invalid_selection_fails(self):
        for run_light, run_plugins in (("", "true"), ("yes", "true"),
                                       ("true", ""), ("true", "1")):
            with self.subTest(run_light=run_light, run_plugins=run_plugins):
                failures = aggregate.evaluate("success", run_light, run_plugins,
                                              "success", "success", "success", "success")
                self.assertTrue(any("missing or invalid" in failure for failure in failures))

    def test_selected_failed_task_fails(self):
        failures = aggregate.evaluate("success", "true", "true", "success", "success",
                                      "failure", "success")
        self.assertTrue(any("plugin checks selected but failure" in failure for failure in failures))
        failures = aggregate.evaluate("success", "true", "false", "failure", "success",
                                      "skipped", "success")
        self.assertTrue(any("lightweight checks selected but failure" in failure for failure in failures))

    def test_runtime_wire_acceptance_is_required(self):
        for result in ("failure", "cancelled", "skipped", ""):
            with self.subTest(result=result):
                failures = aggregate.evaluate("success", "true", "true", "success",
                                              result, "success", "success")
                self.assertTrue(
                    any("runtime wire acceptance selected" in failure for failure in failures),
                    failures)

    def test_light_checks_must_always_run(self):
        failures = aggregate.evaluate("success", "false", "false", "skipped", "skipped",
                                      "skipped", "success")
        self.assertIn("run_light must always be true", failures)

    def test_unselected_plugin_checks_may_skip(self):
        self.assertEqual(
            aggregate.evaluate("success", "true", "false", "success", "success",
                               "skipped", "success"), [])
        failures = aggregate.evaluate("success", "true", "false", "success", "success",
                                      "failure", "success")
        self.assertTrue(any("not selected but failure" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
