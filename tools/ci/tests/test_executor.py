"""Only implemented plugin languages pass the executor guard."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import executor


class ExecutorTests(unittest.TestCase):
    def test_typescript_executor_is_implemented(self):
        self.assertEqual(executor.check("typescript"), "typescript")

    def test_planned_languages_fail_explicitly_until_their_executor_lands(self):
        for language in ("rust", "python"):
            with self.subTest(language=language):
                with self.assertRaisesRegex(ValueError, "no executor implemented"):
                    executor.check(language)

    def test_missing_or_invalid_language_fails(self):
        for language in ("", None, 1):
            with self.subTest(language=language):
                with self.assertRaisesRegex(ValueError, "missing or invalid"):
                    executor.check(language)


if __name__ == "__main__":
    unittest.main()
