"""Required joint acceptance: missing inputs are errors, never skips."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent / "tests"))
from test_install import InstallCase

suite = unittest.TestSuite([InstallCase("test_joint_core_main_capabilities_with_published_assets")])
result = unittest.TextTestRunner(verbosity=2).run(suite)
if result.testsRun != 1 or result.skipped or result.expectedFailures or not result.wasSuccessful():
    raise SystemExit(1)
