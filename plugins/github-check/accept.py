"""Run real-Core acceptance; missing inputs and skipped tests fail closed."""
import os
from pathlib import Path
import sys
import unittest

core = Path(os.environ.get("GATEHOUSE_CORE", ""))
if not core.is_file():
    raise SystemExit("GATEHOUSE_CORE must name the pinned released binary")
suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent / "tests"))
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() and result.testsRun >= 26 and not result.skipped else 1)
