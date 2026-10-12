#!/usr/bin/env python3
"""Run named helper modules and fail on any skipped or failed test."""
import sys
import unittest


def main() -> int:
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite(loader.loadTestsFromName(name) for name in sys.argv[1:])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.skipped:
        print("helper suite must not skip tests", file=sys.stderr)
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
