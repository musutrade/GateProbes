#!/usr/bin/env python3
"""Reject plugin languages whose executor is not implemented in this workflow.

`plugins/registry.json` may list languages that are planned but not migrated
yet. The plugin job must fail explicitly for them instead of skipping every
language step and reporting success. A language becomes accepted only when its
executor steps are added to the workflow in the same change.
"""
from __future__ import annotations

import argparse
import sys

IMPLEMENTED = ("rust", "typescript")


def check(language: str, implemented=IMPLEMENTED) -> str:
    if not isinstance(language, str) or not language:
        raise ValueError(f"plugin language is missing or invalid: {language!r}")
    if language not in implemented:
        raise ValueError(
            f"no executor implemented for language {language!r}; implemented: "
            + ", ".join(sorted(implemented)))
    return language


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", required=True)
    args = parser.parse_args()
    try:
        print("executor available: " + check(args.language))
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
