#!/usr/bin/env python3
"""Fail the fixed aggregate unless every selected task succeeded.

Selection values must be present and exactly `true` or `false`. A missing or
invalid selection is a failure, never a silent skip. Classification must have
succeeded. Lightweight checks always run.
"""
from __future__ import annotations

import argparse
import sys


def selection(value: str, name: str) -> bool:
    if value not in ("true", "false"):
        raise ValueError(f"{name} selection is missing or invalid: {value!r}")
    return value == "true"


def evaluate(classify_result: str, run_light: str, run_plugins: str,
             light_result: str, plugins_result: str) -> list[str]:
    failures = []
    if classify_result != "success":
        return [f"classification did not succeed: {classify_result}"]
    try:
        light = selection(run_light, "run_light")
        plugins = selection(run_plugins, "run_plugins")
    except ValueError as error:
        return [str(error)]
    if not light:
        failures.append("run_light must always be true")
    elif light_result != "success":
        failures.append(f"lightweight checks selected but {light_result}")
    if plugins:
        if plugins_result != "success":
            failures.append(f"plugin checks selected but {plugins_result}")
    elif plugins_result not in ("skipped", "success"):
        failures.append(f"plugin checks not selected but {plugins_result}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--classify-result", required=True)
    parser.add_argument("--run-light", required=True)
    parser.add_argument("--run-plugins", required=True)
    parser.add_argument("--light-result", required=True)
    parser.add_argument("--plugins-result", required=True)
    args = parser.parse_args()
    failures = evaluate(args.classify_result, args.run_light, args.run_plugins,
                        args.light_result, args.plugins_result)
    if failures:
        print("aggregate failed:", file=sys.stderr)
        for failure in failures:
            print("  " + failure, file=sys.stderr)
        return 1
    print("aggregate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
