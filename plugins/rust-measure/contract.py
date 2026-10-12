#!/usr/bin/env python3
"""Pinned Core consumer acceptance for the Rust measurer.

Runs the built binary through the pinned Harness-Gate `source_measure.ast`
contract from the commit recorded in `docs/ownership.json`. That consumer
asserts the `harness-gate-rust-measure/0.3.1` / `mccabe-rust-3` identity and the
compiler target configuration echo, so a binary the pinned Core would reject
fails here instead of being published.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--core-root", type=Path, required=True,
                        help="directory with the pinned core tools/quality modules")
    args = parser.parse_args()
    sys.path.insert(0, str(args.core_root.resolve()))
    import source_measure
    with tempfile.TemporaryDirectory(prefix="rust-measure-contract-") as directory:
        source = Path(directory) / "smoke.rs"
        source.write_text("fn published_measure(x: bool) { if x {} }\n")
        report = source_measure.ast(source, args.binary.resolve())
    print(json.dumps({"analyzer": report["analyzer"], "version": report["version"],
                      "rule": report["rule"], "symbols": len(report["symbols"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
