#!/usr/bin/env python3
"""Pinned Core interface acceptance for the rust-source-risk plugin.

The plugin's own protocol/series suite covers the wire contract; this script
checks the interface the fixed Core relies on: the manifest identity, the
request schema and the metric names/kinds against the pinned Core
`harness_evidence.METRIC_TYPES`. It never builds the LLVM capture fixture.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-root", type=Path, required=True,
                        help="directory with the pinned core harness_evidence module")
    parser.add_argument("--plugin", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    plugin_dir = args.plugin.resolve()
    sys.path.insert(0, str(plugin_dir))
    sys.path.insert(0, str(args.core_root.resolve()))
    import harness_evidence
    import plugin as collector
    manifest = json.loads((plugin_dir / "plugin.json").read_text())
    if manifest["name"] != collector.COLLECTOR["name"]:
        raise SystemExit(f"collector name mismatch: {manifest['name']}")
    if manifest["version"] != collector.COLLECTOR["version"]:
        raise SystemExit(f"collector version mismatch: {manifest['version']}")
    if manifest["request_schema"] != "harness-collector-request/v1" or manifest["adapter_protocol"] != 2:
        raise SystemExit("unexpected request schema or adapter protocol")
    for metric, kind in sorted(collector.TYPES.items()):
        if not harness_evidence.metric_type_matches(metric, kind):
            expected = harness_evidence.METRIC_TYPES.get(metric)
            raise SystemExit(f"metric kind mismatch for {metric}: {kind} != {expected}")
    print(json.dumps({"collector": collector.COLLECTOR,
                      "metrics": sorted(collector.TYPES)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
