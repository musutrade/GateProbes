#!/usr/bin/env python3
"""Deterministic adapter fixture used by the protocol contract tests."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def main() -> int:
    request = json.load(sys.stdin)
    mode = request.get("input", {}).get("mode", "pass")
    root = Path(os.environ["HARNESS_GATE_ARTIFACT_ROOT"])
    if mode == "crash":
        os._exit(17)
    if mode == "sleep":
        time.sleep(2)
    if mode == "stdout-spam":
        sys.stdout.write("x" * 4096)
        sys.stdout.flush()
        return 0
    if mode == "stderr-spam":
        sys.stderr.write("x" * 4096)
        sys.stderr.flush()
        return 0
    if mode == "artifact-spam":
        (root / "large.bin").write_bytes(b"x" * 4096)
    if mode == "malformed":
        print("not-json")
        return 0
    if mode == "escape":
        print(json.dumps({"schema_version": "1", "status": "PASS", "artifacts": [{"path": "../escape.txt", "kind": "fixture"}]}))
        return 0
    (root / "adapter-result.txt").write_text("adapter fixture passed\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "schema_version": "1",
                "status": "PASS",
                "invocation_id": request["invocation_id"],
                "artifacts": [{"path": "adapter-result.txt", "kind": "adapter-output"}],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
