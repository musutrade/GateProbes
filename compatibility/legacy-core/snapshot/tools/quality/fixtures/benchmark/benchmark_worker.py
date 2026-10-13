#!/usr/bin/env python3
"""Deterministic benchmark worker that records observed process concurrency."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def acquire_lock(lock_path: Path, deadline: float) -> None:
    while True:
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(descriptor)
            return
        except (FileExistsError, PermissionError):
            # Windows reports access-denied while another process briefly holds
            # the lock file open, so both errors mean the lock is contended.
            if time.monotonic() >= deadline:
                raise RuntimeError("timed out acquiring benchmark state lock")
            time.sleep(0.01)


def release_lock(lock_path: Path) -> None:
    deadline = time.monotonic() + 1
    while True:
        try:
            lock_path.unlink(missing_ok=True)
            return
        except PermissionError:
            if time.monotonic() >= deadline:
                return
            time.sleep(0.01)


def update_state(path: Path, delta: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    acquire_lock(lock_path, time.monotonic() + 10)
    try:
        if path.is_file():
            state = json.loads(path.read_text())
        else:
            state = {"current": 0, "observed_peak": 0, "workers": 0}
        state["current"] += delta
        state["workers"] += 1 if delta > 0 else 0
        if delta > 0:
            state["observed_peak"] = max(state["observed_peak"], state["current"])
        path.write_text(json.dumps(state, sort_keys=True) + "\n")
    finally:
        release_lock(lock_path)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: benchmark_worker.py STATE", file=sys.stderr)
        return 2
    state_path = Path(sys.argv[1])
    update_state(state_path, 1)
    try:
        # Keep both independent workers overlapping in parallel mode while
        # remaining short enough for repeated quality samples.
        time.sleep(0.25)
    finally:
        update_state(state_path, -1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
