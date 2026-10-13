#!/usr/bin/env python3
"""Shared helpers for the repository quality evidence commands."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / "tools" / "harness-gate"
QUALITY_ROOT = ROOT / "target" / "quality"


def command_output(command: list[str], cwd: Path = ROOT) -> str:
    return subprocess.check_output(command, cwd=cwd, text=True).strip()


def git_sha() -> str:
    return command_output(["git", "rev-parse", "HEAD"])


def metadata(**extra: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "commit": git_sha(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "os": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": platform.python_version(),
        "rustc": command_output(["rustc", "--version"]),
        "cargo": command_output(["cargo", "--version"]),
        "target": command_output(["rustc", "-vV"]).split("host: ", 1)[-1].splitlines()[0],
        "logical_cpus": os.cpu_count(),
    }
    data.update(extra)
    return data


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stats(values: Iterable[float]) -> dict[str, float]:
    samples = list(values)
    if not samples:
        raise ValueError("at least one sample is required")
    return {
        "count": len(samples),
        "min": min(samples),
        "max": max(samples),
        "median": median(samples),
    }


def fail(message: str) -> None:
    print(f"quality gate failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def run_checked(command: list[str], cwd: Path = ROOT, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """Run a quality command while retaining output for evidence callers."""
    return subprocess.run(command, cwd=cwd, check=True, text=True, **kwargs)
