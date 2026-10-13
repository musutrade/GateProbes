#!/usr/bin/env python3
"""Frozen non-authoritative Python reference; see docs/quality/python-retention.md.

Generic decisions belong to the released Rust core. No release-approval path.
Python transport remains supported; its generic preflight is reference-only.

Collector transport and validation boundary; never a release evaluator."""
from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
from typing import Callable

import harness_evidence as evidence
import project_model as model


class CollectionError(ValueError):
    """A typed, fail-closed collection failure (no usable evidence)."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code

    def as_dict(self):
        return {"code": self.code, "message": str(self)}


def require(condition, code, message):
    if not condition:
        raise CollectionError(code, message)


HOST_SCHEMA = "collector-protocol.schema.json"


def host_schema_directory():
    """Resolve the host-contract schema in source and installed layouts."""
    installed = Path(__file__).resolve().parent / "schema"
    if (installed / HOST_SCHEMA).is_file():
        return installed
    return Path(__file__).resolve().parents[2] / "schema"


def _shape(value, definition):
    evidence._shape(value, HOST_SCHEMA, definition,
                    directory=host_schema_directory())


@dataclass(frozen=True)
class InternalAdapter:
    """Trusted in-process implementation: callable(request) -> response object."""

    collect: Callable[[dict], dict]

    def invoke(self, request):
        try:
            return self.collect(request)
        except Exception as error:
            raise CollectionError("adapter_error", str(error)) from error


def _reject_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")


@dataclass(frozen=True)
class SubprocessAdapter:
    """Explicit argv, one JSON request on stdin, one JSON response on stdout."""

    argv: tuple[str, ...]
    timeout_seconds: float = 60

    def invoke(self, request):
        require(bool(self.argv) and all(isinstance(a, str) and a for a in self.argv),
                "invalid_request", "collector argv must be nonempty strings")
        require(isinstance(self.timeout_seconds, (int, float)) and
                math.isfinite(self.timeout_seconds) and self.timeout_seconds > 0,
                "invalid_request", "collector timeout must be finite and positive")
        try:
            with subprocess.Popen(
                self.argv, cwd=request["workspace_root"], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=os.name == "posix",
            ) as process:
                try:
                    stdout, _stderr = process.communicate(
                        evidence._canonical(request), timeout=self.timeout_seconds)
                except subprocess.TimeoutExpired as error:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                    process.communicate()
                    raise CollectionError("timeout", "collector exceeded deadline") from error
                require(process.returncode == 0, "subprocess_exit",
                        f"collector exited with code {process.returncode}")
        except OSError as error:
            raise CollectionError("subprocess_error", str(error)) from error
        try:
            return json.loads(stdout.decode("utf-8"), object_pairs_hook=evidence._unique_object,
                              parse_constant=_reject_constant)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise CollectionError("malformed_json", str(error)) from error


def _request(request, project):
    try:
        _shape(request, "Request")
        model.validate_project(project)
        evidence._shape(request["context"], definition="Context")
        evidence._shape(request["collector"], definition="Versioned")
        require(request["project"] == project["id"], "invalid_request", "project mismatch")
        component = next((c for c in project["components"]
                          if c["id"] == request["component"]), None)
        require(component is not None, "invalid_request", "unknown component")
        require(any(s["component"] == request["component"] and
                    s["target"] == request["context"]["target"] for s in project["subjects"]),
                "invalid_request", "component has no subjects for target")
        capabilities = request["requested_capabilities"]
        require(len(set(capabilities)) == len(capabilities) and
                set(capabilities) <= evidence.METRIC_TYPES.keys(),
                "invalid_request", "unknown or duplicate requested capability")
        roots = []
        for key in ("workspace_root", "output_root"):
            path = Path(request[key])
            require(path.is_absolute() and path.resolve(strict=True) == path and path.is_dir(),
                    "invalid_request", f"{key} must be an existing canonical absolute directory")
            roots.append(path)
        workspace, output = roots
        require(not workspace.is_relative_to(output), "invalid_request",
                "output root must not contain workspace")
        require(not any(output.iterdir()), "invalid_request", "output root must be empty")
        return workspace, output
    except (evidence.MeasurementError, model.ModelError, OSError, RuntimeError) as error:
        raise CollectionError("invalid_request", str(error)) from error


def _walk_error(error):
    raise error


def _output_files(root):
    require(root.resolve(strict=True) == root and root.is_dir(),
            "output_root_escape", "collector replaced output root")
    files = set()
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=_walk_error):
        for name in dirs + names:
            path = Path(directory) / name
            require(not path.is_symlink() and path.resolve(strict=True).is_relative_to(root),
                    "output_root_escape", "symlink or path escapes output root")
            if name in names:
                require(path.is_file(), "invalid_artifact", "output is not a regular file")
                files.add(path.relative_to(root).as_posix())
    return files


def _artifacts(response, output):
    declared, paths = {}, set()
    for artifact in response["artifacts"]:
        evidence._shape(artifact, definition="Artifact")
        try:
            model.canonical_path(artifact["path"])
        except model.ModelError as error:
            raise CollectionError("output_root_escape", str(error)) from error
        require(artifact["id"] not in declared and artifact["path"] not in paths,
                "invalid_artifact", "duplicate artifact ID/path")
        declared[artifact["id"]] = artifact
        paths.add(artifact["path"])
    actual = _output_files(output)
    require(not actual - paths, "undeclared_artifact", "output contains undeclared artifact")
    require(not paths - actual, "missing_artifact", "declared artifact is missing")
    linked = {}
    for record in response["evidence"]:
        for artifact in record["artifacts"]:
            require(declared.get(artifact["id"]) == artifact, "undeclared_artifact",
                    "evidence artifact is absent or differs from response inventory")
            linked[artifact["id"]] = artifact
    require(linked == declared, "undeclared_artifact", "inventory contains unlinked artifact")
    for artifact in declared.values():
        data = (output / artifact["path"]).read_bytes()
        require(len(data) == artifact["bytes"] and
                hashlib.sha256(data).hexdigest() == artifact["sha256"],
                "artifact_tampering", "artifact digest/byte count mismatch")


def _response(response, request, project, workspace, output):
    try:
        _shape(response, "Response")
        if response["error"] is not None:
            _shape(response["error"], "Error")
    except evidence.MeasurementError as error:
        raise CollectionError("invalid_response", str(error)) from error
    try:
        if response["error"] is not None:
            require(not response["evidence"] and not response["artifacts"],
                    "invalid_response", "error response must not include evidence/artifacts")
            # Diagnostics may remain on disk after failure, but are never consumed.
            raise CollectionError(response["error"]["code"], response["error"]["message"])
        require(bool(response["evidence"]), "invalid_response", "empty collector evidence")
        subjects, ids = set(), set()
        for record in response["evidence"]:
            evidence._shape(record)
            require(record["context"] == request["context"], "stale_context",
                    "stale commit/base/target/run evidence")
            require(record["project"] == request["project"] and
                    record["component"] == request["component"] and
                    record["collector"] == request["collector"],
                    "invalid_evidence", "collector/project/component mismatch")
            key = (record["subject"]["id"], record["series"]["id"])
            require(key not in subjects, "duplicate_subject", "duplicate subject/series evidence")
            require(record["id"] not in ids, "invalid_evidence", "duplicate evidence ID")
            subjects.add(key)
            ids.add(record["id"])
            require(set(request["requested_capabilities"]) <=
                    {c["metric"] for c in record["capabilities"]},
                    "missing_capability", "requested capability omitted")
        _artifacts(response, output)
        return evidence.validate_evidence(response["evidence"], project=project,
                                          source_root=workspace, artifact_root=output,
                                          expected=request["context"])
    except evidence.MeasurementError as error:
        raise CollectionError("invalid_evidence", str(error)) from error
    except (OSError, RuntimeError) as error:
        raise CollectionError("invalid_artifact", str(error)) from error


def run_collector(adapter, request, *, project):
    """Return validated harness-evidence/v1 records or raise CollectionError.

    Policy consumers see the same evidence for either transport. Keep caller-owned
    provenance isolated from mutable internal adapters; never evaluate thresholds.
    """
    request, project = copy.deepcopy(request), copy.deepcopy(project)
    workspace, output = _request(request, project)
    response = copy.deepcopy(adapter.invoke(copy.deepcopy(request)))
    return _response(response, request, project, workspace, output)
