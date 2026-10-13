#!/usr/bin/env python3
"""Frozen non-authoritative Python reference; see docs/quality/python-retention.md.

Generic decisions belong to the released Rust core. No release-approval path.

Standalone normalized evidence contracts; no release decision or collector."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

import project_model as model
from quality_evidence import _schema_matches

SCHEMA_DIR = Path(__file__).resolve().parent / "schema"
VALUE_TYPES = {name: name.title() for name in
               ("ratio", "count", "boolean", "duration", "size", "decimal", "rational")}
# Shared names describe policy inputs, never cross-tool measurement equivalence.
METRIC_TYPES = {
    **{f"coverage.{key}": "ratio" for key in ("line", "function", "region", "branch")},
    **{key: "count" for key in ("complexity.cyclomatic", "complexity.cognitive",
       "mutation.killed", "mutation.survived", "security.findings",
       "contract.breaking_changes", "accessibility.violations")},
    "risk.crap": "decimal", "mutation.score": "ratio",
    "contract.schema_valid": "boolean", "contract.client_drift": "boolean",
    "contract.compatible": "boolean", "performance.regression": "boolean",
    "performance.duration": "duration", "bundle.size": "size",
}


class MeasurementError(ValueError):
    """Invalid evidence cannot satisfy a required capability."""


def metric_type_matches(name, kind):
    return kind == METRIC_TYPES.get(name) or (name == "risk.crap" and kind == "rational")


def require(condition, message):
    if not condition:
        raise MeasurementError(message)


def _json_domain(value):
    # v1 deliberately excludes floats: ratios retain counts, decimals use strings.
    if value is None or type(value) in (bool, int):
        return
    if isinstance(value, str):
        require(not any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value),
                "invalid character in evidence string")
    elif isinstance(value, dict):
        for key, child in value.items():
            require(isinstance(key, str), "JSON keys must be strings")
            _json_domain(key)
            _json_domain(child)
    elif isinstance(value, list):
        for child in value:
            _json_domain(child)
    else:
        raise MeasurementError("untyped number or non-JSON value")


def _canonical(value):
    _json_domain(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _shape(value, filename="harness-evidence.schema.json", definition=None, directory=None):
    _json_domain(value)
    root = SCHEMA_DIR if directory is None else Path(directory)
    schema = json.loads((root / filename).read_text())
    shape = schema if definition is None else schema["definitions"][definition]
    errors = _schema_matches(value, shape, schema, "$")
    require(not errors, "; ".join(errors))


def series_id(series):
    """Hash every semantic field; metric contracts have canonical name order."""
    return "measurement-series/v1:" + hashlib.sha256(
        _canonical({k: v for k, v in series.items() if k != "id"})).hexdigest()


def _index(records, key, label):
    result = {}
    for record in records:
        require(record[key] not in result, f"duplicate {label}: {record[key]}")
        result[record[key]] = record
    return result


def validate_series(series):
    _shape(series, definition="Series")
    contracts = _index(series["metrics"], "name", "series metric")
    require(list(contracts) == sorted(contracts), "series metrics must be sorted by name")
    for name, contract in contracts.items():
        require(name in METRIC_TYPES, f"unknown generic metric: {name}")
        require(metric_type_matches(name, contract["type"]), f"wrong metric type: {name}")
    require(series["id"] == series_id(series), "noncanonical measurement series identity")
    return series


def require_compatible_series(base, head):
    """Compatibility precondition only; does not accept a baseline or ratchet."""
    require(base is not None, "missing base series")
    validate_series(base)
    validate_series(head)
    require(base == head, "incompatible measurement series; explicit migration required")


def _file(root, path, digest, size=None):
    try:
        model.canonical_path(path)
        root = Path(root).resolve(strict=True)
        candidate = (root / path).resolve(strict=True)
        require(candidate.is_relative_to(root), "path escapes declared root")
        require(candidate.is_file(), "artifact/source is not a regular file")
        data = candidate.read_bytes()
        require(hashlib.sha256(data).hexdigest() == digest, "artifact/source digest mismatch")
        require(size is None or len(data) == size, "artifact byte count mismatch")
    except (OSError, RuntimeError, model.ModelError) as error:
        raise MeasurementError(f"artifact/source {path}: {error}") from error


def _record(record, project, source_root, artifact_root, expected):
    _shape(record)
    _shape(expected, definition="Context")
    validate_series(record["series"])
    subject = record["subject"]
    require(record["project"] == project["id"], "project mismatch")
    require(subject in project["subjects"], "unknown or altered subject")
    require(record["component"] == subject["component"], "component mismatch")
    require(record["context"] == expected, "stale commit/base/target/run evidence")
    require(expected["target"] == subject["target"] == record["series"]["target"],
            "target mismatch")
    require(record["collector"] == record["series"]["collector"], "collector version mismatch")
    require(record["source"] == {"path": subject["path"], "sha256": subject["source_sha256"]},
            "source identity mismatch")
    _file(source_root, record["source"]["path"], record["source"]["sha256"])
    artifacts = _index(record["artifacts"], "id", "artifact ID")
    _index(record["artifacts"], "path", "artifact path")
    for artifact in artifacts.values():
        require(artifact["context"] == expected and artifact["source"] == record["source"],
                "stale artifact provenance")
        _file(artifact_root, artifact["path"], artifact["sha256"], artifact["bytes"])
    capabilities = _index(record["capabilities"], "metric", "capability")
    metrics = _index(record["metrics"], "name", "metric")
    contracts = {item["name"] for item in record["series"]["metrics"]}
    require(capabilities.keys() == contracts, "series/capability mismatch")
    require(metrics.keys() <= capabilities.keys(), "metric has no declared capability")
    used = set()
    for name, capability in capabilities.items():
        supported = capability["state"] == "supported"
        require((name in metrics) == supported, "capability/evidence mismatch: " + name)
        linked = capability["artifacts"]
        require(len(linked) == len(set(linked)) and set(linked) <= artifacts.keys(),
                "unknown or duplicate capability artifact")
        used.update(linked)
        if supported:
            metric = metrics[name]
            value = metric["value"]
            require(isinstance(value, dict) and isinstance(value.get("type"), str) and
                    value["type"] in VALUE_TYPES,
                    "unknown metric value type")
            _shape(value, definition=VALUE_TYPES[value["type"]])
            contract = next(c for c in record["series"]["metrics"] if c["name"] == name)
            require(value["type"] == contract["type"], "metric value/series type mismatch")
            if value["type"] == "ratio":
                require(value["covered"] <= value["total"], "covered exceeds total")
            refs = metric["artifacts"]
            require(len(refs) == len(set(refs)) and set(refs) <= set(linked),
                    "metric/capability artifact mismatch")
    require(used == artifacts.keys(), "unlinked raw artifact")
    states = {c["state"] for c in capabilities.values()}
    status = ("measurement_error" if "measurement_error" in states else
              "measured" if "supported" in states else "unavailable")
    require(record["status"] == status, "measurement status/capability mismatch")


def validate_evidence(records, *, project, source_root, artifact_root, expected):
    """Validate a complete batch against caller-owned model, roots and provenance."""
    try:
        model.validate_project(project)
        require(isinstance(records, list) and records, "evidence batch must be nonempty")
        ids, subjects = set(), set()
        for record in records:
            _record(record, project, source_root, artifact_root, expected)
            require(record["id"] not in ids, "duplicate evidence ID")
            ids.add(record["id"])
            key = (record["subject"]["id"], record["series"]["id"])
            require(key not in subjects, "duplicate subject/series evidence")
            subjects.add(key)
    except model.ModelError as error:
        raise MeasurementError(str(error)) from error
    return records


def canonical_serialize(records, **context):
    """Canonical v1 UTF-8 JSON: sorted keys, no whitespace, original array order."""
    return _canonical(validate_evidence(records, **context))


def evaluate_requirements(records, requirements, **context):
    """Return capability availability, never a numerical or release pass decision."""
    validate_evidence(records, **context)
    _shape(requirements, "capability-requirements.schema.json")
    results, seen = [], set()
    components = {c["id"] for c in context["project"]["components"]}
    for requirement in requirements["requirements"]:
        component, metric = requirement["component"], requirement["metric"]
        require(component in components and metric in METRIC_TYPES, "unknown requirement scope")
        require((component, metric) not in seen, "duplicate capability requirement")
        seen.add((component, metric))
        matching = [r for r in records if r["component"] == component]
        for record in matching or [None]:
            capability = next((c for c in record["capabilities"] if c["metric"] == metric),
                              None) if record else None
            state = capability["state"] if capability else "measurement_error"
            status = "available" if state == "supported" else state
            if requirement["mode"] == "required" and state != "supported":
                status = ("measurement_error" if state == "measurement_error" else
                          requirement["on_unavailable"])
            results.append({"component": component, "metric": metric,
                            "evidence_id": record["id"] if record else None,
                            "state": state, "status": status})
    return results


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path):
    def invalid_constant(value):
        raise MeasurementError(f"non-finite JSON number: {value}")
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"),
                          object_pairs_hook=_unique_object, parse_constant=invalid_constant)
    except (OSError, ValueError) as error:
        raise MeasurementError(str(error)) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    for option in ("project", "source-root", "artifact-root", "expected", "output"):
        parser.add_argument("--" + option, required=True, type=Path)
    args = parser.parse_args()
    try:
        canonical = canonical_serialize(load_json(args.evidence), project=load_json(args.project),
                                        source_root=args.source_root, artifact_root=args.artifact_root,
                                        expected=load_json(args.expected))
        result = {"status": "valid", "schema": "harness-evidence/v1",
                  "canonical_sha256": hashlib.sha256(canonical).hexdigest()}
    except (MeasurementError, OSError) as error:
        result = {"status": "measurement_error", "error": str(error)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    return 0 if result["status"] == "valid" else 1


if __name__ == "__main__":
    sys.exit(main())
