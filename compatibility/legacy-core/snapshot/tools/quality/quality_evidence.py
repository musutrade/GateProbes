#!/usr/bin/env python3
"""Frozen non-authoritative Python reference; see docs/quality/python-retention.md.

Generic decisions belong to the released Rust core. No release-approval path.
Legacy complexity-evidence validation remains required Python measurement tooling.

Validate versioned quality evidence records (stdlib only).

The canonical machine-readable shape lives in
``tools/quality/schema/quality-evidence.schema.json``.  This module loads that
schema and applies the subset of JSON Schema that the schema uses, then
enforces the cross-field rules that JSON Schema cannot express alone:
canonical series keys, canonical source-symbol identities, digest/byte
agreement, recomputed cyclomatic complexity, raw-count constraints, and
incompatible-series detection.

The module intentionally does not import ``jsonschema``: the quality script
CI job only installs the Python standard library, so validation must be
reproducible in that environment.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


SCHEMA_DIR = Path(__file__).resolve().parent / "schema"
SCHEMA_PATH = SCHEMA_DIR / "quality-evidence.schema.json"

SCHEMA_VERSION = "1"
KIND = "complexity-evidence"

RAW_KEYS = (
    "if",
    "guards",
    "match",
    "match_arms",
    "while",
    "for",
    "loop",
    "and_and",
    "or_or",
    "question_mark",
    "closures",
    "macro_invocations_skipped",
    "nested_functions",
)

SERIES_SEPARATOR = "|"
SERIES_KEY_FIELDS = (
    "kind",
    "analyzer",
    "rule",
    "toolchain.target",
    "toolchain.python",
    "source.path",
    "source.sha256",
    "source.bytes",
)
SOURCE_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
QUALIFIED_NAME_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$"
)


class EvidenceError(ValueError):
    """A quality evidence record violates the frozen contract."""


def load_schema() -> dict[str, Any]:
    try:
        schema = json.loads(SCHEMA_PATH.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot load schema {SCHEMA_PATH}: {exc}") from exc
    if schema.get("type") != "object":
        raise EvidenceError("quality evidence schema root must describe an object")
    return schema


def _definition(schema: dict[str, Any], ref: str) -> dict[str, Any]:
    if not ref.startswith("#/definitions/"):
        raise EvidenceError(f"unsupported schema reference: {ref}")
    value: Any = schema
    for part in ref[2:].split("/"):
        value = value[part]
    if not isinstance(value, dict):
        raise EvidenceError(f"schema reference does not resolve to an object: {ref}")
    return value


def _schema_matches(value: Any, schema: dict[str, Any], root: dict[str, Any], where: str) -> list[str]:
    """Validate ``value`` against a small, deterministic draft-07 subset.

    Only the keywords used by the quality evidence schema are implemented:
    type, const, enum, pattern, minLength/maxLength, minimum, required,
    properties, additionalProperties, items, minItems/maxItems, and
    ``#/definitions/...`` references.  Types are checked strictly so that a
    JSON boolean can never satisfy an integer or number constraint.
    """
    errors: list[str] = []

    def add(message: str) -> None:
        errors.append(f"{where}: {message}")

    if "$ref" in schema:
        errors.extend(
            _schema_matches(value, _definition(root, schema["$ref"]), root, where)
        )
        return errors
    if "type" in schema:
        expected = schema["type"]
        if isinstance(expected, str):
            expected = [expected]
        kind = None
        if isinstance(value, bool):
            kind = "boolean"
        elif type(value) is int:
            kind = "integer"
        elif isinstance(value, float):
            kind = "number"
        elif isinstance(value, str):
            kind = "string"
        elif isinstance(value, list):
            kind = "array"
        elif isinstance(value, dict):
            kind = "object"
        if kind not in expected:
            add(f"expected type {expected}, got {kind or type(value).__name__}")
            return errors
        if "integer" in expected and "number" not in expected:
            pass  # strict int kind was already required above.
    if "const" in schema and value != schema["const"]:
        add(f"expected const {schema['const']!r}, got {value!r}")
    if "enum" in schema and value not in schema["enum"]:
        add(f"expected one of {schema['enum']!r}, got {value!r}")
    if "pattern" in schema and isinstance(value, str):
        if re.search(schema["pattern"], value) is None:
            add(f"value {value!r} does not match pattern {schema['pattern']!r}")
    if "minLength" in schema and isinstance(value, str) and len(value) < schema["minLength"]:
        add(f"string is shorter than {schema['minLength']}")
    if "maxLength" in schema and isinstance(value, str) and len(value) > schema["maxLength"]:
        add(f"string is longer than {schema['maxLength']}")
    if "minimum" in schema and (not isinstance(value, int) or isinstance(value, bool)):
        add(f"expected integer at or above {schema['minimum']}")
    elif "minimum" in schema and value < schema["minimum"]:
        add(f"integer {value} is below minimum {schema['minimum']}")
    if "required" in schema and isinstance(value, dict):
        missing = [key for key in schema["required"] if key not in value]
        if missing:
            add(f"missing required field(s): {', '.join(missing)}")
    if isinstance(value, dict):
        if "properties" in schema:
            for key, child in schema["properties"].items():
                if key in value:
                    errors.extend(
                        _schema_matches(value[key], child, root, f"{where}.{key}")
                    )
        if schema.get("additionalProperties") is False:
            known = set(schema.get("properties", {}))
            unknown = sorted(set(value) - known)
            if unknown:
                add(f"unknown field(s): {', '.join(unknown)}")
    if isinstance(value, list):
        if "items" in schema:
            item_schema = schema["items"]
            for index, item in enumerate(value):
                errors.extend(_schema_matches(item, item_schema, root, f"{where}[{index}]"))
        if "minItems" in schema and len(value) < schema["minItems"]:
            add(f"expected at least {schema['minItems']} item(s)")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            add(f"expected at most {schema['maxItems']} item(s)")
    return errors


def validate_schema(record: Any) -> list[str]:
    """Return schema violations for ``record``, using the committed schema."""
    if not isinstance(record, dict):
        return ["evidence must be a JSON object"]
    schema = load_schema()
    return _schema_matches(record, schema, schema, "$")


def _clean_component(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise EvidenceError(f"{where} must be a string")
    if SERIES_SEPARATOR in value or "\n" in value or "\r" in value:
        raise EvidenceError(f"{where} must not contain '|' or newlines")
    if not value:
        raise EvidenceError(f"{where} must not be empty")
    return value


def series_key(record: dict[str, Any]) -> str:
    """Return the canonical key that distinguishes incompatible series."""
    series = record.get("series")
    if not isinstance(series, dict):
        raise EvidenceError("series must be an object")
    components = [
        _clean_component(record.get("kind"), "kind"),
        _clean_component(series["analyzer"].get("name"), "series.analyzer.name"),
        _clean_component(series["analyzer"].get("version"), "series.analyzer.version"),
        _clean_component(series["rule"].get("name"), "series.rule.name"),
        _clean_component(series["rule"].get("version"), "series.rule.version"),
        _clean_component(series["toolchain"].get("target"), "series.toolchain.target"),
        _clean_component(series["toolchain"].get("python"), "series.toolchain.python"),
        _clean_component(series["source"].get("path"), "series.source.path"),
        _clean_component(series["source"].get("sha256"), "series.source.sha256"),
        str(series["source"]["bytes"]),
    ]
    return SERIES_SEPARATOR.join(components)


def symbol_id(symbol: dict[str, Any], source_path: str, source_sha256: str) -> str:
    """Return the canonical source-symbol identity."""
    start = symbol["span"]
    digest = source_sha256[:12]
    return (
        f"{source_path}::{symbol['kind']}::{symbol['qualified_name']}"
        f"@{start['start_line']}:{start['start_column']}:{digest}"
    )


def _is_posix_relative(path: str) -> bool:
    if not path or path.startswith(("/", "\\")) or "\\" in path:
        return False
    if path in (".", ".."):
        return False
    if any(part in ("", ".", "..") for part in path.split("/")):
        return False
    return not path.startswith(".")


def recompute_cyclomatic_complexity(raw: dict[str, int]) -> int:
    arms = int(raw["match_arms"])
    matches = int(raw["match"])
    return (
        1
        + int(raw["if"])
        + int(raw["guards"])
        + int(raw["while"])
        + int(raw["for"])
        + int(raw["loop"])
        + max(0, arms - matches)
        + int(raw["and_and"])
        + int(raw["or_or"])
        + int(raw["question_mark"])
    )


def _span_valid(span: dict[str, Any]) -> bool:
    start_line, start_column = span["start_line"], span["start_column"]
    end_line, end_column = span["end_line"], span["end_column"]
    if (start_line, start_column) > (end_line, end_column):
        return False
    return True


def _symbol_errors(record: dict[str, Any], symbol: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    series_source = record["series"]["source"]
    source = symbol.get("source", {})
    if not isinstance(source, dict):
        return ["symbol.source must be an object"]
    if source.get("path") != series_source.get("path"):
        errors.append("symbol.source.path does not match series.source.path")
    if source.get("sha256") != series_source.get("sha256"):
        errors.append("symbol.source.sha256 does not match series.source.sha256")
    if not _span_valid(symbol.get("span", {})):
        errors.append("symbol.span ends before it starts")
    canonical = symbol_id(symbol, series_source.get("path", ""), series_source.get("sha256", ""))
    if symbol.get("id") != canonical:
        errors.append(f"symbol.id is not canonical: expected {canonical!r}")
    qualified = symbol.get("qualified_name", "")
    if QUALIFIED_NAME_PATTERN.fullmatch(qualified) is None:
        errors.append(f"symbol.qualified_name is not a supported Rust path: {qualified!r}")
    raw = symbol.get("raw", {})
    raw_errors: list[str] = []
    for key in RAW_KEYS:
        if key not in raw:
            raw_errors.append(f"raw.{key} is missing")
        elif type(raw[key]) is not int:
            raw_errors.append(f"raw.{key} must be an integer, got {type(raw[key]).__name__}")
        elif raw[key] < 0:
            raw_errors.append(f"raw.{key} must not be negative")
    if raw_errors:
        errors.extend(raw_errors)
        return errors
    if raw["match"] == 0 and raw["match_arms"] != 0:
        errors.append("match_arms must be zero when match is zero")
    if raw["match_arms"] < raw["match"]:
        errors.append("match_arms must be at least match")
    if raw["guards"] > raw["match_arms"]:
        errors.append("guards must not exceed match_arms")
    metrics = symbol.get("metrics", {})
    if type(metrics.get("cyclomatic_complexity")) is not int:
        errors.append("metrics.cyclomatic_complexity must be an integer")
    else:
        expected = recompute_cyclomatic_complexity(raw)
        if metrics["cyclomatic_complexity"] != expected:
            errors.append(
                "metrics.cyclomatic_complexity "
                f"({metrics['cyclomatic_complexity']}) does not recompute from raw "
                f"counts ({expected})"
            )
    return errors


def validate_evidence(
    record: Any,
    *,
    expected_source_sha256: str | None = None,
    expected_source_bytes: int | None = None,
    expected_commit: str | None = None,
) -> None:
    """Fail closed unless ``record`` satisfies the frozen evidence contract.

    Optional expected source digest/byte counts let a caller prove that the
    record describes a specific immutable source file; when absent, only the
    self-consistency checks apply.
    """
    if not isinstance(record, dict):
        raise EvidenceError("evidence must be a JSON object")
    schema_errors = validate_schema(record)
    if schema_errors:
        raise EvidenceError("; ".join(schema_errors))
    if record["schema_version"] != SCHEMA_VERSION:
        raise EvidenceError(f"unsupported schema_version {record['schema_version']!r}")
    if record["kind"] != KIND:
        raise EvidenceError(f"unsupported kind {record['kind']!r}")
    series = record["series"]
    source = series["source"]
    if not _is_posix_relative(source["path"]):
        raise EvidenceError(
            f"series.source.path must be a relative POSIX path without '..': {source['path']!r}"
        )
    if SOURCE_SHA256_PATTERN.fullmatch(source["sha256"]) is None:
        raise EvidenceError("series.source.sha256 must be 64 lowercase hexadecimal digits")
    if type(source["bytes"]) is not int or source["bytes"] <= 0:
        raise EvidenceError("series.source.bytes must be a positive integer")
    if source.get("language") != "rust":
        raise EvidenceError("series.source.language must be 'rust'")
    if expected_source_sha256 is not None and source["sha256"] != expected_source_sha256:
        raise EvidenceError(
            "source digest does not match expected_source_sha256 "
            f"({source['sha256']} != {expected_source_sha256})"
        )
    if expected_source_bytes is not None and source["bytes"] != expected_source_bytes:
        raise EvidenceError(
            "source byte count does not match expected_source_bytes "
            f"({source['bytes']} != {expected_source_bytes})"
        )
    if expected_commit is not None and record.get("commit") != expected_commit:
        raise EvidenceError(
            f"commit does not match expected_commit ({record.get('commit')} != {expected_commit})"
        )
    series_key(record)
    symbols = record.get("symbols", [])
    ids: set[str] = set()
    for symbol in symbols:
        errors = _symbol_errors(record, symbol)
        if errors:
            raise EvidenceError("; ".join(errors))
        if symbol["id"] in ids:
            raise EvidenceError(f"duplicate symbol id {symbol['id']!r}")
        ids.add(symbol["id"])


def assert_compatible_series(records: Iterable[dict[str, Any]]) -> str:
    """Return the shared canonical series key, rejecting incompatible series."""
    key = None
    for record in records:
        current = series_key(record)
        if key is None:
            key = current
        elif current != key:
            raise EvidenceError(
                "incompatible series: records must not be compared "
                f"(expected {key!r}, found {current!r})"
            )
    if key is None:
        raise EvidenceError("at least one record is required")
    return key


def _record_from_file(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{path}: cannot parse evidence JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{path}: evidence must be a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate quality evidence records.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate", help="validate one evidence record")
    validate.add_argument("--record", type=Path, required=True)
    validate.add_argument("--expected-source-sha256", default=None)
    validate.add_argument("--expected-source-bytes", type=int, default=None)
    validate.add_argument("--expected-commit", default=None)
    compare = subparsers.add_parser("compare-series", help="require a shared canonical series")
    compare.add_argument("--record", type=Path, action="append", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            record = _record_from_file(args.record)
            validate_evidence(
                record,
                expected_source_sha256=args.expected_source_sha256,
                expected_source_bytes=args.expected_source_bytes,
                expected_commit=args.expected_commit,
            )
            print(f"valid: {args.record}")
            print(f"series: {series_key(record)}")
            return 0
        if args.command == "compare-series":
            records = [_record_from_file(path) for path in args.record]
            key = assert_compatible_series(records)
            print(f"compatible series: {key}")
            return 0
        parser.error(f"unknown command {args.command!r}")
    except EvidenceError as exc:
        print(f"quality evidence failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
