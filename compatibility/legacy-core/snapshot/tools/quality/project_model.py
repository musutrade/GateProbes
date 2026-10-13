#!/usr/bin/env python3
"""Frozen non-authoritative Python reference; see docs/quality/python-retention.md.

Generic decisions belong to the released Rust core. No release-approval path.

Shadow project/subject contracts; no collector or release-policy authority."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import unicodedata

from quality_evidence import _schema_matches

SCHEMA_DIR = Path(__file__).resolve().parent / "schema"
IDENTITY_VERSION = "subject-identity/v1"
IDENTITY_FIELDS = ("component", "target", "boundary", "kind", "path",
                   "discriminator", "span", "source_sha256")


class ModelError(ValueError):
    """Invalid or ambiguous project identity; callers must fail closed."""


def require(condition, message):
    if not condition:
        raise ModelError(message)


def validate_shape(value, filename, definition=None):
    schema = json.loads((SCHEMA_DIR / filename).read_text())
    shape = schema if definition is None else schema["definitions"][definition]
    errors = _schema_matches(value, shape, schema, "$")
    require(not errors, "; ".join(errors))
    _validate_metadata(value)


def _validate_metadata(value):
    # The existing stdlib schema walker supports additionalProperties=false,
    # but not schema-valued additionalProperties. Enforce metadata values here.
    if isinstance(value, str):
        require(not any(ord(c) < 32 for c in value), "control character in model string")
    elif isinstance(value, dict):
        for key, child in value.items():
            if key == "metadata":
                require(isinstance(child, dict) and
                        all(isinstance(v, str) and v for v in child.values()),
                        "metadata values must be nonempty strings")
                for item in child.values():
                    _validate_metadata(item)
            else:
                _validate_metadata(child)
    elif isinstance(value, list):
        for child in value:
            _validate_metadata(child)


def canonical_path(path):
    require(path == unicodedata.normalize("NFC", path), "path must use NFC Unicode")
    require(not any(ord(c) < 32 or c in "\\:" for c in path), "invalid source path")
    require(not PurePosixPath(path).is_absolute() and
            path == str(PurePosixPath(path)) and
            ".." not in PurePosixPath(path).parts, "path must be canonical and relative")
    return PurePosixPath(path)


def subject_id(project_id, subject):
    """Digest canonical UTF-8 JSON; metadata and supplied ID are not identity."""
    validate_shape(subject, "project-model.schema.json", "Subject")
    canonical_path(subject["path"])
    require(subject["discriminator"].strip() == subject["discriminator"] and
            subject["discriminator"] == unicodedata.normalize("NFC", subject["discriminator"]),
            "discriminator must be canonical")
    if "span" in subject:
        span = subject["span"]
        require((span["start_line"], span["start_column"]) <=
                (span["end_line"], span["end_column"]), "reversed source span")
    payload = {"identity_version": IDENTITY_VERSION, "project": project_id,
               **{key: subject[key] for key in IDENTITY_FIELDS if key in subject}}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False).encode("utf-8")).hexdigest()
    return f"{IDENTITY_VERSION}:{digest}"


def unique_index(records, label):
    result = {}
    for record in records:
        require(record["id"] not in result, f"duplicate {label} identity: {record['id']}")
        result[record["id"]] = record
    return result


def validate_project(project):
    """Validate schema, graph references, source ownership and canonical IDs."""
    validate_shape(project, "project-model.schema.json")
    components = unique_index(project["components"], "component")
    roots, targets, boundaries = set(), {}, {}
    for component in components.values():
        root = canonical_path(component["path"])
        require(root not in roots, "duplicate component path")
        roots.add(root)
        targets[component["id"]] = unique_index(component["targets"], "target")
        local = unique_index(component["source_boundaries"], "boundary")
        boundaries[component["id"]] = local
        for boundary in local.values():
            path = canonical_path(boundary["path"])
            require(path.is_relative_to(root), "boundary escapes component")
        for target in component["targets"]:
            refs = target["boundaries"]
            require(len(refs) == len(set(refs)), "duplicate target boundary")
            require(set(refs) <= local.keys(), "unknown target boundary")
    subjects = unique_index(project["subjects"], "subject")
    locations, sources = set(), {}
    for subject in subjects.values():
        component = subject["component"]
        require(component in components, "unknown subject component")
        require(subject["target"] in targets[component], "unknown subject target")
        require(subject["boundary"] in targets[component][subject["target"]]["boundaries"],
                "unknown subject boundary for target")
        path = canonical_path(subject["path"])
        boundary = boundaries[component][subject["boundary"]]
        require(path.is_relative_to(canonical_path(boundary["path"])),
                "subject escapes source boundary")
        require(subject["id"] == subject_id(project["id"], subject), "noncanonical subject identity")
        # One physical location cannot silently have conflicting source bytes/owners.
        source = (component, subject["source_sha256"])
        require(sources.get(subject["path"], source) == source, "conflicting source path or digest")
        sources[subject["path"]] = source
        locator = tuple(json.dumps(subject.get(key), sort_keys=True) for key in
                        ("component", "target", "boundary", "kind", "path", "discriminator", "span"))
        require(locator not in locations, "duplicate subject location")
        locations.add(locator)
    relationships = unique_index(project["relationships"], "relationship")
    edges = set()
    for relationship in relationships.values():
        producer, consumer = relationship["producer"], relationship["consumer"]
        require(producer in components and consumer in components, "unknown relationship component")
        require(producer != consumer, "relationship must cross components")
        refs = relationship["subjects"]
        require(len(refs) == len(set(refs)), "duplicate relationship subject")
        require(set(refs) <= subjects.keys(), "unknown relationship subject identity")
        require(all(subjects[ref]["component"] in (producer, consumer) for ref in refs),
                "relationship subject belongs to an unrelated component")
        edge = (relationship["kind"], producer, consumer, tuple(sorted(refs)))
        require(edge not in edges, "duplicate relationship edge")
        edges.add(edge)
    return project


def validate_mappings(base, head, mappings):
    """Resolve explicit one-to-one modify/rename/move or one-to-many split lineage.

    The returned head->base identity index conveys lineage only. Metric series,
    baseline acceptance and debt/ratchet policy remain separate contracts.
    """
    validate_project(base)
    validate_project(head)
    validate_shape(mappings, "subject-mappings.schema.json")
    require(base["id"] == head["id"] == mappings["project"], "mapping project mismatch")
    old = unique_index(base["subjects"], "base subject")
    new = unique_index(head["subjects"], "head subject")
    resolved, used = {}, set()
    for mapping in mappings["mappings"]:
        source, destinations = mapping["from"], mapping["to"]
        require(source in old, "unknown mapping base identity")
        require(source not in used, "ambiguous mapping source")
        require(source not in new, "mapping source still exists at head")
        used.add(source)
        kind = mapping["kind"]
        require(len(destinations) >= 2 if kind == "split" else len(destinations) == 1,
                "invalid mapping cardinality")
        for destination in destinations:
            require(destination in new, "unknown mapping head identity")
            require(destination not in resolved and destination not in old,
                    "ambiguous mapping destination")
            before, after = old[source], new[destination]
            require(before["kind"] == after["kind"], "mapping changes subject kind")
            require(before["target"] == after["target"], "mapping changes target")
            if kind == "modify":
                require(all(before[key] == after[key] for key in
                            ("component", "target", "boundary", "kind", "path", "discriminator")),
                        "modification changes subject locator")
            if kind == "rename":
                require((before["component"], before["path"]) ==
                        (after["component"], after["path"]) and
                        before["discriminator"] != after["discriminator"], "invalid rename")
            if kind == "move":
                require((before["component"], before["path"]) !=
                        (after["component"], after["path"]) and
                        before["discriminator"] == after["discriminator"], "invalid move")
            resolved[destination] = source
    return resolved


def baseline_identity(base, head, mappings, identity):
    """Reject implicit favorable inheritance for any changed/new identity."""
    resolved = validate_mappings(base, head, mappings)
    require(identity in {s["id"] for s in head["subjects"]}, "unknown head subject identity")
    if identity in {s["id"] for s in base["subjects"]}:
        return identity
    require(identity in resolved, "explicit identity mapping required for baseline inheritance")
    return resolved[identity]


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_project(path):
    return validate_project(json.loads(Path(path).read_text(), object_pairs_hook=_unique_object))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path)
    args = parser.parse_args()
    try:
        project = load_project(args.project)
    except (ValueError, OSError) as error:
        print(f"project model error: {error}", file=sys.stderr)
        return 1
    print(f"valid {project['schema']}: {len(project['components'])} components, "
          f"{len(project['subjects'])} subjects, {len(project['relationships'])} relationships")
    return 0


if __name__ == "__main__":
    sys.exit(main())
