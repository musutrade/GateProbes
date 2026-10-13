"""Delivery contract preflight; no sampling, installation or policy authority.

The caller authenticates the manifest and reviewed compatibility matrix, measures
the actual environment, and retains capture trust separately. This module does
not authenticate either distribution assets or runtime captures.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

import collector_runner as runner
import harness_evidence as evidence


class DeliveryError(ValueError):
    """An incompatible delivery must be rejected before any producer launch."""


def require(condition, message):
    if not condition:
        raise DeliveryError(message)


def fingerprint(value):
    return hashlib.sha256(evidence._canonical(value)).hexdigest()


def validate(value, definition):
    try:
        filename = ('rust-collector-plugin.schema.json'
                    if definition == 'Manifest' and isinstance(value, dict) and
                    value.get('schema') == 'rust-collector-delivery/v2'
                    else 'rust-collector-delivery.schema.json')
        evidence._shape(value, filename, definition)
    except evidence.MeasurementError as error:
        raise DeliveryError(str(error)) from error


def load_manifest(raw):
    """Reject duplicate keys, non-JSON numbers, unknown fields and unsafe paths."""
    try:
        manifest = json.loads(raw, object_pairs_hook=evidence._unique_object,
                              parse_constant=runner._reject_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise DeliveryError(str(error)) from error
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest):
    validate(manifest, 'Manifest')
    payloads = manifest['payloads']
    paths = [p['path'] for p in payloads]
    require(len(paths) == len(set(paths)), 'duplicate payload path')
    for path in paths:
        require(not path.startswith('/') and '\\' not in path and ':' not in path
                and all(p not in ('', '.', '..') for p in path.split('/')),
                'unsafe payload path')
    tools = manifest['tools']
    require(len({t['name'] for t in tools}) == len(tools), 'duplicate tool')
    required = {'driver', 'rustc', 'rustc-driver-library', 'llvm-cov', 'llvm-profdata', 'python'}
    require(required <= {t['name'] for t in tools}, 'missing runtime tool')
    inventory = {p['path']: p['sha256'] for p in payloads}
    for tool in tools:
        require(inventory.get(tool['path']) == tool['sha256'], 'tool absent from payload inventory')
    capabilities = manifest['capabilities']
    require(len({c['metric'] for c in capabilities}) == len(capabilities), 'duplicate capability')


def preflight(manifest, matrix, observed):
    """Match one exact reviewed tuple. An empty matrix authorizes no sampling.

    observed comes from host probes, never copied from the manifest. Matrix
    receipts describe tested combinations, not package SemVer ranges. Verification
    of signatures/receipt bytes belongs to the delivery lifecycle, not this check.
    """
    validate_manifest(manifest)
    validate(matrix, 'Matrix')
    validate(observed, 'Environment')
    require(observed['core'] in manifest['core_compatibility'], 'undeclared Core identity')
    require(manifest['host_abi'] == observed['host_abi'], 'unsupported host ABI')
    expected_tools = {t['name']: (t['sha256'], t['version']) for t in manifest['tools']}
    actual_tools = {t['name']: (t['sha256'], t['version']) for t in observed['tools']}
    require(len(actual_tools) == len(observed['tools']) and actual_tools == expected_tools,
            'wrong/missing runtime tool')
    require(observed['protocol'] == manifest['protocol'], 'incompatible protocol')
    identity = {'manifest_sha256': fingerprint(manifest),
                'environment': observed}
    matches = [row for row in matrix['tested']
               if {k: row[k] for k in identity} == identity]
    require(len(matches) == 1, 'unknown/ambiguous tested Core/protocol/ABI combination')
    return matches[0]['receipt']


def require_same_capture_identity(original, requested):
    """Conservative relocation guard; no anchor rewriting or series migration.

    Include absolute captured tool paths as well as all semantic identities.
    This is stricter than package relocation and does not modify legacy history.
    """
    validate(original, 'CaptureIdentity')
    validate(requested, 'CaptureIdentity')
    require(original == requested, 'relocated/incompatible capture requires reviewed series transition')


@dataclass(frozen=True)
class MeasurementComplete:
    """Validated transport facts, including explicit blocked capability states.

    Completion says nothing about thresholds, requiredness or final outcomes.
    A capability's measurement_error remains a measurement error for Core.
    """

    records: tuple[dict, ...]


@dataclass(frozen=True)
class MeasurementFailure:
    """Operational failure has diagnostics only, never partial usable evidence."""

    code: str
    message: str


MeasurementResult = MeasurementComplete | MeasurementFailure


def measure(adapter, request, *, project) -> MeasurementResult:
    """Development contract adapter; standalone native entry is a later task.

    A legacy subprocess must exit zero AND validate its complete protocol output.
    Never infer measurement validity from a legacy threshold field or exit 1.
    """
    try:
        records = runner.run_collector(adapter, request, project=project)
        return MeasurementComplete(tuple(records))
    except runner.CollectionError as error:
        return MeasurementFailure(error.code, str(error))
