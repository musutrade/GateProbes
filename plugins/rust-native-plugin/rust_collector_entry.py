#!/usr/bin/env python3
"""Private runtime measurement entry. No policy/lineage or release decisions."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

# -I -S excludes both ambient modules and the script directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import rust_native_driver as native
import rust_native_classify as classifier
import collector_runner as runner
import rust_collector_project as project
import rust_collector_delivery as delivery
from rust_collector_contract import MeasurementComplete, MeasurementFailure


def measure_capture(directory, anchor):
    """Validate original bytes and re-export before declaring completion.

    Legacy threshold fields remain in retained reports and the developer CLI.
    The product returns the same measurements with those verdicts removed.
    """
    try:
        report = native.certify(directory, anchor)
        report.pop('passed')
        for function in report['functions']:
            function.pop('passed')
        return MeasurementComplete((report,))
    except (ValueError, OSError, KeyError, TypeError) as error:
        return MeasurementFailure('measurement_error', str(error))


def doctor(root):
    inventory = json.loads((root / 'runtime.json').read_text())
    expected = inventory['host']
    observed = {'system': platform.system(), 'machine': platform.machine(),
                'kernel': platform.release(), 'glibc': os.confstr('CS_GNU_LIBC_VERSION')}
    native.require(all(observed[k] == expected[k] for k in observed), 'unsupported host ABI')
    for row in expected['libraries'].values():
        native.require(native.file_hash(row['source']) == row['sha256'], 'host runtime changed')
    for name, row in inventory['payload'].items():
        path = root / name
        native.require(not Path(name).is_absolute() and '..' not in Path(name).parts,
                       'unsafe runtime inventory path')
        native.require(path.is_file() and not path.is_symlink() and native.file_hash(path) == row['sha256'],
                       'missing/modified private runtime: ' + name)
    return {'runtime_complete': True, 'host': observed,
            'delivery_compatibility': 'not_configured',
            'reason': 'No reviewed standalone Core/ABI receipt is shipped in this runtime candidate.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    action = sub.add_parser('doctor')
    action.add_argument('--json', action='store_true')
    for kind in ('certify', 'classify'):
        action = sub.add_parser(kind)
        action.add_argument('--evidence', required=True, type=Path)
        action.add_argument('--anchor', required=True)
    action = sub.add_parser('collect')
    action.add_argument('--binding', type=Path)
    action.add_argument('--binding-sha256')
    args = parser.parse_args()
    try:
        if args.action == 'collect':
            # Read the envelope before runtime validation so operational failures
            # still use the caller's protocol and invocation identity.
            request = json.load(sys.stdin, object_pairs_hook=runner.evidence._unique_object,
                                parse_constant=runner._reject_constant)
        root = Path(__file__).resolve().parents[1]
        status = doctor(root)
        if args.action == 'doctor':
            print(json.dumps(status))
            return 0
        if args.action == 'collect':
            if isinstance(request, dict) and 'protocol_version' in request:
                project.validate_request(request)
                if args.binding is None or args.binding_sha256 is None:
                    raise ValueError('generic collection requires a host-pinned capture binding')
                binding = project.load_binding(request, args.binding, args.binding_sha256)
                delivery.preflight(root, binding)
                directory = Path(binding['capture']['path'])
                delivery.capture_paths(root, directory)
                result = measure_capture(directory, binding['capture']['anchor'])
                if isinstance(result, MeasurementFailure):
                    raise ValueError(result.message)
                print(json.dumps(project.project_report(result.records[0], binding)))
                return 0
            else:
                runner._shape(request, 'Request')
            # Legacy envelopes have no authenticated delivery binding.
            raise ValueError('unknown tested Core/protocol/ABI combination; sampling blocked')
        delivery.capture_paths(root, args.evidence)
        if args.action == 'classify':
            loaded = classifier.load_evidence(args.evidence, args.anchor)
            result = classifier.classify(loaded)
            native.require(result['classification_complete'], 'incomplete classification')
            result.pop('measurement_passed')
            result.pop('baseline_accepted')
            print(json.dumps({'measurement': result, 'error': None}))
            return 0
        result = measure_capture(args.evidence, args.anchor)
        if isinstance(result, MeasurementFailure):
            raise ValueError(result.message)
        print(json.dumps({'measurement': result.records[0], 'error': None}))
        return 0
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError,
            runner.CollectionError) as error:
        print(str(error), file=sys.stderr)
        if args.action == 'collect':
            response = {'schema': 'harness-collector-response/v1', 'evidence': [], 'artifacts': [],
                        'error': {'code': 'adapter_error', 'message': str(error)}}
            if isinstance(locals().get('request'), dict) and 'protocol_version' in request:
                response = {'schema_version': '1', 'status': 'FAIL',
                            'invocation_id': request.get('invocation_id', ''), 'artifacts': [],
                            'collection': {'schema': 'harness-project-collector-response/v1',
                                           'evidence': [], 'error': str(error)}}
        else:
            response = {'measurement': None, 'error': {'code': 'measurement_error', 'message': str(error)}}
        print(json.dumps(response))
        return 1


if __name__ == '__main__':
    sys.exit(main())
