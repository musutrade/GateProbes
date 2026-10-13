#!/usr/bin/env python3
"""Replay retained bytes through the non-authoritative Rust comparator; no collection."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

import replay


def prepare(work):
    manifest, blobs = replay.load_corpus()
    cases = []
    for item in manifest['cases']:
        case = json.loads(replay.payload(replay.ROOT / item['input']))
        if case['schema'] != 'generic-core-case/v1':
            raise ValueError('unknown case schema: ' + item['id'])
        expected = json.loads(replay.payload(replay.ROOT / item['expected']))
        actual = replay.evaluate(case, blobs, work / 'oracle' / item['id'])
        if not replay.oracle_matches(expected, actual):
            raise ValueError('frozen Python oracle mismatch: ' + item['id'])
        # Roots are explicit trusted transport context, not record-owned paths.
        for side in ('head', 'base'):
            if side in case:
                value = case[side]
                context = replay.materialize(value, blobs, work / 'rust' / item['id'] / side)
                case[side] = dict(records=value['records'], **{
                    key: str(value) if isinstance(value, Path) else value
                    for key, value in context.items()})
        case.update(id=item['id'], expected_output=expected)
        cases.append(case)
    return dict(schema='generic-core-differential-input/v1', cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rust-replay', type=Path, help='built differential_replay example')
    parser.add_argument('--prepare', type=Path, help='retain explicit input and roots for Rust tests')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if bool(args.prepare) == bool(args.rust_replay):
        parser.error('specify exactly one of --prepare and --rust-replay')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.prepare:
        args.output.write_bytes(replay.canonical(prepare(args.prepare.resolve())))
        return 0
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        input_path = work / 'input.json'
        input_path.write_bytes(replay.canonical(prepare(work)))
        completed = subprocess.run([str(args.rust_replay.resolve()), str(input_path), str(args.output)])
        if completed.returncode not in (0, 1):
            return completed.returncode
        result = json.loads(args.output.read_bytes())
        # Only replay-owned roots in human diagnostics become portable.
        result = replay.portable_errors(result, work)
        args.output.write_bytes(replay.canonical(result))
        print(f"{result['case_count']} retained Rust/Angular/contract cases; "
              f"{result['mismatch_count']} unexplained field mismatches; non-authoritative")
        return completed.returncode


if __name__ == '__main__':
    raise SystemExit(main())
