#!/usr/bin/env python3
"""Migration acceptance of the shipped Rust CLI; never a release approval tool."""
import argparse
import json
import os
from pathlib import Path
import subprocess

import differential
import replay


def write(path, value):
    path.write_bytes(replay.canonical(value))
    return str(path.resolve())


def compare(expected, actual, path=''):
    """Retain every differing leaf, applying GH-150's sole wording classification."""
    if replay.same_json(expected, actual):
        return []
    if isinstance(expected, dict) and isinstance(actual, dict):
        diffs = []
        for key in sorted(expected.keys() | actual.keys()):
            child = path + '/' + key.replace('~', '~0').replace('/', '~1')
            if key not in expected or key not in actual:
                diffs.append(dict(path=child, expected_present=key in expected,
                                  actual_present=key in actual, classification='mismatch'))
            else:
                diffs.extend(compare(expected[key], actual[key], child))
        return diffs
    if isinstance(expected, list) and isinstance(actual, list) and len(expected) == len(actual):
        return [diff for i, (left, right) in enumerate(zip(expected, actual))
                for diff in compare(left, right, path + '/' + str(i))]
    diagnostic = replay.oracle_matches(expected, actual, path)
    return [dict(path=path, expected=expected, actual=actual,
                 classification='os-missing-file-wording' if diagnostic else 'mismatch')]


def cli_cases(binary, cases, output):
    results = []
    empty_path = output / 'no-executables'
    empty_path.mkdir(exist_ok=True)
    for case in cases:
        work = output / 'cli' / case['id']
        work.mkdir(parents=True, exist_ok=True)
        report = work / 'report.json'
        # A stale favorable report must be removed on model/transport errors.
        write(report, {'stale': True, 'aggregate': {'state': 'pass'}})
        command = [str(binary), 'quality', 'evaluate', '--output', str(report),
                   '--now', case['now']]
        for name in ('policy', 'selection', 'mappings', 'exceptions'):
            if name in case:
                command += ['--' + name, write(work / (name + '.json'), case[name])]
        for side in ('head', 'base'):
            if side not in case:
                continue
            prefix = '' if side == 'head' else 'base-'
            value = case[side]
            for key, flag in (('project', 'project'), ('records', 'evidence'),
                              ('expected', 'expected')):
                command += ['--' + prefix + flag,
                            write(work / (prefix + flag + '.json'), value[key])]
            for key in ('source_root', 'artifact_root'):
                command += ['--' + prefix + key.replace('_', '-'), value[key]]
        # Collection/materialization above is finished. Runtime cannot find Python,
        # collectors, a shell or any other executable through PATH.
        completed = subprocess.run(command, capture_output=True, text=True,
                                   env={**os.environ, 'PATH': str(empty_path.resolve())},
                                   cwd=empty_path, timeout=30)
        (work / 'stderr.txt').write_text(completed.stderr)
        expected = case['expected_output'].get('project_report')
        actual = json.loads(report.read_bytes()) if report.exists() else None
        write(work / 'expected-report.json', expected)
        # OS missing-file wording is the sole preaccepted diagnostic variation.
        differences = compare(expected, actual)
        write(work / 'differences.json', differences)
        equivalent = not any(diff['classification'] == 'mismatch' for diff in differences)
        wanted = 0 if expected and expected['aggregate']['state'] == 'pass' else 1
        results.append(dict(id=case['id'], exit_code=completed.returncode,
                            expected_exit_code=wanted, equivalent=equivalent,
                            passed=equivalent and completed.returncode == wanted))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--harness-gate', required=True, type=Path)
    parser.add_argument('--rust-replay', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    prepared = differential.prepare(output / 'inputs')
    input_path = write(output / 'python-reference.json', prepared)
    replay_exit = None
    if args.rust_replay:
        replay_exit = subprocess.run([str(args.rust_replay.resolve()), input_path,
                                      str(output / 'rust-differential.json')]).returncode
    results = cli_cases(args.harness_gate.resolve(), prepared['cases'], output)
    summary = dict(schema='generic-core-authority-acceptance/v1',
                   authoritative=False, case_count=len(results),
                   mismatch_count=sum(not result['passed'] for result in results),
                   replay_exit_code=replay_exit, cases=results)
    write(output / 'acceptance.json', summary)
    print(f"{len(results)} shipped CLI cases; {summary['mismatch_count']} mismatches; "
          f"differential exit: {replay_exit}; non-authoritative acceptance evidence")
    return int(summary['mismatch_count'] != 0 or replay_exit not in (None, 0))


if __name__ == '__main__':
    raise SystemExit(main())
