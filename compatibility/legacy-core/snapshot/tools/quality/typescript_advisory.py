#!/usr/bin/env python3
"""Opt-in replay of the bounded frontend window; owns no required CI authority."""
import argparse
import json
from pathlib import Path
import platform
import subprocess
import sys
import tarfile

import harness_evidence as evidence
import typescript_acceptance as acceptance
import typescript_contracts as contracts

REPO = Path(__file__).resolve().parents[2]
CONTRACTS = REPO / 'docs/quality/gh-133'


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def replay_contracts(retained, output):
    index = evidence.load_json(retained / 'index.json')
    results = {}
    for scenario, expected in [('compatible', 'pass'), ('breaking', 'fail')]:
        entry = index['native'][scenario]
        archive = retained / entry['path']
        if contracts.digest(archive) != entry['sha256']:
            raise ValueError(f'{scenario}: native contract archive digest mismatch')
        native = output / scenario
        native.mkdir(parents=True)
        with tarfile.open(archive) as bundle:
            bundle.extractall(native, filter='data')
        project, policy, records, report = contracts.evaluate(
            native, entry['receipt_sha256'], entry['context'])
        write(output / f'{scenario}.json', dict(
            project=project, policy=policy, records=records, report=report))
        if (report['aggregate']['state'] != expected or
                any(report['components'][c]['local']['state'] != 'pass'
                    for c in ('api', 'frontend'))):
            raise ValueError(f'{scenario}: unexpected generic contract decision')
        results[scenario] = dict(expected=expected, actual=report['aggregate']['state'],
                                 archive_sha256=entry['sha256'],
                                 series=[r['series'] for r in records])
    return results


def run(output):
    # Refuse stale output so a failed run cannot publish an earlier pass.
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    summary = dict(schema='typescript-advisory-results/v1', status='error',
                   authority='advisory', certification='bounded; see typescript-certification.md',
                   replay_environment=dict(python=platform.python_version(),
                                           platform=platform.platform()), checks={})
    try:
        summary['checkout'] = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
        window = acceptance.verify_window(acceptance.RETAINED, output / 'coverage')
        summary['checks']['coverage'] = dict(
            exact_counter_comparisons=sum(v['exact_counter_comparisons']
                                          for v in window['counters'].values()),
            unexplained_mismatches=window['unexplained_mismatches'],
            pairs={p: {k: v['report']['aggregate']['state'] for k, v in reports.items()}
                   for p, reports in window['pairs'].items()})
        summary['fixture_revisions'] = evidence.load_json(acceptance.RETAINED / 'window.json')
        summary['coverage_series'] = evidence.load_json(
            output / 'coverage/compatible-head/normalized.json')[0]['series']
        summary['checks']['contracts'] = replay_contracts(CONTRACTS, output / 'contracts')
        for name in ('acceptance', 'contracts'):
            command = [sys.executable, '-m', 'unittest', 'discover', '-s',
                       'tools/quality/tests', '-p', f'test_typescript_{name}.py', '-v']
            with (output / f'{name}-tests.log').open('w') as log:
                result = subprocess.run(command, cwd=REPO, stdout=log, stderr=subprocess.STDOUT)
            summary['checks'][f'{name}_tests'] = dict(command=command, exit_code=result.returncode)
            if result.returncode:
                raise ValueError(f'{name} rejection tests failed; see retained log')
        summary['status'] = 'pass'
    except Exception as error:
        summary['error'] = f'{type(error).__name__}: {error}'
    finally:
        write(output / 'summary.json', summary)
        write(output / 'artifacts.json', contracts.inventory(output, exclude={'artifacts.json'}))
    return 0 if summary['status'] == 'pass' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.output))
