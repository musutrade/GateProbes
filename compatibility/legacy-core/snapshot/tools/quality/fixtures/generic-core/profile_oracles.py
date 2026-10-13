#!/usr/bin/env python3
"""Profile real retained oracles in fresh processes; never reuse their results."""
import argparse
import cProfile
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import pstats
import runpy
import subprocess
import sys
import time

# This driver is repository-only diagnostic tooling, not a required gate or cache.
ROOT = Path(__file__).resolve().parents[4]
WORKLOADS = {
    'policy': 'tools/harness-gate/quality-core/tests/policy_reference.py',
    'evidence': 'tools/harness-gate/quality-core/tests/reference.py',
    'replay': 'tools/quality/fixtures/generic-core/replay.py',
    'differential': 'tools/quality/fixtures/generic-core/differential.py',
}


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def worker(name, output, profiled):
    script = ROOT / WORKLOADS[name]
    work = output / 'work'
    work.mkdir()
    if name in ('policy', 'evidence'):
        args = [str(ROOT / 'tools/quality'), str(work)]
    elif name == 'replay':
        args = ['--output', str(work / 'result.json')]
    else:
        args = ['--prepare', str(work), '--output', str(output / 'cases.json')]
    sys.argv = [str(script), *args]
    sys.path.insert(0, str(script.parent))
    profiler = cProfile.Profile() if profiled else None
    wall, cpu, children = time.perf_counter(), time.process_time(), os.times()
    if profiler:
        profiler.enable()
    try:
        runpy.run_path(str(script), run_name='__main__')
    except SystemExit as error:
        if error.code not in (None, 0):
            raise
    finally:
        if profiler:
            profiler.disable()
            profiler.dump_stats(str(output / 'profile.pstats'))
    final = os.times()
    record = dict(wall_seconds=time.perf_counter() - wall,
                  cpu_seconds=time.process_time() - cpu,
                  child_cpu_seconds=(final.children_user + final.children_system
                                     - children.children_user - children.children_system)
                  if os.name == 'posix' else None,
                  profiled=profiled)
    if profiler:
        stats = pstats.Stats(profiler)
        functions = []
        for (filename, line, function), (primitive, calls, own, cumulative, _) in stats.stats.items():
            try:
                filename = str(Path(filename).relative_to(ROOT))
            except ValueError:
                pass
            functions.append(dict(file=filename, line=line, function=function,
                                  calls=calls, primitive_calls=primitive,
                                  self_seconds=own, cumulative_seconds=cumulative))
        record['functions'] = sorted(functions, key=lambda row: row['cumulative_seconds'], reverse=True)
    write(output / 'timing.json', record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--workloads', nargs='+', choices=WORKLOADS, default=list(WORKLOADS))
    parser.add_argument('--worker', choices=WORKLOADS, help=argparse.SUPPRESS)
    parser.add_argument('--profiled', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    output = args.output.resolve()
    if args.worker:
        worker(args.worker, output, args.profiled)
        return
    if args.samples < 1:
        parser.error('--samples must be positive')
    output.mkdir(parents=True, exist_ok=False)
    summary = dict(schema='oracle-profile/v1', authoritative=False, status='running',
                   created_at=datetime.now(timezone.utc).isoformat(),
                   sha=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                   dirty=subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True),
                   python=sys.version, platform=platform.platform(),
                   sources={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                            for name in sorted(set(WORKLOADS.values()) | {
                                'tools/quality/fixtures/generic-core/authority.py',
                                'tools/quality/fixtures/generic-core/manifest.json'})},
                   environment={name: os.environ.get(name) for name in
                                ('RUNNER_OS', 'RUNNER_ARCH', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')},
                   # This is a startup probe, not subtracted from workload results.
                   interpreter_startup_seconds=[], workloads={})
    write(output / 'summary.json', summary)
    for _ in range(args.samples):
        start = time.perf_counter()
        subprocess.run([sys.executable, '-c', 'pass'], check=True)
        summary['interpreter_startup_seconds'].append(time.perf_counter() - start)
    for name in args.workloads:
        summary['workloads'][name] = []
        for sample in range(args.samples + 1):
            destination = output / name / ('profiled' if sample == 0 else f'run-{sample}')
            destination.mkdir(parents=True)
            command = [sys.executable, str(Path(__file__).resolve()), '--output', str(destination), '--worker', name]
            if sample == 0:
                command.append('--profiled')
            start = time.perf_counter()
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            (destination / 'stdout.txt').write_text(result.stdout, encoding='utf-8')
            (destination / 'stderr.txt').write_text(result.stderr, encoding='utf-8')
            if result.returncode:
                summary.update(status='failed', failure=dict(workload=name, sample=sample,
                               returncode=result.returncode,
                               evidence=str(destination.relative_to(output))))
                write(output / 'summary.json', summary)
            result.check_returncode()
            record = json.loads((destination / 'timing.json').read_text())
            record.update(process_wall_seconds=time.perf_counter() - start,
                          evidence=str(destination.relative_to(output)))
            summary['workloads'][name].append(record)
            write(output / 'summary.json', summary)
            print(f'{name} {sample}: {record["process_wall_seconds"]:.3f}s (profiled={sample == 0})', flush=True)
    summary['status'] = 'completed'
    write(output / 'summary.json', summary)


if __name__ == '__main__':
    main()
