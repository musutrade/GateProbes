#!/usr/bin/env python3
"""Fail-closed, isolated test-to-source critical-path evidence (rule v2)."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
import sys
import tomllib
from pathlib import Path

from production_coverage import CoverageTokenizer, require
from quality_common import CRATE, ROOT, QUALITY_ROOT, git_sha, metadata, sha256, write_json

INVENTORY = Path(__file__).with_suffix('.toml')
POLICY = Path(__file__).with_name('critical_paths_policy.json')
RULE = 'critical-path-source-v2'
PLATFORMS = {'linux', 'macos', 'windows'}


def source_identity(crate: Path) -> dict:
    paths = [p for directory in ('src', 'tests', 'benches', 'examples', '.cargo')
             for p in (crate / directory).rglob('*') if p.is_file()]
    paths += [crate / name for name in ('Cargo.toml', 'Cargo.lock', 'build.rs')
              if (crate / name).is_file()]
    return {str(path.relative_to(crate)): sha256(path) for path in sorted(paths)}


def require_committed_sources(commit: str) -> None:
    inputs = {f'tools/harness-gate/{path}': digest for path, digest in source_identity(CRATE).items()}
    roots = ['src', 'tests', 'benches', 'examples', '.cargo', 'Cargo.toml', 'Cargo.lock', 'build.rs']
    listing = subprocess.run(['git', 'ls-tree', '-r', '--name-only', commit, '--'] +
                             [f'tools/harness-gate/{name}' for name in roots],
                             cwd=ROOT, capture_output=True)
    require(listing.returncode == 0 and set(listing.stdout.decode().splitlines()) == set(inputs),
            'source snapshot differs from commit: added/deleted compilation inputs')
    for path in (INVENTORY, POLICY, Path(__file__), Path(__file__).with_name('critical_paths_collect.py')):
        inputs[str(path.relative_to(ROOT))] = sha256(path)
    for path, digest in inputs.items():
        result = subprocess.run(['git', 'show', f'{commit}:{path}'],
                                cwd=ROOT, capture_output=True)
        require(result.returncode == 0 and hashlib.sha256(result.stdout).hexdigest() == digest,
                f'source snapshot differs from commit: {path}; commit source changes before collecting')


def platform_for(target: str) -> str:
    for fragment, platform in [('linux', 'linux'), ('apple-darwin', 'macos'), ('windows', 'windows')]:
        if fragment in target:
            return platform
    raise ValueError(f'unsupported target: {target}')


def function_binding(crate: Path, path: str, name: str, line: int | None = None) -> dict:
    """Resolve an exact Rust fn token/body, including raw strings and comments."""
    source = (crate / path).read_text()
    tokens = CoverageTokenizer(source).tokenize()
    matches = [i for i, t in enumerate(tokens[:-1]) if t.text == 'fn'
               and tokens[i + 1].text == name and (line is None or t.line == line)]
    require(len(matches) == 1, f'{path}::{name}: missing/ambiguous/moved function')
    start = matches[0]
    end = start
    while tokens[end].text not in ('{', ';'):
        end += 1
    require(tokens[end].text == '{', f'{path}::{name}: no executable body')
    depth = 1
    while depth:
        end += 1
        depth += (tokens[end].text == '{') - (tokens[end].text == '}')
    return {'path': path, 'symbol': name, 'start': tokens[start].line,
            'end': tokens[end].line, 'sha256': sha256(crate / path)}


def binding_text(crate: Path, binding: dict) -> str:
    require(not Path(binding['path']).is_absolute() and '..' not in Path(binding['path']).parts,
            'source path must be crate relative')
    rebuilt = function_binding(crate, binding['path'], binding['symbol'], binding['start'])
    require(rebuilt == binding, f"stale source binding: {binding['path']}::{binding['symbol']}")
    return '\n'.join((crate / binding['path']).read_text().splitlines()[binding['start'] - 1:binding['end']])


def validate_inventory(inventory: dict, policy: dict, crate: Path = CRATE) -> None:
    require(inventory['version'] == 2 and inventory['rule'] == RULE and
            policy['version'] == 2, 'unsupported inventory/policy rule')
    ids = [row['id'] for row in inventory['paths']]
    require(len(ids) == len(set(ids)), 'duplicate path IDs')
    require(set(policy['mandatory']) <= set(ids),
            f"missing mandatory IDs: {sorted(set(policy['mandatory']) - set(ids))}")
    for row in inventory['paths']:
        require(row['rule'] == RULE, f"{row['id']}: stale rule")
        platforms = set(row['platforms'])
        require(bool(platforms) and platforms <= PLATFORMS, f"{row['id']}: invalid platforms")
        require(all(row.get(k) for k in ('platform_note', 'owner', 'review_date', 'observable', 'assertions')),
                f"{row['id']}: missing applicability/observable review")
        if row['id'] in policy['mandatory']:
            require(row['platforms'] == policy['mandatory'][row['id']],
                    f"{row['id']}: mandatory applicability changed")
        binding_text(crate, row['source'])
        test = binding_text(crate, row['test_source'])
        require(row['test'].split('::')[-1] == row['test_source']['symbol'], f"{row['id']}: test symbol mismatch")
        require(all(assertion in test for assertion in row['assertions']),
                f"{row['id']}: degraded observable assertion")
        require(bool(row['probes']), f"{row['id']}: no source probes")
        lines = (crate / row['source']['path']).read_text().splitlines()
        for probe in row['probes']:
            require(row['source']['start'] <= probe['line'] <= row['source']['end'] and
                    lines[probe['line'] - 1].strip() == probe['text'] and
                    1 <= probe['column'] <= len(lines[probe['line'] - 1]),
                    f"{row['id']}: moved source probe")


def passed_test_events(path: Path, binary: str, test: str) -> None:
    events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    suites = [e for e in events if e.get('type') == 'suite' and e.get('event') != 'started']
    terminals = [e for e in events if e.get('type') == 'test' and e.get('event') != 'started']
    require(len(suites) == 1 and suites[0].get('event') == 'ok' and suites[0].get('passed') == 1 and
            suites[0].get('failed') == 0 and suites[0].get('ignored') == 0,
            'isolated suite must pass exactly one test without skips')
    require(len(terminals) == 1 and terminals[0].get('event') == 'ok',
            'test missing, skipped, cancelled, failed, or not isolated')
    event = terminals[0]
    # nextest libtest-json-plus 0.1 names bind the binary and exact Rust test.
    expected = f'harness-gate::{binary}${test}'
    require(event.get('name') == expected, f"wrong test identity: {event.get('name')} != {expected}")


def covered_probes(llvm: dict, row: dict, source_root: Path) -> list[dict]:
    require(llvm['type'] == 'llvm.coverage.json.export' and len(llvm['data']) == 1,
            'expected one LLVM coverage dataset')
    binding = row['source']
    expected = (source_root / binding['path']).resolve()
    hits = []
    for probe in row['probes']:
        candidates = []
        for function in llvm['data'][0]['functions']:
            regions = function['regions']
            if not regions or not any(Path(p).resolve() == expected for p in function['filenames']):
                continue
            local = [r for r in regions if Path(function['filenames'][r[5]]).resolve() == expected]
            # Bind the actual LLVM function envelope to the reviewed source body.
            if not local or min(r[0] for r in local) != binding['start'] or max(r[2] for r in local) != binding['end']:
                continue
            for r in local:
                require(len(r) == 8 and all(type(v) is int and v >= 0 for v in r), 'invalid LLVM region')
                if r[7] == 0 and (r[0], r[1]) <= (probe['line'], probe['column']) < (r[2], r[3]):
                    candidates.append(r)
        require(bool(candidates), f"{row['id']}: missing source region at {probe['line']}")
        # The most specific region decides; an outer function hit cannot cover
        # an unexecuted inner failure branch. Merge monomorphizations by max.
        smallest = [r for r in candidates if not any(
            r[:4] != s[:4] and (r[0], r[1]) <= (s[0], s[1]) and
            (s[2], s[3]) <= (r[2], r[3]) for s in candidates)]
        count = max(r[4] for r in smallest)
        require(count > 0, f"{row['id']}: source probe not executed at {probe['line']}")
        hits.append({'probe': probe, 'regions': smallest, 'count': count})
    return hits


def artifact(base: Path, item: dict) -> Path:
    path = base / item['path']
    require(not Path(item['path']).is_absolute() and '..' not in Path(item['path']).parts,
            'artifact must stay within evidence bundle')
    require(path.resolve().is_relative_to(base.resolve()), 'artifact symlink escapes evidence bundle')
    require(path.is_file() and sha256(path) == item['sha256'], f'missing/modified artifact: {path}')
    return path


def evaluate(inventory: dict, policy: dict, bundle: dict, base: Path, commit: str,
             target: str, crate: Path = CRATE) -> dict:
    validate_inventory(inventory, policy, crate)
    identity = {'commit': commit, 'target': target, 'rule': RULE}
    require(bundle['identity'] == identity, 'mixed/stale bundle commit, target or rule')
    require(bundle['sources'] == source_identity(crate), 'stale/mixed source snapshot')
    require(bundle['inventory_sha256'] == hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest(),
            'stale inventory evidence')
    platform = platform_for(target)
    rows, failures = [], []
    seen_runs = set()
    for row in inventory['paths']:
        result = {**row, 'applicable': platform in row['platforms'], 'traceable': False}
        if not result['applicable']:
            result['status'] = 'not-applicable'
        else:
            try:
                run = bundle['runs'][row['id']]
                require(run['identity'] == identity, 'mixed/stale run commit or target')
                require(run['run_id'] not in seen_runs, 'reused isolated run')
                seen_runs.add(run['run_id'])
                require(run['test'] == row['test'] and run['binary'] == row['binary'], 'wrong run test identity')
                require(all(run[field] == 0 for field in ('clean_exit', 'test_exit', 'coverage_exit')),
                        'clean/test/coverage command failed')
                for kind in ('nextest', 'coverage'):
                    require(run[kind]['identity'] == identity and run[kind]['run_id'] == run['run_id'],
                            f'mixed {kind} commit/target/run')
                    require(Path(run[kind]['path']).parts[0] == run['run_id'],
                            f'{kind} artifact belongs to another isolated run')
                passed_test_events(artifact(base, run['nextest']), row['binary'], row['test'])
                require(run['observable'] == row['observable'] and run['assertions'] == row['assertions'],
                        'degraded observable evidence')
                result['hits'] = covered_probes(json.loads(artifact(base, run['coverage']).read_text()), row,
                                                Path(bundle['source_root']))
                result.update(status='pass', traceable=True, run_id=run['run_id'],
                              nextest=run['nextest'], coverage=run['coverage'])
            except (ValueError, KeyError, OSError, TypeError, IndexError) as error:
                result.update(status='fail', error=str(error))
                failures.append(row['id'])
        rows.append(result)
    total = sum(r['applicable'] for r in rows)
    passed = sum(r['traceable'] for r in rows)
    percent = passed / total * 100 if total else 0
    return {'identity': identity, 'rows': rows, 'summary': {'platform': platform, 'passed': passed,
            'total': total, 'percent': percent, 'failures': failures,
            'status': 'pass' if total and percent >= 95 and not set(failures).intersection(policy['mandatory']) else 'fail'}}


def run(output: Path, evidence: Path, threshold: float = 95.0, coverage: Path | None = None) -> int:
    require(math.isfinite(threshold) and threshold >= 95, 'threshold cannot weaken 95% policy')
    require(coverage is None, 'module coverage is not isolated source evidence; use --collect')
    inventory = tomllib.loads(INVENTORY.read_text())
    policy = json.loads(POLICY.read_text())
    meta = metadata(tool='critical-path-matrix', threshold=threshold)
    require_committed_sources(meta['commit'])
    result = evaluate(inventory, policy, json.loads(evidence.read_text()), evidence.parent,
                      git_sha(), meta['target'])
    if result['summary']['percent'] < threshold:
        result['summary']['status'] = 'fail'
    write_json(output, {**meta, **result})
    output.with_suffix('.md').write_text('# Critical Path Evidence\n\n' +
        '\n'.join(f"- `{r['id']}`: {r['status']} {r.get('error', '')}" for r in result['rows']) +
        f"\n\n{result['summary']['passed']}/{result['summary']['total']} applicable paths passed.\n")
    return 0 if result['summary']['status'] == 'pass' else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=QUALITY_ROOT / 'critical-paths.json')
    parser.add_argument('--evidence', type=Path, default=QUALITY_ROOT / 'critical-path-runs/bundle.json')
    parser.add_argument('--collect', action='store_true')
    parser.add_argument('--jobs', type=int, default=2, choices=range(1, 9),
                        help='parallel isolated critical-path tests (default: 2; 1 is serial)')
    parser.add_argument('--coverage', type=Path, help='obsolete; module coverage is rejected')
    parser.add_argument('--threshold', type=float, default=95)
    args = parser.parse_args()
    try:
        if args.collect:
            from critical_paths_collect import collect
            collect(args.evidence, jobs=args.jobs)
        return run(args.output, args.evidence, args.threshold, args.coverage)
    except (ValueError, KeyError, OSError, TypeError, IndexError) as error:
        write_json(args.output, {'summary': {'status': 'fail'}, 'error': str(error)})
        print(f'critical path evidence failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
