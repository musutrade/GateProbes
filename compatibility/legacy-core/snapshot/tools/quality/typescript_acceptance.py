#!/usr/bin/env python3
"""GH-134: collect and replay two real, locked frontend history pairs."""
import argparse
import copy
from fractions import Fraction
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

import collector_runner as runner
import harness_evidence as evidence
import policy_engine as engine
import typescript_reference as adapter
import typescript_semantics as ts

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
FIXTURE = ROOT / 'fixtures/typescript-angular'
RETAINED = REPO / 'docs/quality/gh-134'
PATHS = ('src/app/pricing.ts', 'src/app/standard-quote.ts',
         'src/app/priority-quote.ts', 'src/app/app.routes.ts', 'src/app/quote-client.ts')
DISCOUNT = """
describe('Acceptance discount branch', () => {
  it('quotes a bulk order', () => {
    expect(TestBed.inject(Pricing).quote(10)).toBe(80);
  });
});
"""
COMPATIBLE = """
describe('Acceptance compatible change', () => {
  it('quotes another small order', () => {
    expect(TestBed.inject(Pricing).quote(3)).toBe(30);
  });
});
"""


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def pack(files, path):
    with tarfile.open(path, 'w:gz') as archive:
        for name, data in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


def unpack(path):
    with tarfile.open(path, 'r:gz') as archive:
        return {m.name: archive.extractfile(m).read() for m in archive.getmembers()}


def collect_window(work, retained):
    """Each pair has a real local Git parent/head and four independent tool runs."""
    work.mkdir(parents=True, exist_ok=False)
    retained.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('native_collection', FIXTURE / 'collect.py')
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    native.REPO = REPO

    class WindowCollection(native.Collection):
        def run(self, argv, cwd=None):
            # Collection.run's default cwd was bound when its module was loaded.
            # Snapshot collection must explicitly select the current fixture root.
            return super().run(argv, native.ROOT if cwd is None else cwd)

    runs = {}
    for pair in ('compatible', 'regression'):
        repo = work / pair / 'repo'
        fixture = repo / 'fixture'
        shutil.copytree(FIXTURE, fixture, ignore=shutil.ignore_patterns(
            'node_modules', '.angular', 'dist', 'coverage', 'evidence', 'semantics', '__pycache__'))
        (repo / '.gitignore').write_text('node_modules/\n.angular/\ndist/\ncoverage/\n')
        def git(*args):
            result = subprocess.run(['git', *args], cwd=repo, check=True,
                                    capture_output=True, text=True)
            return result.stdout.strip()
        git('init', '-b', 'acceptance')
        git('config', 'user.name', 'Frontend acceptance fixture')
        git('config', 'user.email', 'fixture@example.invalid')
        test = fixture / 'app/src/app/pricing.spec.ts'
        original = test.read_text()
        base = None
        for side in ('base', 'head'):
            name = pair + '-' + side
            test.write_text(original + (DISCOUNT if side == 'base' or pair == 'compatible' else '')
                            + (COMPATIBLE if side == 'head' and pair == 'compatible' else ''))
            git('add', '.')
            git('commit', '-m', name)
            commit = git('rev-parse', 'HEAD')
            parent = git('rev-parse', 'HEAD^') if side == 'head' else commit
            if side == 'head' and parent != base:
                raise ValueError('unexpected fixture history')
            base = commit if side == 'base' else base
            destination = retained / name
            destination.mkdir()
            native.ROOT = fixture
            output = work / pair / side
            collection = WindowCollection(output)
            try:
                collection.collect()
            except Exception as error:
                collection.manifest['error'] = str(error)
                collection.save()
                raise
            app = fixture / 'app'
            for script, arguments, filename in [
                ('source-index.cjs', [str(app)], 'source-index.json'),
                ('coverage-oracle.cjs', [str(destination / 'source-index.json'),
                    str(next((output / 'coverage').rglob('coverage-final.json'))), str(app)],
                 'native-counters.json')]:
                argv = ['node', str(fixture / script), *arguments]
                result = subprocess.run(argv, cwd=fixture, capture_output=True, check=True)
                (destination / filename).write_bytes(result.stdout)
                write_json(destination / (filename + '.command.json'),
                           dict(argv=argv, exit_status=result.returncode,
                                stderr=result.stderr.decode()))
            pack({p.relative_to(output).as_posix(): p.read_bytes()
                  for p in output.rglob('*') if p.is_file()}, destination / 'native.tar.gz')
            write_json(destination / 'receipt.json', dict(
                native_sha256=ts.digest((destination / 'native.tar.gz').read_bytes()),
                index_sha256=ts.digest((destination / 'source-index.json').read_bytes()),
                coverage_root=str(app)))
            runs[name] = dict(commit=commit, base_commit=parent, target='node-jsdom', run=name)
            write_json(retained / 'window.json', dict(schema='typescript-acceptance-window/v1', runs=runs))
            print(f'{name}: collected {commit}', flush=True)
        git('bundle', 'create', str(retained / (pair + '.bundle')), '--all')


def replay(retained, name, root):
    source = retained / name
    files = unpack(source / 'native.tar.gz')
    expected = evidence.load_json(retained / 'window.json')['runs'][name]
    manifest = json.loads(files['manifest.json'])
    if manifest['revision'] != expected['commit'] or manifest['working_tree']:
        raise ValueError('native run does not match clean acceptance commit')
    workspace, output = root / 'workspace', root / 'output'
    output.mkdir(parents=True)
    for path, data in files.items():
        if path.startswith('sources/'):
            destination = workspace / path.removeprefix('sources/')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
    for src, dst in [('native.tar.gz', 'native.tar.gz'), ('source-index.json', 'index.json')]:
        shutil.copyfile(source / src, workspace / dst)
    receipt = evidence.load_json(source / 'receipt.json')
    bundle = ts.read_bundle((source / 'native.tar.gz').read_bytes(),
        (source / 'source-index.json').read_bytes(), receipt,
        {p.removeprefix('sources/app/'): data for p, data in files.items()
         if p.startswith('sources/app/src/')})
    subjects = [row['subject'] for path in PATHS for row in bundle.measure(path)]
    project = dict(schema='harness-project/v1', id='typescript-reference', metadata={},
                   relationships=[], subjects=subjects, components=[dict(
                       id='typescript', path='app', metadata={},
                       targets=[dict(id='node-jsdom', boundaries=['production-ts'], metadata={})],
                       source_boundaries=[dict(id='production-ts', path='app/src',
                                               role='production', metadata={})])])
    request = dict(schema='harness-collector-request/v1', project=project['id'],
        component='typescript', collector=adapter.COLLECTOR, context=expected,
        requested_capabilities=list(evidence.METRIC_TYPES), workspace_root=str(workspace),
        output_root=str(output), parameters=dict(native='native.tar.gz', index='index.json',
                                                subjects=copy.deepcopy(subjects)))
    request['parameters']['receipt'] = dict(receipt, schema='typescript-collector-replay/v1',
        native_revision=manifest['revision'], request=adapter.binding(request))
    records = runner.run_collector(runner.InternalAdapter(adapter.collect), request, project=project)
    return dict(records=records, context=dict(project=project, source_root=workspace,
                artifact_root=output, expected=expected), request=request)


def pricing(run):
    return next(r for r in run['records'] if r['subject']['path'] == 'app/src/app/pricing.ts'
                and r['subject']['kind'] == 'file/v1')


def policy(subject, numerator=4, denominator=5):
    return dict(schema='harness-policy/v1', rules=[dict(id='pricing-lines',
        scope=dict(kind='subject', subject=subject), metric='coverage.line', operator='ge',
        limit=dict(type='ratio', covered=numerator, total=denominator), required=True,
        on_violation='fail', remediation_classes=['increase_meaningful_coverage'],
        ratchet=dict(deny_regression=True, allow_legacy_debt=True))])


def evaluate(base, head, selected_policy):
    return engine.evaluate(selected_policy, head['records'], **head['context'],
                           base_records=base['records'], base_context=base['context'])


def verify_window(retained, work):
    runs, counters = {}, {}
    for name in evidence.load_json(retained / 'window.json')['runs']:
        run = runs[name] = replay(retained, name, work / name)
        oracle = evidence.load_json(retained / name / 'native-counters.json')['files']
        checked = 0
        for path, scopes in oracle.items():
            rows = [r for r in run['records'] if r['subject']['path'] == 'app/' + path]
            if len(rows) != len(scopes):
                raise ValueError('native/normalized subject count mismatch')
            for row, scope in zip(rows, scopes):
                values = {m['name']: m['value'] for m in row['metrics']}
                for metric, native in [('coverage.line', 'lines'), ('coverage.function', 'functions')]:
                    expected = dict(type='ratio', **scope[native])
                    if values.get(metric) != expected:
                        raise ValueError(f'{name}/{path}/{scope["scope"]}: counter mismatch')
                    checked += 1
        counters[name] = dict(exact_counter_comparisons=checked,
                             pricing=oracle['src/app/pricing.ts'][0]['lines'])
        write_json(work / name / 'normalized.json', run['records'])
    pairs = {}
    for pair in ('compatible', 'regression'):
        base, head = runs[pair + '-base'], runs[pair + '-head']
        reports = {}
        for label, limit in [('threshold', (4, 5)), ('debt', (9, 10))]:
            selected = policy(pricing(head)['subject']['id'], *limit)
            report = evaluate(base, head, selected)
            b, h = [counters[pair + '-' + side]['pricing'] for side in ('base', 'head')]
            bv, hv = Fraction(b['covered'], b['total']), Fraction(h['covered'], h['total'])
            absolute, base_absolute = hv >= Fraction(*limit), bv >= Fraction(*limit)
            regression = hv < bv
            legacy = not absolute and not base_absolute and not regression
            expected = dict(absolute_compliant=absolute, base_absolute_compliant=base_absolute,
                trend='regressed' if regression else 'unchanged',
                debt='none' if absolute else 'new' if base_absolute else
                     'regressed' if regression else 'unchanged',
                remaining_debt=not absolute, regression=regression, legacy_debt_allowed=legacy)
            outcome = 'fail' if regression or (not absolute and not legacy) else 'pass'
            if (report['aggregate']['state'] != outcome or
                    report['results'][0]['record']['ratchet'] != expected or
                    bool(report['debt_ledger']) != (expected['debt'] != 'none')):
                raise ValueError(f'{pair}/{label}: native/generic outcome or debt mismatch')
            reports[label] = dict(native_expected=dict(aggregate=outcome, comparison=expected),
                                  policy=selected, report=report)
        pairs[pair] = reports
    summary = dict(schema='typescript-acceptance-results/v1', counters=counters, pairs=pairs,
                   unexplained_mismatches=[], certification='none; task 4.1 only')
    write_json(work / 'results.json', summary)
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collect', action='store_true')
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--retained', type=Path, default=RETAINED)
    args = parser.parse_args()
    if args.collect:
        collect_window(args.work.resolve(), args.retained.resolve())
    else:
        verify_window(args.retained.resolve(), args.work.resolve())
