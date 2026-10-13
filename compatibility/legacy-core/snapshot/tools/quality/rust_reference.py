#!/usr/bin/env python3
"""Project retained Rust candidate evidence and compare policies in shadow mode."""
from __future__ import annotations

import argparse
from collections import defaultdict, deque
from decimal import Decimal
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import sys
import tarfile

import ci_quality
import harness_evidence as evidence
import policy_engine as engine
import production_coverage as production
import project_model as model
import source_measure as rust
from function_risk import crap_line
from quality_common import sha256, write_json

COLLECTOR = {'name': 'rust-reference', 'version': '1'}
HISTORICAL_SERIES = {'analyzer': 'harness-gate-rust-measure/0.2.0', 'rule': 'mccabe-rust-2/1',
                     'instrumentation': 'closure-black-box/1', 'mapping': 'insertions-utf8/1'}
HISTORICAL_HOTSPOTS = {
    'doctor/checks.rs': ['run_check', 'check_path', 'check_env', 'check_env_or_file', 'check_git_config', 'check_version'],
    'app/commands.rs': ['run', 'run_doctor', 'run_cleanup', 'run_scope', 'run_secrets', 'run_audit', 'run_verify', 'run_hook'],
    'verify/mod.rs': ['run_selected', 'service_results', 'merge_results', 'publish_report'],
    'verify/steps.rs': ['configured_task', 'configure_runner', 'configure_isolation', 'configure_shard', 'inject_task_environment'],
    'verify/parser.rs': ['count_json_results', 'count_json_path', 'discover_json_results'],
    'process/adapter.rs': ['run_with_cancel', 'prepare_request', 'run_process', 'wait_for_adapter',
                           'validate_process_output', 'finish_response'],
}
METRICS = {'lines': 'coverage.line', 'functions': 'coverage.function',
           'regions': 'coverage.region'}


def json_text(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def load_native(path):
    """Native display floats are valid; duplicate keys and nonfinite values are not."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            evidence.require(key not in result, 'duplicate native JSON key: ' + key)
            result[key] = value
        return result

    def invalid(value):
        raise ValueError('nonfinite native JSON value: ' + value)

    return json.loads(path.read_text(), object_pairs_hook=unique, parse_constant=invalid)


def fingerprint(value):
    return hashlib.sha256(json_text(value).encode()).hexdigest()


def risk_contract(series):
    if series == rust.SERIES:
        return rust.HOTSPOTS
    evidence.require(series == HISTORICAL_SERIES, 'unknown Rust risk series')
    return HISTORICAL_HOTSPOTS


def capability(counts):
    # A zero denominator remains raw 0/0 in native metadata, never numeric success.
    return 'supported' if counts['count'] else 'not_applicable'


class Projection:
    def __init__(self, root, sources, context, name, native_series):
        self.root, self.sources, self.expected = root, sources, context
        self.name, self.native_series = name, native_series
        self.records, self.rules = [], []
        self.project = {'schema': 'harness-project/v1', 'id': 'harness-gate',
                        'metadata': {'adapter': 'rust-reference', 'rust_series': json_text(native_series)}, 'relationships': [],
                        'components': [{'id': 'rust', 'path': '.', 'metadata': {'language': 'rust'},
                            'targets': [{'id': context['target'], 'boundaries': [], 'metadata': {}}],
                            'source_boundaries': []}], 'subjects': []}

    def add(self, key, path, digest, kind, native, values, states=None, group=None):
        group = group or key
        component = self.project['components'][0]
        if group not in component['targets'][0]['boundaries']:
            component['targets'][0]['boundaries'].append(group)
            component['source_boundaries'].append({'id': group, 'path': '.',
                                                   'role': 'production', 'metadata': {}})
        subject = {'id': 'subject-identity/v1:' + '0' * 64,
                   'identity_version': 'subject-identity/v1', 'component': 'rust',
                   'target': self.expected['target'], 'boundary': group, 'kind': kind,
                   'path': path, 'discriminator': key, 'source_sha256': digest,
                   'metadata': {'rust_native': json_text(native)}}
        subject['id'] = model.subject_id(self.project['id'], subject)
        states = {**{m: 'supported' for m in values}, 'coverage.branch': 'unsupported', **(states or {})}
        series_name = 'rust-function-risk' if self.name.endswith('-risk.json') else 'rust-production-coverage'
        series = {'name': series_name, 'collector': COLLECTOR,
                  'tool': {'name': 'retained-rust-tools', 'version': fingerprint(self.native_series)},
                  'rule': {'name': series_name, 'version': fingerprint(self.native_series)},
                  'runtime': {'name': 'rust', 'version': str(self.native_series['runtime'])},
                  'source_identity': {'name': 'rust-native-identity', 'version': '1'},
                  'normalization': COLLECTOR, 'target': self.expected['target'],
                  'metrics': [{'name': m, 'type': values[m]['type'] if m in values else evidence.METRIC_TYPES[m]}
                              for m in sorted(states)]}
        series['id'] = evidence.series_id(series)
        source = {'path': path, 'sha256': digest}
        artifact = self.root / self.name
        artifact_ref = {'id': 'native', 'kind': 'raw', 'media_type': 'application/json', 'path': self.name, 'sha256': sha256(artifact),
                        'bytes': artifact.stat().st_size, 'context': self.expected, 'source': source}
        record = {'schema': 'harness-evidence/v1', 'id': key, 'project': self.project['id'],
                  'component': 'rust', 'collector': COLLECTOR, 'series': series,
                  'subject': subject, 'context': self.expected, 'source': source,
                  'metrics': [{'name': m, 'value': v, 'artifacts': ['native']} for m, v in values.items()],
                  'capabilities': [{'metric': m, 'state': s, 'reason': 'Rust retained evidence: ' + s,
                                    'artifacts': ['native']} for m, s in states.items()],
                  'artifacts': [artifact_ref], 'status': 'measured' if values else 'unavailable'}
        self.records.append(record)
        self.project['subjects'].append(subject)
        return record

    def rule(self, group, metric, limit, required=True, operator='ge'):
        self.rules.append({'id': group + '.' + metric,
                           'scope': {'kind': 'boundary', 'component': 'rust', 'boundary': group},
                           'metric': metric, 'operator': operator, 'limit': limit,
                           'required': required, 'on_violation': 'fail',
                           'remediation_classes': ['review_retained_rust_evidence']})

    def evaluate(self):
        context = {'project': self.project, 'source_root': self.sources,
                   'artifact_root': self.root, 'expected': self.expected}
        evidence.validate_evidence(self.records, **context)
        result = engine.evaluate({'schema': 'harness-policy/v1', 'rules': self.rules},
                                 self.records, **context)
        # Optional unsupported gates do not affect the aggregate. Their semantic
        # state must still agree, or an apparently green replay could hide drift.
        rules = {rule['id']: rule for rule in self.rules}
        records = {record['subject']['id']: record for record in self.records}
        expected = {(rule['id'], record['subject']['id']) for rule in self.rules
                    for record in self.records
                    if record['subject']['boundary'] == rule['scope']['boundary']}
        actual = [(gate['policy'], gate['subject']) for gate in result['results']]
        evidence.require(len(actual) == len(set(actual)) and set(actual) == expected,
                         'Rust/generic policy result inventory mismatch')
        for gate in result['results']:
            metric = rules[gate['policy']]['metric']
            state = next(c['state'] for c in records[gate['subject']]['capabilities']
                         if c['metric'] == metric)
            if state in ('unsupported', 'not_applicable'):
                evidence.require(gate['state'] == state,
                                 'Rust/generic capability state mismatch: ' + metric)
            evidence.require(gate['state'] != 'measurement_error',
                             'generic policy measurement_error: ' + metric)
        return result


def coverage_values(row):
    values, states = {}, {}
    for key, metric in METRICS.items():
        if key in row:
            counts = row[key]
            evidence.require(type(counts['count']) is int and type(counts['covered']) is int and
                             0 <= counts['covered'] <= counts['count'], 'invalid Rust coverage counts')
            states[metric] = capability(counts)
            if states[metric] == 'supported':
                values[metric] = {'type': 'ratio', 'covered': counts['covered'], 'total': counts['count']}
    return values, states


def project_production(root, sources, context, report):
    evidence.require('error' not in report, 'production measurement_error: ' + str(report.get('error')))
    evidence.require(report['schema_version'] == 1 and report['gate_metric'] == 'lines' and
                     report['metrics_version'] == 'production-location-1', 'unknown production contract')
    evidence.require(report['commit'] == context['commit'] and report['target'] == context['target'],
                     'stale production identity')
    # Native paths name the original runner; read only the matching retained files.
    for filename in ('coverage.raw.json', 'coverage.lcov'):
        digests = [v for k, v in report['raw_artifacts'].items() if k.endswith('/' + filename)]
        evidence.require(digests == [sha256(root / filename)], 'stale production raw input: ' + filename)
    native_series = {k: report[k] for k in ('inventory_version', 'metrics_version', 'gate_metric')}
    native_series.update(runtime=report['rustc'], inventory=next(
        v for k, v in report['raw_artifacts'].items() if k.endswith('/production-source.json')))
    projection = Projection(root, sources, context, 'production.json', native_series)
    # Boundary/aggregate subjects identify their retained report; file subjects keep source digests.
    report_path = sources / 'evidence/production.json'
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_bytes((root / 'production.json').read_bytes())
    threshold = Fraction(report['threshold']) / 100
    expected, failures = {}, []
    for key, row in {**report['boundaries'], 'aggregate': report['aggregate']}.items():
        group = 'production-' + key
        passed = production.meets_threshold(row['lines']['covered'], row['lines']['count'],
                                             Decimal(report['threshold']))
        blocking = row.get('blocking', True)
        state = ('pass' if passed else 'fail') if blocking else 'informational'
        evidence.require(row['status'] == state, 'stored production outcome differs from current evaluator')
        if blocking and not passed:
            failures.append(key)
        values, states = coverage_values(row)
        record = projection.add(group, 'evidence/production.json', sha256(report_path),
                                'boundary/v1', row, values, states)
        expected[record['subject']['id']] = {'state': state, 'blocking': blocking}
        projection.rule(group, 'coverage.line', {'type': 'ratio', 'covered': threshold.numerator,
                                               'total': threshold.denominator}, blocking)
        projection.rule(group, 'coverage.branch', {'type': 'ratio', 'covered': 0, 'total': 1}, False)
    evidence.require(failures == report['failures'] and report['status'] == ('fail' if failures else 'pass'),
                     'stored production aggregate differs from current evaluator')
    evidence.require(report['files'].keys() == report['source_sha256'].keys(), 'incomplete production sources')
    for index, (path, row) in enumerate(report['files'].items()):
        values, states = coverage_values(row)
        projection.add(f'file-{index}', 'tools/harness-gate/' + path, report['source_sha256'][path],
                       'file/v1', row, values, states, group='files')
    result = projection.evaluate()
    actual = {r['subject']: r['state'] for r in result['results'] if r['policy'].endswith('.coverage.line')}
    mismatches = [identity for identity, row in expected.items()
                  if (actual.get(identity) if row['blocking'] else 'informational') != row['state']]
    if result['aggregate']['state'] != report['status']:
        mismatches.append('production aggregate')
    return projection, result, mismatches


def project_risk(root, sources, context, report, previous, *, label):
    hotspots = risk_contract(report['series'])
    old = defaultdict(deque)
    for index, row in enumerate(previous['functions']):
        old[(row['source'], row['kind'], row['syntax_sha256'])].append((index, row))
    native_series = {'series': report['series'], 'tools': report['tools'],
                     'runtime': fingerprint(report['tools'])}
    name = f'{label}-risk.json'
    projection = Projection(root, sources, context, name, native_series)
    identities, groups = [], set()
    for index, row in enumerate(report['functions']):
        matches = old[(row['source'], row['kind'], row['syntax_sha256'])]
        prior = matches.popleft()[1] if matches else None
        changed = prior is None
        selected = row['name'] in hotspots.get(row['source'], [])
        high = selected or (changed and row['cc'] > 10)
        group = 'high' if high else 'changed' if changed else 'legacy'
        groups.add(group)
        values, states = coverage_values(row)
        score = Fraction(*row['crap_exact'])
        evidence.require(score == crap_line(row['cc'], row['lines']['covered'], row['lines']['count']) and
                         float(score) == row['crap_line'] and row['cc'] == rust.complexity(row['raw']),
                         'inconsistent exact Rust risk counters')
        values.update({'complexity.cyclomatic': {'type': 'count', 'value': row['cc']},
                       'risk.crap': {'type': 'rational', 'numerator': row['crap_exact'][0],
                                     'denominator': row['crap_exact'][1]}})
        # Native identity, closure kind, span, float display and all raw counters remain lossless metadata.
        source = row['source']
        if report['series'] == rust.SERIES:
            evidence.require(source in rust.SOURCE_FILES, 'unknown Rust production source')
        else:
            evidence.require(source in hotspots, 'unknown historical Rust source')
        path = ('tools/harness-gate/' + source.removeprefix('../') if source.startswith('../quality-core/')
                else 'tools/harness-gate/src/' + source)
        record = projection.add(f'function-{index}', path,
                                row['source_sha256'], 'function/v1', row, values, states, group)
        identities.append({'subject': record['subject']['id'], 'source': row['source'], 'name': row['name'],
                           'span': row['span'], 'syntax_sha256': row['syntax_sha256'],
                           'changed': changed, 'selected': selected, 'high_risk': high,
                           'base': None if prior is None else {k: prior[k] for k in ('name', 'span', 'source_sha256')},
                           'head_source_sha256': row['source_sha256']})
    for group in sorted(groups):
        for metric in ('coverage.line', 'coverage.region'):
            projection.rule(group, metric, {'type': 'ratio', 'covered': 4, 'total': 5}, group == 'high')
        projection.rule(group, 'risk.crap', {'type': 'rational', 'numerator': 30, 'denominator': 1},
                        group != 'legacy', 'le')
        projection.rule(group, 'coverage.branch', {'type': 'ratio', 'covered': 0, 'total': 1}, False)
    result = projection.evaluate()
    by_subject = defaultdict(dict)
    for item in result['results']:
        by_subject[item['subject']][item['policy'].split('.', 1)[1]] = item['state']
    for identity, row in zip(identities, report['functions']):
        states = by_subject[identity.pop('subject')]
        absolute = all(states.get(metric) == 'pass' for metric in ('coverage.line', 'coverage.region', 'risk.crap'))
        evidence.require(absolute == row['passed'], 'Rust/generic absolute risk mismatch')
        identity['coverage_debt'] = not absolute
        identity['accepted'] = (absolute if identity['high_risk'] else
                                states.get('risk.crap') == 'pass' if identity['changed'] else True)
    return projection, result, identities


def sources_from_archive(archive, destination):
    with tarfile.open(archive) as bundle:
        seen = set()
        for member in bundle:
            if not member.name.startswith(('tools/harness-gate/src/', 'tools/harness-gate/quality-core/')) or member.isdir():
                continue
            model.canonical_path(member.name)
            evidence.require(member.isfile() and member.name not in seen, 'unsafe/duplicate source archive member')
            seen.add(member.name)
            path = destination / member.name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(bundle.extractfile(member).read())


def shadow(candidate_path, output, *, head, base, run_id):
    """No subprocesses: verify retained artifacts, project facts, run both evaluators."""
    root = candidate_path.parent.resolve()
    report = {'schema': 'rust-reference-shadow/v1', 'mode': 'shadow', 'authoritative': 'rust',
              'identity': {'commit': head, 'base_commit': base, 'run': run_id},
              'compatible': False, 'migration_blocked': True, 'compatibility_failures': []}
    evidence.require(not output.exists(), 'shadow output must be a fresh directory')
    evidence.require(not output.resolve().is_relative_to(root), 'shadow output must be outside retained candidate')
    output.mkdir(parents=True)
    try:
        candidate = load_native(candidate_path)
        evidence.require((candidate['commit'], candidate['base_sha'], candidate['run_id']) == (head, base, run_id),
                         'stale or mixed candidate identity')
        evidence.require(candidate['schema_version'] == 1 and candidate['candidate'] is True,
                         'invalid candidate schema')
        evidence.require(set(candidate['stages']) == set(ci_quality.STAGES), 'missing required Rust stage')
        report['current_stages'] = candidate['stages']
        report['retained_artifacts'] = candidate['artifacts']
        report['candidate_sha256'] = sha256(candidate_path)
        try:
            ci_quality.verify(candidate_path, head, base, run_id)
            report['current_state'] = 'pass'
        except (ValueError, OSError) as error:
            report['current_state'] = 'fail'
            report['current_error'] = str(error)
        evidence.require(ci_quality.REQUIRED_ARTIFACTS <= candidate['artifacts'].keys(), 'missing required raw evidence')
        for path, digest in candidate['artifacts'].items():
            evidence._file(root, path, digest)
        context = {'commit': head, 'base_commit': base, 'target': candidate['target'], 'run': run_id}
        report['identity'] = context
        for label in ('base', 'head'):
            sources_from_archive(root / f'{label}-source.tar', output / label)
        production_report = load_native(root / 'production.json')
        projection, result, mismatches = project_production(root, output / 'head', context, production_report)
        write_json(output / 'production-evidence.json', projection.records)
        write_json(output / 'production-project.json', projection.project)
        write_json(output / 'production-policy.json', {'schema': 'harness-policy/v1', 'rules': projection.rules})
        report['production'] = result
        report['compatibility_failures'].extend(mismatches)
        base_risk, head_risk = [load_native(root / f'{label}-risk.json') for label in ('base', 'head')]
        for label, risk in (('base', base_risk), ('head', head_risk)):
            evidence.require(risk['manifest_sha256'] == sha256(root / f'{label}-manifest.json') and
                             risk['llvm_sha256'] == sha256(root / f'{label}-coverage.json'), 'stale Rust risk inputs')
        current = rust.compare(base_risk, head_risk, series=head_risk['series'],
                               hotspots=risk_contract(head_risk['series']))
        evidence.require(current == load_native(root / 'risk.json'),
                         'retained risk result differs from current evaluator')
        base_projection = None
        for label, risk in (('base', base_risk), ('head', head_risk)):
            risk_context = {**context, 'commit': base if label == 'base' else head}
            # The label is explicit even for baseline runs where base == head.
            projection, result, identities = project_risk(root, output / label, risk_context, risk, base_risk, label=label)
            if label == 'base':
                base_projection = projection
            else:
                evidence.require_compatible_series(base_projection.records[0]['series'], projection.records[0]['series'])
            write_json(output / f'{label}-risk-evidence.json', projection.records)
            write_json(output / f'{label}-risk-project.json', projection.project)
            write_json(output / f'{label}-risk-policy.json', {'schema': 'harness-policy/v1', 'rules': projection.rules})
            if label == 'head':
                report['risk'] = result
                report['identities'] = identities
                if identities != current['identities']:
                    report['compatibility_failures'].append('risk identity/outcome/debt classification')
                if result['aggregate']['state'] != ('fail' if current['failures'] else 'pass'):
                    report['compatibility_failures'].append('risk aggregate')
        # Other required stages remain authoritative and are retained, never erased by this projection.
        report['generic_state'] = ('pass' if all(s['status'] == 'success' for s in candidate['stages'].values())
                                   and all(report[k]['aggregate']['state'] == 'pass' for k in ('production', 'risk'))
                                   else 'fail')
        if report['generic_state'] != report['current_state']:
            report['compatibility_failures'].append('required Rust aggregate')
        report['compatible'] = not report['compatibility_failures']
        report['state'] = 'compatible' if report['compatible'] else 'measurement_error'
        report['migration_blocked'] = not report['compatible'] or report['current_state'] != 'pass'
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, ArithmeticError, OSError, StopIteration, tarfile.TarError) as error:
        report.update(state='measurement_error', compatible=False, migration_blocked=True)
        report['compatibility_failures'].append(str(error))
    write_json(output / 'shadow.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--head-sha', required=True)
    parser.add_argument('--base-sha', required=True)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    try:
        report = shadow(args.candidate, args.output, head=args.head_sha, base=args.base_sha, run_id=args.run_id)
        print(json.dumps({k: report[k] for k in ('state', 'compatible', 'migration_blocked')}))
        return int(report['migration_blocked'])
    except (ValueError, OSError) as error:
        print(f'Rust shadow measurement_error: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
