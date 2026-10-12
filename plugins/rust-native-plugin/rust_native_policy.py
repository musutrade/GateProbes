#!/usr/bin/env python3
"""Opt-in native facts to the released Rust evaluator; never accepts a baseline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

import harness_evidence as evidence
import project_model as model
import rust_native_driver as native
import rust_native_config as configuration

COLLECTOR = {'name': 'rust-native-production', 'version': '1'}


def fingerprint(value):
    return native.digest(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def compatibility(report, hotspots):
    native.require(report['series'] == native.SERIES and report['mapping_complete_for_declared_scope'],
                   'uncertified/incompatible production series')
    return {k: report[k] for k in ('series', 'scope', 'tools', 'flags', 'cfg', 'build_inputs', 'adapter_sha256')} | {
        'hotspots': sorted(hotspots), 'projection_sha256': native.file_hash(Path(__file__))}


def require_history(base, head, hotspots):
    native.require(base is not None, 'missing immutable native baseline; reset is forbidden')
    native.require(compatibility(base, hotspots) == compatibility(head, hotspots),
                   'incompatible native tools/rules/config/selection/history')
    for report in (base, head):
        native.require(set(hotspots) <= {f['name'] for f in report['functions']}, 'missing selected hotspot')


def project(report, root, sources, context, project_id, hotspots, component='rust'):
    root.mkdir(parents=True, exist_ok=False)
    native.write_json(root / 'native.json', report)
    document = {'schema': 'harness-project/v1', 'id': project_id, 'metadata': {}, 'relationships': [],
                'components': [{'id': component, 'path': '.', 'metadata': {},
                    'targets': [{'id': context['target'], 'boundaries': ['production'], 'metadata': {}}],
                    'source_boundaries': [{'id': 'production', 'path': '.', 'role': 'production', 'metadata': {}}]}],
                'subjects': []}
    records = []
    inventory = {p['relative']: p['sha256'] for p in report['source_inventory']}
    # Aggregate source identity hashes the complete lexical inventory, including
    # cfg-inactive files. Keep it beside the original sources for core verification.
    aggregate_path = 'native-source-inventory.json'
    native.require(not (sources / aggregate_path).exists(), 'aggregate source collision')
    native.write_json(sources / aggregate_path, report['source_inventory'])
    inventory[aggregate_path] = native.file_hash(sources / aggregate_path)
    rows = []
    for function in report['functions']:
        rows.append((fingerprint(function['owner']), function['source_lines'][0][0], function, {
            'coverage.line': ratio(function['lines']), 'coverage.region': ratio(function['regions']),
            'coverage.function': {'type': 'ratio', 'covered': int(function['blocks'][0] > 0), 'total': 1},
            'complexity.cyclomatic': {'type': 'count', 'value': function['cc']},
            'risk.crap': {'type': 'rational', 'numerator': function['crap_exact'][0], 'denominator': function['crap_exact'][1]},
        }))
    rows.append(('aggregate', aggregate_path, None, {
        'coverage.' + name: ratio(report['coverage'][plural])
        for name, plural in [('line', 'lines'), ('region', 'regions'), ('function', 'functions')]}))
    for key, path, function, values in rows:
        subject = {'id': 'subject-identity/v1:' + '0' * 64, 'identity_version': 'subject-identity/v1', 'component': component,
                   'target': context['target'], 'boundary': 'production',
                   'kind': 'function/v1' if function else 'boundary/v1', 'path': path,
                   'discriminator': key, 'source_sha256': inventory[path],
                   'metadata': {'owner': function['owner']} if function else {}}
        subject['id'] = model.subject_id(project_id, subject)
        series = {'name': 'rust-native-production-mir-block', 'collector': COLLECTOR,
                  'tool': {'name': 'native-toolchain', 'version': fingerprint(report['tools'])},
                  'rule': {'name': 'native-production', 'version': fingerprint(compatibility(report, hotspots))},
                  'runtime': {'name': 'rustc', 'version': native.RUSTC_COMMIT},
                  'source_identity': {'name': 'rustc-def-path-hash-expansion', 'version': '1'},
                  'normalization': COLLECTOR, 'target': context['target'],
                  'metrics': [{'name': m, 'type': v['type']} for m, v in sorted(values.items())]}
        series['id'] = evidence.series_id(series)
        source = {'path': path, 'sha256': inventory[path]}
        artifact = {'id': 'native', 'kind': 'raw', 'media_type': 'application/json', 'path': 'native.json',
                    'sha256': native.file_hash(root / 'native.json'), 'bytes': (root / 'native.json').stat().st_size,
                    'context': context, 'source': source}
        records.append({'schema': 'harness-evidence/v1', 'id': 'native-' + key, 'project': project_id,
                        'component': component, 'collector': COLLECTOR, 'series': series, 'subject': subject,
                        'context': context, 'source': source, 'status': 'measured', 'artifacts': [artifact],
                        'metrics': [{'name': m, 'value': v, 'artifacts': ['native']} for m, v in values.items()],
                        'capabilities': [{'metric': m, 'state': 'supported', 'reason': 'Independent native counters',
                                          'artifacts': ['native']} for m in values]})
        document['subjects'].append(subject)
    return {'project': document, 'evidence': records, 'expected': context,
            'source-root': str(sources), 'artifact-root': str(root)}


def ratio(counts):
    return {'type': 'ratio', 'covered': counts['covered'], 'total': counts['count']}


def policy_and_lineage(base, head, base_projection, head_projection, hotspots, crap_rule):
    """Apply the configured CRAP ceiling with native changed/selected debt scopes.

    The Rust core calculates absolute outcomes, debt, trend and the aggregate.
    Rename/move/split history requires a separately reviewed explicit mapping;
    only unique identical compiler owners get automatic modify lineage here.
    """
    prior = {f['owner']: f for f in base['functions']}
    subjects = {s['discriminator']: s for s in base_projection['project']['subjects']}
    rows = {fingerprint(f['owner']): f for f in head['functions']}
    rules, mappings, identities = [], [], []
    for subject in head_projection['project']['subjects']:
        key = subject['discriminator']
        row = rows.get(key)
        old = prior.get(row['owner']) if row else None
        changed = bool(row and (old is None or old['syntax_sha256'] != row['syntax_sha256']))
        high = bool(row and (row['name'] in hotspots or (changed and row['cc'] > 10)))
        if key in subjects and subjects[key]['id'] != subject['id']:
            mappings.append({'kind': 'modify', 'from': subjects[key]['id'], 'to': [subject['id']],
                             'reason': 'Unique compiler owner retained across verified source revisions' if row
                             else 'Complete production aggregate across verified source revisions'})
        identities.append({'subject': subject['id'], 'changed': changed, 'high_risk': high,
                           'base_subject': subjects[key]['id'] if key in subjects else None})
        metrics = ['coverage.line', 'coverage.region'] + (['risk.crap'] if row else [])
        for metric in metrics:
            absolute = row is None or high or (changed and metric == 'risk.crap')
            rules.append({'id': 'native-' + key + '.' + metric,
                          'scope': {'kind': 'subject', 'subject': subject['id']}, 'metric': metric,
                          'operator': 'le' if metric == 'risk.crap' else 'ge',
                          'limit': crap_rule['limit'] if metric == 'risk.crap'
                          else {'type': 'ratio', 'covered': 4, 'total': 5},
                          'required': True, 'on_violation': 'fail',
                          'ratchet': {'deny_regression': True, 'allow_legacy_debt': not absolute},
                          'remediation_classes': ['review_native_production_evidence']})
            if metric == 'risk.crap':
                rules[-1]['remediation_classes'] = crap_rule['remediation_classes']
                rules[-1]['ratchet']['allow_legacy_debt'] &= crap_rule['ratchet']['allow_legacy_debt']
    return ({'schema': 'harness-policy/v1', 'rules': rules},
            {'schema': 'subject-mappings/v1', 'project': head_projection['project']['id'], 'mappings': mappings}, identities)


def evaluate(base_directory, base_anchor, head_directory, head_anchor, output, binary,
             base_context, head_context, project_id, hotspots=(), explicit_mappings=(), *,
             repository_root, policy_binding):
    """Both anchors must come from a trusted host; neither is inferred from disk."""
    import shutil
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    binding = configuration.load(repository_root, policy_binding, project_id, binary, output)
    base, head = (native.certify(Path(d), a) for d, a in
                  [(base_directory, base_anchor), (head_directory, head_anchor)])
    require_history(base, head, hotspots)
    configuration.require_scope(binding, (base, head))
    native.require(head_context['base_commit'] == base_context['commit'], 'unrelated baseline commit')
    native.require(head_context['target'] == base_context['target'], 'incompatible target')
    projections = []
    for label, report, directory, context in [('base', base, base_directory, base_context),
                                               ('head', head, head_directory, head_context)]:
        source = output / (label + '-sources')
        if report['backend_complete']:
            shutil.copytree(Path(directory) / 'source', source)
        else:
            source.mkdir()
            shutil.copyfile(Path(directory) / 'fixture.rs', source / 'fixture.rs')
        projections.append(project(report, output / label, source, context, project_id, hotspots, binding['component']))
        native.write_json(output / (label + '-evidence.json'), projections[-1]['evidence'])
    configuration.require_series(binding, projections)
    policy, mappings, identities = policy_and_lineage(base, head, *projections, hotspots, binding['rule'])
    # The released core validates explicit rename/move/split cardinality and
    # collisions with automatic same-owner modifications. Never infer renames.
    mappings['mappings'].extend(explicit_mappings)
    native.write_json(output / 'identities.json', identities)
    command = [str(Path(binary).resolve()), 'quality', 'evaluate', '--output', str(output / 'report.json')]
    for name, value in [('policy', policy), ('mappings', mappings)]:
        native.write_json(output / (name + '.json'), value)
        command.extend(['--' + name, str(output / (name + '.json'))])
    for prefix, projection in [('base-', projections[0]), ('', projections[1])]:
        for name, value in projection.items():
            if name.endswith('-root'):
                path = value
            else:
                path = str(output / (prefix + name + '.json'))
                native.write_json(Path(path), value)
            command.extend(['--' + prefix + name, path])
    completed = subprocess.run(command, capture_output=True, text=True)
    (output / 'evaluate.stdout').write_text(completed.stdout)
    (output / 'evaluate.stderr').write_text(completed.stderr)
    native.write_json(output / 'evaluate.command.json', {'command': command, 'exit_code': completed.returncode})
    native.require(completed.returncode in (0, 1) and (output / 'report.json').is_file(), 'Rust policy evaluation failed')
    return json.loads((output / 'report.json').read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'base-anchor', 'head', 'head-anchor', 'output', 'harness-gate',
                 'base-context', 'head-context', 'project', 'repository-root', 'policy-binding'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--hotspots', required=True, help='JSON array of explicitly selected compiler names (may be empty)')
    parser.add_argument('--mappings', help='JSON array of reviewed explicit subject lineage mappings')
    args = parser.parse_args()
    try:
        report = evaluate(args.base, args.base_anchor, args.head, args.head_anchor, args.output, args.harness_gate,
                          json.loads(Path(args.base_context).read_text()), json.loads(Path(args.head_context).read_text()),
                          args.project, json.loads(Path(args.hotspots).read_text()),
                          json.loads(Path(args.mappings).read_text()) if args.mappings else (),
                          repository_root=args.repository_root, policy_binding=args.policy_binding)
        print(json.dumps(report['aggregate']))
        return int(report['aggregate']['state'] != 'pass')
    except (ValueError, KeyError, OSError) as error:
        print('native production measurement_error: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
