#!/usr/bin/env python3
"""Frozen non-authoritative Python reference; see docs/quality/python-retention.md.

Generic decisions belong to the released Rust core. No release-approval path.

Check opt-in project configuration and report generic shadow gates."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import harness_evidence as evidence
import policy_engine as engine
import project_model as model


def load_config(path, root):
    config = evidence.load_json(path)
    evidence._shape(config, 'project-config.schema.json')
    root = Path(root).resolve()

    def referenced(name):
        relative = model.canonical_path(config[name])
        resolved = (root / relative).resolve()
        evidence.require(resolved.is_relative_to(root), 'config reference escapes project root')
        return evidence.load_json(resolved)

    project, policy = referenced('project_model'), referenced('policy')
    engine.validate_policy(policy, project)
    return project, policy


def report(policy_result, project, policy):
    """Indexes point to one lossless gate table, including raw evidence links."""
    gates = {}
    indexes = {name: {} for name in ('component', 'subject', 'policy', 'status', 'relationship')}
    for position, result in enumerate(policy_result['results']):
        gate_id = f'gate-{position:06d}'
        gates[gate_id] = result
        record = result['record']
        link = record.get('relationship')
        components = ([link['producer'], link['consumer']] if link else
                      [record['component']] if record['component'] else [])
        values = {'component': components, 'subject': [result['subject']],
                  'policy': [result['policy']], 'status': [result['state']],
                  'relationship': [link['id']] if link else []}
        for dimension, keys in values.items():
            for key in keys:
                if key is not None:
                    indexes[dimension].setdefault(key, []).append(gate_id)

    def aggregate(ids):
        results = [engine.GateResult(**gates[i]) for i in ids]
        policies = {r.policy for r in results}
        if not policies:
            return {'state': 'not_applicable', 'blockers': []}
        return engine.aggregate({**policy, 'rules': [r for r in policy['rules']
                                                    if r['id'] in policies]}, results)

    components = {}
    for component in project['components']:
        ids = indexes['component'].get(component['id'], [])
        local = [i for i in ids if 'relationship' not in gates[i]['record']]
        cross = [i for i in ids if 'relationship' in gates[i]['record']]
        components[component['id']] = {'gates': ids, 'aggregate': aggregate(ids),
                                      'local': aggregate(local), 'cross_component': aggregate(cross)}
    return {'schema': 'harness-project-report/v1', 'mode': 'shadow',
            'project': project['id'], 'aggregate': policy_result['aggregate'],
            'components': components, 'gates': gates, 'indexes': indexes,
            'policy_result': policy_result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('check', 'evaluate'))
    parser.add_argument('--config', type=Path, default=Path('.harness-gate/project.json'))
    parser.add_argument('--root', type=Path, default=Path('.'),
                        help='Root for explicit model/policy references; defaults to working directory')
    parser.add_argument('--output', required=True, type=Path)
    for name in ('evidence', 'expected', 'source-root', 'artifact-root', 'selection'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--reference-only', action='store_true', required=True,
                        help='Acknowledge frozen reference output cannot approve a release')
    args = parser.parse_args()
    try:
        project, policy = load_config(args.config, args.root)
        if args.command == 'check':
            result = {'schema': 'harness-project-config-check/v1', 'mode': 'shadow',
                      'project': project['id'], 'aggregate': {'state': 'pass'}}
        else:
            evidence.require(all((args.evidence, args.expected, args.source_root, args.artifact_root)),
                             'evaluate requires evidence, expected, source-root and artifact-root')
            result = report(engine.evaluate(
                policy, evidence.load_json(args.evidence), project=project,
                expected=evidence.load_json(args.expected), source_root=args.source_root,
                artifact_root=args.artifact_root,
                selection=evidence.load_json(args.selection) if args.selection else None), project, policy)
    except (evidence.MeasurementError, model.ModelError, OSError) as error:
        result = {'schema': 'harness-project-report/v1', 'mode': 'shadow',
                  'aggregate': {'state': 'measurement_error'}, 'error': str(error)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return 0 if result['aggregate']['state'] == 'pass' else 1


if __name__ == '__main__':
    sys.exit(main())
