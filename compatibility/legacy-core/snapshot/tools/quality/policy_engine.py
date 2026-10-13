#!/usr/bin/env python3
"""Frozen non-authoritative Python reference; see docs/quality/python-retention.md.

Generic decisions belong to the released Rust core. No release-approval path.

Generic shadow policy evaluation over validated harness-evidence/v1 facts."""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from enum import Enum
from fractions import Fraction
import json
from pathlib import Path
import sys

import harness_evidence as evidence
import project_model as model
import policy_ratchet as ratchet
import cross_component as contracts


class GateState(str, Enum):
    PASS = 'pass'
    FAIL = 'fail'
    WARNING = 'warning'
    INFORMATIONAL = 'informational'
    SKIPPED = 'skipped'
    UNSUPPORTED = 'unsupported'
    NOT_APPLICABLE = 'not_applicable'
    MEASUREMENT_ERROR = 'measurement_error'
    BLOCKED = 'blocked'
    CANCELLED = 'cancelled'


@dataclass(frozen=True)
class GateResult:
    policy: str
    subject: str | None
    state: GateState
    reason: str
    record: dict

    def to_dict(self):
        return asdict(self)


def validate_policy(policy, project):
    evidence._shape(policy, 'policy.schema.json')
    model.validate_project(project)
    components = {c['id']: c for c in project['components']}
    evidence._index(policy['rules'], 'id', 'policy ID')
    for rule in policy['rules']:
        kind = evidence.METRIC_TYPES.get(rule['metric'])
        evidence.require(evidence.metric_type_matches(rule['metric'], rule['limit']['type']),
                         'policy metric/limit type mismatch')
        if kind == 'boolean':
            evidence.require(rule['operator'] in ('eq', 'ne'), 'boolean requires eq or ne')
        if kind == 'ratio':
            evidence.require(rule['limit']['covered'] <= rule['limit']['total'],
                             'policy ratio exceeds total')
        scope = rule['scope']
        if scope['kind'] == 'subject':
            evidence.require(scope['subject'] in {s['id'] for s in project['subjects']},
                             'unknown policy subject')
        if scope['kind'] == 'relationship':
            evidence.require(rule['metric'].startswith('contract.'),
                             'relationship scope requires a contract metric')
            evidence.require('ratchet' not in rule,
                             'contract comparison uses retained baseline provenance, not debt ratchet')
            contracts.subjects(project, scope['relationship'])
        if 'component' in scope:
            evidence.require(scope['component'] in components, 'unknown policy component')
        if 'boundary' in scope:
            boundaries = components[scope['component']]['source_boundaries']
            evidence.require(scope['boundary'] in {b['id'] for b in boundaries},
                             'unknown policy boundary')
    return policy


def _value(value):
    if value['type'] == 'rational':
        return Fraction(value['numerator'], value['denominator'])
    if value['type'] == 'ratio':
        return Fraction(value['covered'], value['total'])
    if value['type'] == 'boolean':
        return value['value']
    return Fraction(value['value'])


def compare(observed, operator, limit):
    """Exact typed comparison; no floating point rounding or metric-specific rules."""
    for value in (observed, limit):
        evidence.require(value.get('type') in evidence.VALUE_TYPES, 'unknown value type')
        evidence._shape(value, definition=evidence.VALUE_TYPES[value['type']])
        if value['type'] == 'ratio':
            evidence.require(value['covered'] <= value['total'], 'ratio exceeds total')
    evidence.require(observed['type'] == limit['type'], 'comparison type mismatch')
    if observed['type'] == 'boolean':
        evidence.require(operator in ('eq', 'ne'), 'boolean requires eq or ne')
    a, b = _value(observed), _value(limit)
    comparisons = {'lt': a < b, 'le': a <= b, 'eq': a == b,
                   'ne': a != b, 'ge': a >= b, 'gt': a > b}
    evidence.require(operator in comparisons, 'unknown comparison operator')
    return comparisons[operator]


def _select(scope, project, selection, target):
    subjects = [s for s in project['subjects'] if s['target'] == target]
    kind = scope['kind']
    if kind == 'subject':
        return [s for s in subjects if s['id'] == scope['subject']]
    if kind == 'relationship':
        return contracts.subjects(project, scope['relationship'], target)
    if kind in ('changed_subject', 'critical_subject'):
        evidence.require(kind in selection, f'missing caller-owned {kind} selection')
        ids = selection[kind]
        evidence.require(isinstance(ids, list) and all(isinstance(i, str) for i in ids),
                         'subject selection must be a list of IDs')
        evidence.require(len(ids) == len(set(ids)) and
                         set(ids) <= {s['id'] for s in subjects}, 'unknown/duplicate selected subject')
        return [s for s in subjects if s['id'] in ids]
    return [s for s in subjects if all(s[key] == scope[key]
            for key in ('component', 'boundary') if key in scope)]


def _result(rule, subject, state, reason, context, head=None, base=None):
    if subject is None and rule['scope']['kind'] == 'subject':
        subject = next(s for s in context['project']['subjects']
                       if s['id'] == rule['scope']['subject'])

    def metric(record):
        return next((m['value'] for m in record['metrics'] if m['name'] == rule['metric']),
                    None) if record else None
    detail = {
        'component': subject['component'] if subject else rule['scope'].get('component'),
        'subject': subject, 'metric': rule['metric'],
        'base': metric(base), 'head': metric(head),
        'context': context['expected'], 'policy': rule,
        'measurement_series': {'base': base['series']['id'] if base else None,
                               'head': head['series']['id'] if head else None},
        'evidence_links': {label: {'evidence_id': r['id'], 'artifacts': r['artifacts']}
                           if r else None for label, r in [('base', base), ('head', head)]},
        'remediation_classes': (rule['remediation_classes'] if state in
                                (GateState.FAIL, GateState.WARNING, GateState.INFORMATIONAL)
                                else ['repair_measurement']) if state != GateState.PASS else [],
    }
    if rule['scope']['kind'] == 'relationship':
        detail['relationship'] = contracts.relationship(context['project'],
                                                        rule['scope']['relationship'])
        detail['contract'] = head.get('contract') if head else None
    return GateResult(rule['id'], subject['id'] if subject else None, state, reason, detail)


def aggregate(policy, results):
    """Requiredness belongs to policy, never to a collector or child result."""
    evidence._shape(policy, 'policy.schema.json')
    rules = evidence._index(policy['rules'], 'id', 'policy ID')
    seen, blockers = set(), []
    for result in results:
        evidence.require(result.policy in rules, 'unknown result policy')
        key = (result.policy, result.subject)
        evidence.require(key not in seen, 'duplicate gate result')
        seen.add(key)
        state = GateState(result.state)
        if rules[result.policy]['required'] and state not in (
                GateState.PASS, GateState.INFORMATIONAL):
            blockers.append({'policy': result.policy, 'subject': result.subject, 'state': state})
    for rule in rules.values():
        if rule['required'] and not any(key[0] == rule['id'] for key in seen):
            blockers.append({'policy': rule['id'], 'subject': None, 'state': GateState.BLOCKED})
    states = {b['state'] for b in blockers}
    status = (GateState.MEASUREMENT_ERROR if GateState.MEASUREMENT_ERROR in states else
              GateState.FAIL if GateState.FAIL in states else
              GateState.BLOCKED if blockers else GateState.PASS)
    return {'state': status, 'blockers': blockers}


def evaluate(policy, records, *, selection=None, base_records=None, base_context=None,
             mappings=None, exceptions=None, now=None, **context):
    """Evaluate absolute limits and optional compatible-series debt/ratchet rules.

    Context and selections are caller-owned. Complete evidence is validated before
    any metric is used. Empty/missing scopes never produce vacuous required success.
    """
    validate_policy(policy, context['project'])
    results = []
    try:
        # A missing batch is handled per selected subject with useful remediation.
        if records:
            evidence.validate_evidence(records, **context)
        else:
            evidence.require(records == [], 'evidence must be a list')
        lineage = None
        if base_records is not None or base_context is not None or mappings is not None:
            lineage = ratchet.validate_base(base_records, base_context, context, mappings)
    except (evidence.MeasurementError, model.ModelError) as error:
        results = [_result(rule, None, GateState.MEASUREMENT_ERROR, str(error), context)
                   for rule in policy['rules']]
    else:
        for rule in policy['rules']:
            try:
                subjects = _select(rule['scope'], context['project'], selection or {},
                                   context['expected']['target'])
            except evidence.MeasurementError as error:
                results.append(_result(rule, None, GateState.MEASUREMENT_ERROR, str(error), context))
                continue
            if not subjects:
                results.append(_result(rule, None, GateState.NOT_APPLICABLE,
                                       'scope selects no subjects', context))
            for subject in subjects:
                head, base, baseline, assessment = None, None, None, None
                try:
                    candidates = records
                    if rule['scope']['kind'] == 'relationship':
                        candidates = [r for r in records if r.get('contract', {}).get(
                            'relationship', rule['scope']['relationship']) == rule['scope']['relationship']]
                    head = ratchet.metric_record(candidates, subject['id'], rule['metric'])
                    if 'ratchet' in rule:
                        evidence.require(lineage is not None, 'missing base for incremental policy')
                        base, baseline = ratchet.baseline(head, rule['metric'], base_records,
                                                          base_context, lineage)
                    elif base_records is not None:
                        prior = [r for r in base_records if r['subject']['id'] == subject['id'] and
                                 any(c['metric'] == rule['metric'] for c in r['capabilities'])]
                        evidence.require(len(prior) <= 1, 'ambiguous base evidence')
                        base = prior[0] if prior else None
                        if base:
                            evidence.require_compatible_series(base['series'], head['series'])
                    capability = next(c for c in head['capabilities'] if c['metric'] == rule['metric'])
                    state = {'unsupported': GateState.UNSUPPORTED,
                             'not_applicable': GateState.NOT_APPLICABLE,
                             'not_configured': GateState.BLOCKED,
                             'not_collected': GateState.SKIPPED,
                             'measurement_error': GateState.MEASUREMENT_ERROR}.get(capability['state'])
                    reason = capability['state']
                    if state is None:
                        value = next(m['value'] for m in head['metrics'] if m['name'] == rule['metric'])
                        if rule['scope']['kind'] == 'relationship':
                            contracts.validate(head, rule, context['project'])
                        if 'ratchet' in rule:
                            prior_value = None
                            if base:
                                base_cap = next(c for c in base['capabilities']
                                                if c['metric'] == rule['metric'])
                                evidence.require(base_cap['state'] == 'supported',
                                                 'base metric unavailable: ' + base_cap['state'])
                                prior_value = next(m['value'] for m in base['metrics']
                                                   if m['name'] == rule['metric'])
                            state, assessment = ratchet.decision(rule, value, prior_value, compare)
                            state = GateState(state)
                            reason = 'ratchet ' + assessment['trend'] + '; debt ' + assessment['debt']
                        else:
                            passed = compare(value, rule['operator'], rule['limit'])
                            state = GateState.PASS if passed else GateState(rule['on_violation'])
                            reason = 'comparison satisfied' if passed else 'policy limit violated'
                except evidence.MeasurementError as error:
                    state, reason = GateState.MEASUREMENT_ERROR, str(error)
                result = _result(rule, subject, state, reason, context, head, base)
                if baseline is not None:
                    result.record['baseline'] = baseline
                if assessment is not None:
                    result.record['ratchet'] = assessment
                results.append(result)
    review = ratchet.review_exceptions(exceptions if exceptions is not None else [],
                                      policy, context['project'], now)
    for result in results:
        matching = [item for item in review['exceptions'] if isinstance(item, dict) and
                    item.get('policy') == result.policy and item.get('subject') == result.subject
                    ] if isinstance(review['exceptions'], list) else []
        result.record['exception_review'] = {'state': review['state'] if matching else 'none',
                                             'exceptions': matching}
    quality = aggregate(policy, results)
    combined = {**quality, 'blockers': list(quality['blockers'])}
    if review['errors']:
        combined['state'] = GateState.MEASUREMENT_ERROR
        combined['blockers'].append({'state': GateState.MEASUREMENT_ERROR,
                                     'reason': 'invalid exception metadata', 'errors': review['errors']})
    return {'schema': 'harness-policy-results/v1', 'mode': 'shadow',
            'aggregate': combined, 'quality_aggregate': quality, 'exception_review': review,
            'results': [r.to_dict() for r in results],
            'debt_ledger': [r.to_dict() for r in results
                            if r.record.get('ratchet', {}).get('debt', 'none') != 'none'],
            'violations': [r.to_dict() for r in results if r.state != GateState.PASS]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('policy', 'evidence', 'project', 'source-root', 'artifact-root', 'expected', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--selection', type=Path)
    for name in ('base-evidence', 'base-project', 'base-source-root', 'base-artifact-root',
                 'base-expected', 'mappings', 'exceptions'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--reference-only', action='store_true', required=True,
                        help='Acknowledge frozen reference output cannot approve a release')
    args = parser.parse_args()
    try:
        base_paths = (args.base_evidence, args.base_project, args.base_source_root,
                      args.base_artifact_root, args.base_expected)
        evidence.require(not any(base_paths) or all(base_paths), 'incomplete base CLI context')
        base_context = {'project': evidence.load_json(args.base_project),
                        'source_root': args.base_source_root,
                        'artifact_root': args.base_artifact_root,
                        'expected': evidence.load_json(args.base_expected)} if all(base_paths) else None
        result = evaluate(evidence.load_json(args.policy), evidence.load_json(args.evidence),
                          selection=evidence.load_json(args.selection) if args.selection else None,
                          base_records=evidence.load_json(args.base_evidence) if args.base_evidence else None,
                          base_context=base_context,
                          mappings=evidence.load_json(args.mappings) if args.mappings else None,
                          exceptions=evidence.load_json(args.exceptions) if args.exceptions else None,
                          project=evidence.load_json(args.project), source_root=args.source_root,
                          artifact_root=args.artifact_root, expected=evidence.load_json(args.expected))
    except (evidence.MeasurementError, model.ModelError) as error:
        result = {'schema': 'harness-policy-results/v1', 'mode': 'shadow',
                  'aggregate': {'state': 'measurement_error'}, 'error': str(error)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return 0 if result['aggregate']['state'] == 'pass' else 1


if __name__ == '__main__':
    sys.exit(main())
