"""Frozen non-authoritative Python reference; see docs/quality/python-retention.md.

Generic decisions belong to the released Rust core. No release-approval path.

Baseline identity and review metadata for the generic shadow policy engine."""
from datetime import datetime, timezone

import harness_evidence as evidence
import project_model as model


def validate_base(records, context, head_context, mappings):
    evidence.require(records is not None and context is not None,
                     'missing base evidence or validation context')
    evidence.require(context['project']['id'] == head_context['project']['id'],
                     'base/head project mismatch')
    evidence.require(context['expected']['commit'] == head_context['expected']['base_commit'],
                     'base commit does not match head provenance')
    evidence.require(context['expected']['target'] == head_context['expected']['target'],
                     'base/head target mismatch')
    evidence.validate_evidence(records, **context)
    mappings = mappings if mappings is not None else {
        'schema': 'subject-mappings/v1', 'project': context['project']['id'], 'mappings': []}
    resolved = model.validate_mappings(context['project'], head_context['project'], mappings)
    kinds = {destination: mapping['kind'] for mapping in mappings['mappings']
             for destination in mapping['to']}
    return resolved, kinds


def metric_record(records, identity, metric):
    matching = [r for r in records if r['subject']['id'] == identity and
                any(c['metric'] == metric for c in r['capabilities'])]
    evidence.require(len(matching) == 1, 'missing or ambiguous subject metric evidence')
    return matching[0]


def baseline(head, metric, records, context, lineage):
    """Only exact IDs and explicit one-to-one mappings inherit historical values."""
    identity = head['subject']['id']
    resolved, kinds = lineage
    old_ids = {s['id'] for s in context['project']['subjects']}
    prior_id = identity if identity in old_ids else resolved.get(identity)
    kind = kinds.get(identity)
    classification = 'unchanged' if identity in old_ids else (
        'modified' if prior_id and kind != 'split' else 'new')
    prior = metric_record(records, prior_id, metric) if prior_id else None
    if prior:
        evidence.require_compatible_series(prior['series'], head['series'])
    else:
        # A new identity still needs a compatible measurement series at base.
        evidence.require(any(r['component'] == head['component'] and
                             r['series'] == head['series'] for r in records),
                         'missing compatible base series for new subject')
    return (prior if kind != 'split' else None), {
        'classification': classification, 'lineage_kind': kind,
        'lineage_base_subject': prior_id, 'inherits_history': prior is not None and kind != 'split'}


def decision(rule, head, base, compare):
    """Record absolute compliance independently from permission to retain debt."""
    absolute = compare(head, rule['operator'], rule['limit'])
    base_pass = compare(base, rule['operator'], rule['limit']) if base else None
    if base is None:
        trend = 'new'
    elif compare(head, 'eq', base):
        trend = 'unchanged'
    elif rule['operator'] in ('lt', 'le', 'gt', 'ge'):
        better = 'lt' if rule['operator'] in ('lt', 'le') else 'gt'
        trend = 'improved' if compare(head, better, base) else 'regressed'
    else:
        # Equality/inequality policies order compliance, not arbitrary numbers.
        trend = ('improved' if absolute else 'regressed') if absolute != base_pass else 'unchanged'
    debt = ('resolved' if base_pass is False else 'none') if absolute else (
        trend if base_pass is False else 'new')
    options = rule['ratchet']
    regression = trend == 'regressed'
    legacy_allowed = (not absolute and base_pass is False and not regression and
                      options['allow_legacy_debt'])
    violated = (not absolute and not legacy_allowed) or (regression and options['deny_regression'])
    state = rule['on_violation'] if violated else 'informational' if legacy_allowed else 'pass'
    return state, {'absolute_compliant': absolute, 'base_absolute_compliant': base_pass,
                   'trend': trend, 'debt': debt, 'remaining_debt': not absolute,
                   'regression': regression, 'legacy_debt_allowed': legacy_allowed}


def review_exceptions(exceptions, policy, project, now=None):
    """Review metadata cannot change quality results or authorize a waiver."""
    errors, seen = [], set()
    try:
        evidence._shape(exceptions, 'policy-exceptions.schema.json')
        policies = {r['id'] for r in policy['rules']}
        subjects = {s['id'] for s in project['subjects']}
        now = now if now is not None else datetime.now(timezone.utc)
        evidence.require(now.tzinfo is not None, 'exception clock must have timezone')
        for item in exceptions:
            evidence.require(all(v.strip() for v in item.values()), 'empty exception metadata')
            key = (item['policy'], item['subject'])
            evidence.require(key not in seen, 'duplicate policy/subject exception')
            seen.add(key)
            evidence.require(item['policy'] in policies and item['subject'] in subjects,
                             'unknown exception policy or subject')
            expiry = datetime.fromisoformat(item['expiry'].replace('Z', '+00:00'))
            evidence.require(expiry.tzinfo is not None, 'exception expiry must have timezone')
            evidence.require(expiry > now, 'expired exception')
    except (evidence.MeasurementError, ValueError) as error:
        errors.append(str(error))
    return {'state': 'invalid' if errors else 'documented' if exceptions else 'none',
            'exceptions': exceptions, 'errors': errors}
