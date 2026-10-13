"""Frozen non-authoritative Python reference; see docs/quality/python-retention.md.

Generic decisions belong to the released Rust core. No release-approval path.

Tool-independent contract bindings over already validated normalized evidence."""
import harness_evidence as evidence


def relationship(project, identity):
    matches = [r for r in project['relationships'] if r['id'] == identity]
    evidence.require(len(matches) == 1, 'unknown contract relationship')
    return matches[0]


def subjects(project, identity, target=None):
    link = relationship(project, identity)
    selected = [s for s in project['subjects'] if s['id'] in link['subjects']
                and s['kind'] == 'contract/v1'
                and (target is None or s['target'] == target)]
    evidence.require(bool(selected), 'relationship has no contract subject for target')
    evidence.require(all(s['component'] == link['producer'] for s in selected),
                     'contract must belong to relationship provider')
    return selected


def validate(record, rule, project):
    """Validate provenance before a supported contract metric can be compared.

    Raw files have already been digest checked by harness_evidence. A baseline
    artifact is the retained base contract; its outer context describes this
    comparison run, while baseline.commit records the caller-pinned base commit.
    """
    identity = rule['scope']['relationship']
    link = relationship(project, identity)
    binding = record.get('contract')
    evidence.require(binding is not None, 'missing contract provenance')
    evidence.require(binding['relationship'] == identity and
                     binding['producer'] == link['producer'] and
                     binding['consumer'] == link['consumer'], 'contract participants mismatch')
    evidence.require(record['subject'] in subjects(project, identity),
                     'contract subject mismatch')
    metric = next(m for m in record['metrics'] if m['name'] == rule['metric'])
    artifacts = {a['id']: a for a in record['artifacts']}

    def artifact(identity):
        evidence.require(identity in artifacts and identity in metric['artifacts'],
                         'missing required contract artifact: ' + identity)
        return artifacts[identity]

    contract = artifact(binding['contract_artifact'])
    evidence.require(contract['sha256'] == record['source']['sha256'],
                     'contract artifact/source digest mismatch')
    if rule['metric'] in ('contract.breaking_changes', 'contract.compatible'):
        baseline = binding.get('baseline')
        evidence.require(baseline is not None, 'missing contract baseline')
        artifact(baseline['artifact'])
        evidence.require(baseline['commit'] == record['context']['base_commit'],
                         'stale contract baseline commit')
        evidence.require(baseline['series_id'] == record['series']['id'],
                         'incompatible contract baseline series')
    if rule['metric'] == 'contract.compatible':
        evidence.require('consumer_artifact' in binding, 'missing consumer expectation')
        artifact(binding['consumer_artifact'])
    if rule['metric'] == 'contract.client_drift':
        client = binding.get('generated_client')
        evidence.require(client is not None, 'missing generated-client evidence')
        artifact(client['artifact'])
        evidence.require(metric['value']['value'] ==
                         (client['contract_sha256'] != contract['sha256']),
                         'generated-client drift contradicts contract digest')
