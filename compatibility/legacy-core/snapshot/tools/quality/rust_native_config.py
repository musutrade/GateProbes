"""Resolve a project-owned CRAP rule; Core validates policy and owns decisions."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tomllib

import rust_native_driver as native
import project_model as model


def repository_file(root, relative):
    native.require(isinstance(relative, str) and relative and
                   not any(c in relative for c in ('\\', ':', '${')) and
                   not any(ord(c) < 32 for c in relative),
                   'policy path must be a literal repository-relative path')
    path = Path(relative)
    native.require(not path.is_absolute() and '..' not in path.parts,
                   'policy path must stay inside repository')
    resolved = (root / path).resolve(strict=True)
    native.require(resolved.is_relative_to(root) and resolved.is_file(),
                   'policy path must be a file inside repository')
    return resolved


def load(repository_root, binding_name, project_id, binary, output):
    """No implicit default: a missing or invalid configured rule always blocks."""
    root = Path(repository_root).resolve(strict=True)
    quality_path = repository_file(root, '.harness-gate/quality.toml')
    quality_bytes = quality_path.read_bytes()
    config = tomllib.loads(quality_bytes.decode('utf-8'))
    native.require(config['project']['id'] == project_id, 'quality project id differs from --project')
    native.require(binding_name in config['policies'], 'unknown CRAP policy binding: ' + binding_name)
    binding = config['policies'][binding_name]
    expectation = binding['expectation']
    native.require(expectation['capability'] == 'risk.crap' and expectation['target']['kind'] == 'component',
                   'native evaluate requires a component risk.crap policy binding')
    component = expectation['target']['id']
    native.require(component in config['components'], 'unknown native policy component')
    # This command evaluates one anchored native capture, not an entire profile.
    # Require the caller to select its binding explicitly; never choose the first.
    policy_path = repository_file(root, binding['policy_file'])
    policy_bytes = policy_path.read_bytes()
    flow_path = repository_file(root, '.harness-gate/flow.toml')
    flow_bytes = flow_path.read_bytes()
    command = [str(Path(binary).resolve()), 'config', 'check', '--project-root', str(root), '--format', 'json']
    checked = subprocess.run(command, capture_output=True, text=True)
    (output / 'config-check.stdout').write_text(checked.stdout, encoding='utf-8')
    (output / 'config-check.stderr').write_text(checked.stderr, encoding='utf-8')
    native.write_json(output / 'config-check.command.json', {'command': command, 'exit_code': checked.returncode})
    native.require(checked.returncode == 0, 'Core rejected project configuration; see config-check.stdout/stderr')
    snapshots = [('.harness-gate/quality.toml', quality_path, quality_bytes),
                 (binding['policy_file'], policy_path, policy_bytes),
                 ('.harness-gate/flow.toml', flow_path, flow_bytes)]
    for relative, path, contents in snapshots:
        native.require(repository_file(root, relative) == path and path.read_bytes() == contents,
                       'project policy inputs changed during Core validation')
        retained = output / 'policy-inputs' / relative
        retained.parent.mkdir(parents=True, exist_ok=True)
        retained.write_bytes(contents)
    # Core's strict parser has already rejected duplicate JSON keys and rule IDs.
    document = json.loads(policy_bytes)
    rules = [r for r in document['rules'] if r['id'] == binding['rule']]
    native.require(len(rules) == 1, 'missing or ambiguous configured CRAP rule')
    rule = rules[0]
    native.require(rule['operator'] == 'le' and rule['limit']['type'] == 'rational',
                   'native CRAP ceiling requires operator le and a rational limit')
    # Resolve the explicit value definition: the generic policy shape's oneOf
    # is not traversed by the frozen schema walker. This validates input shape,
    # never compares a measured value or decides a gate.
    model.validate_shape(rule['limit'], 'policy.schema.json', 'Rational')
    native.require(rule['required'] and rule['on_violation'] == 'fail',
                   'native CRAP gate requires required=true and on_violation=fail')
    native.require(rule.get('ratchet', {}).get('deny_regression', False),
                   'native CRAP gate requires an explicit ratchet with deny_regression=true')
    receipt = {'schema': 'rust-native-policy-binding/v1', 'repository_root': str(root),
               'binding': binding_name, 'component': component, 'expectation': expectation,
               'source_roots': config['components'][component]['source_roots'],
               'policy_file': binding['policy_file'], 'rule': rule,
               'config_files': {name: native.digest(contents) for name, _, contents in snapshots},
               'assurance': 'selected-native-capture'}
    native.write_json(output / 'policy-binding.json', receipt)
    return receipt


def require_series(binding, projections):
    expected = binding['expectation']['series']
    for projection in projections:
        actual = {row['series']['id'] for row in projection['evidence']
                  if any(m['name'] == 'risk.crap' for m in row['metrics'])}
        native.require(actual == {expected},
                       'configured CRAP measurement series differs from native projection: ' +
                       json.dumps({'configured': expected, 'measured': sorted(actual)}))


def require_scope(binding, reports):
    roots = [Path(p) for p in binding['source_roots']]
    for report in reports:
        outside = [row['relative'] for row in report['source_inventory']
                   if not any(Path(row['relative']).is_relative_to(root) for root in roots)]
        native.require(not outside, 'native capture is outside configured component source_roots: ' + json.dumps(outside))
