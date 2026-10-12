"""Native facts for Core's generic project collector transport.

The host signs the invocation, including a digest-pinned capture binding. This
module neither signs requests nor accepts capture anchors or policy baselines.
Delivery authorization is a separate, mandatory precondition of collection.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import harness_evidence as evidence
import project_model as model
import rust_native_driver as native


def fingerprint(value):
    return native.digest(native_json(value))


def native_json(value):
    # Native reports contain multiline tool versions and legacy floating-point
    # display fields. Keep these in opaque raw artifacts, outside the normalized
    # evidence JSON domain; typed metrics below use only exact counts/rationals.
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _keys(value, names, label):
    evidence.require(isinstance(value, dict) and set(value) == set(names.split()),
                     'invalid ' + label + ' fields')


def validate_request(request):
    """Validate the transport shape; signature/replay validation belongs to Core."""
    _keys(request, 'protocol_version result_schema_version adapter invocation_id step_id '
          'timeout_ms config_digest artifact_root nonce issued_at_ms expires_at_ms args '
          'environment capabilities input', 'adapter request')
    evidence._json_domain(request)
    evidence.require(type(request['protocol_version']) is int and request['protocol_version'] == 2
                     and request['result_schema_version'] == '1', 'incompatible adapter protocol')
    _keys(request['adapter'], 'name version executable source_digest signature', 'adapter')
    _keys(request['adapter']['signature'], 'algorithm key_id value', 'signature')
    _keys(request['capabilities'], 'network resources environment', 'capabilities')
    for key in ('invocation_id', 'step_id', 'config_digest', 'artifact_root', 'nonce'):
        evidence.require(isinstance(request[key], str) and request[key], 'invalid ' + key)
    for key in ('timeout_ms', 'issued_at_ms', 'expires_at_ms'):
        evidence.require(type(request[key]) is int and request[key] >= 0, 'invalid ' + key)
    evidence.require(request['timeout_ms'] > 0 and request['expires_at_ms'] > request['issued_at_ms'],
                     'invalid request deadline')
    evidence.require(isinstance(request['args'], list)
                     and all(isinstance(arg, str) for arg in request['args']), 'invalid request arguments')
    evidence.require(isinstance(request['environment'], dict)
                     and all(isinstance(v, str) for v in request['environment'].values()),
                     'invalid request environment')
    for values in request['capabilities'].values():
        evidence.require(isinstance(values, list) and all(isinstance(v, str) for v in values)
                         and len(values) == len(set(values)), 'invalid execution capabilities')
    inner = request['input']
    _keys(inner, 'schema project collector context workspace_root output_root selection bindings',
          'project collector request')
    evidence.require(inner['schema'] == 'harness-project-collector-request/v1',
                     'incompatible project collector protocol')
    evidence._shape(inner['context'], definition='Context')
    evidence.require(inner['output_root'] == request['artifact_root'], 'artifact root mismatch')
    for key in ('workspace_root', 'output_root'):
        evidence.require(isinstance(inner[key], str) and Path(inner[key]).is_absolute(),
                         'absolute ' + key + ' required')
    evidence.require(inner['collector'] == {k: request['adapter'][k] for k in ('name', 'version')},
                     'collector identity mismatch')
    evidence.require(isinstance(inner['bindings'], list) and inner['bindings'], 'empty claims')
    claims = set()
    for claim in inner['bindings']:
        _keys(claim, 'subject capability series', 'producer claim')
        evidence.require(all(isinstance(v, str) and v for v in claim.values()), 'invalid producer claim')
        key = tuple(claim[k] for k in ('subject', 'capability', 'series'))
        evidence.require(key not in claims, 'duplicate producer claim')
        claims.add(key)
    return claims


def load_binding(request, path, digest):
    """Bind retained capture, context and selected owners through signed args."""
    claims = validate_request(request)
    path = Path(path)
    evidence.require(path.is_absolute() and not path.is_symlink(), 'unsafe capture binding path')
    evidence.require(request['args'] == ['collect', '--binding', str(path), '--binding-sha256', digest],
                     'capture binding differs from signed arguments')
    raw = path.read_bytes()
    evidence.require(native.digest(raw) == digest, 'capture binding digest mismatch')
    binding = json.loads(raw, object_pairs_hook=evidence._unique_object)
    evidence._shape(binding, 'rust-project-collector-binding.schema.json')
    evidence.require(binding['input'] == request['input']
                     and binding['invocation_id'] == request['invocation_id']
                     and binding['config_digest'] == request['config_digest'],
                     'stale or altered capture binding')
    model.validate_project(binding['project'])
    evidence.validate_series(binding['series'])
    evidence.require(binding['project']['id'] == request['input']['project'], 'project mismatch')
    evidence.require(binding['series']['collector'] == request['input']['collector'], 'series collector mismatch')
    selected = {claim[0] for claim in claims}
    subjects = {s['id']: s for s in binding['project']['subjects']}
    evidence.require(selected <= subjects.keys(), 'missing selected owner')
    expected = {(subject, metric['name'], binding['series']['id'])
                for subject in selected for metric in binding['series']['metrics']}
    evidence.require(claims == expected, 'incomplete or incompatible producer claims')
    for subject in selected:
        evidence.require(subjects[subject]['kind'] == 'function/v1', 'unsupported subject scope')
    metrics = [row['metric'] for row in binding['capabilities']]
    evidence.require(len(metrics) == len(set(metrics)) and set(metrics) == {c[1] for c in claims},
                     'capability contract mismatch')
    directory = Path(binding['capture']['path'])
    evidence.require(directory.is_absolute() and not directory.is_symlink(), 'unsafe native capture path')
    return binding


def measurement_identity(report):
    """Do not equate package versions, paths, or rebuilt projections with history."""
    return {'native_sha256': fingerprint({key: report[key] for key in
            ('series', 'scope', 'tools', 'flags', 'cfg', 'build_inputs', 'adapter_sha256')}),
        'projection_sha256': native.file_hash(Path(__file__))}


def project_report(report, binding):
    """Project a fully certified report; never interpret historical verdict fields.

    This stage does not authorize delivery or authenticate a capture. The caller
    must run delivery preflight and native certification before calling it.
    """
    evidence.require(report['mapping_complete_for_declared_scope'], 'incomplete native mapping')
    evidence.require(measurement_identity(report) == binding['native_identity'],
                     'incompatible native measurement identity')
    series = binding['series']
    evidence.require(series['rule']['version'] == fingerprint(binding['native_identity']),
                     'series does not bind native measurement identity')
    evidence.require(report['artifact_anchor'] == binding['capture']['anchor'], 'capture anchor mismatch')
    inner = binding['input']
    selected = {c['subject'] for c in inner['bindings']}
    functions = {}
    for function in report['functions']:
        key = fingerprint(function['owner'])
        evidence.require(key not in functions, 'duplicate native owner')
        functions[key] = function
    prefix = binding.get('source_prefix', '')
    evidence.require(isinstance(prefix, str) and
                     (not prefix or all(part not in ('', '.', '..') for part in prefix.split('/'))) and
                     not any(char in prefix for char in ('\\', ':')) and
                     not any(ord(char) < 32 for char in prefix), 'invalid package source prefix')

    def project_path(relative):
        return prefix + '/' + relative if prefix else relative

    sources = {project_path(p['relative']): p['sha256'] for p in report['source_inventory']}
    # Resolve every owner/source before creating any output. No partial success.
    rows = []
    for subject in binding['project']['subjects']:
        if subject['id'] not in selected:
            continue
        function = functions.get(subject['discriminator'])
        evidence.require(function is not None, 'missing selected native owner')
        evidence.require(subject['path'] == project_path(function['source_lines'][0][0])
                         and sources.get(subject['path']) == subject['source_sha256'],
                         'native owner/source mismatch')
        evidence._file(Path(inner['workspace_root']), subject['path'], subject['source_sha256'])
        def ratio(counts):
            return {'type': 'ratio', 'covered': counts['covered'], 'total': counts['count']}
        values = {'coverage.line': ratio(function['lines']), 'coverage.region': ratio(function['regions']),
                  'coverage.function': {'type': 'ratio', 'covered': int(function['blocks'][0] > 0), 'total': 1},
                  'complexity.cyclomatic': {'type': 'count', 'value': function['cc']},
                  'risk.crap': {'type': 'rational', 'numerator': function['crap_exact'][0],
                                'denominator': function['crap_exact'][1]}}
        for capability in binding['capabilities']:
            evidence.require(capability['state'] != 'supported' or capability['metric'] in values,
                             'unsupported metric cannot supply a value')
        rows.append((subject, values))
    evidence.require({s['id'] for s, _ in rows} == selected, 'missing selected subject')
    # Bind the complete, retained native report once. Repeating all exclusions
    # and owners in every subject artifact grows quadratically on real projects.
    report_digest = fingerprint(report)
    identity = measurement_identity(report)
    output = Path(inner['output_root'])
    evidence.require(output.is_dir() and not output.is_symlink() and not any(output.iterdir()),
                     'collector output must be an empty directory')
    records, artifacts = [], []
    for subject, values in rows:
        source = {'path': subject['path'], 'sha256': subject['source_sha256']}
        function = copy.deepcopy(functions[subject['discriminator']])
        function.pop('passed', None)
        paths = {row[0] for row in function['source_lines']}
        facts = {'schema': 'rust-native-owner-artifact/v1',
                 'source_prefix': prefix,
                 'native_report_sha256': report_digest, 'native_identity': identity,
                 'artifact_anchor': report['artifact_anchor'], 'series': report['series'],
                 'scope': report['scope'], 'tools': report['tools'],
                 'source_inventory': [p for p in report['source_inventory'] if p['relative'] in paths],
                 'functions': [function]}
        raw = native_json(facts)
        # Core binds each artifact to one source: distinct paths avoid conflicting
        # descriptors when two selected owners share the same raw capture.
        name = fingerprint(subject['id']) + '.json'
        with (output / name).open('xb') as stream:
            stream.write(raw)
        artifact = {'id': 'native', 'kind': 'raw', 'media_type': 'application/json', 'path': name,
                    'sha256': native.digest(raw), 'bytes': len(raw), 'context': inner['context'], 'source': source}
        capabilities = [c | {'artifacts': ['native']} for c in binding['capabilities']]
        states = {c['state'] for c in capabilities}
        records.append({'schema': 'harness-evidence/v1', 'id': 'native-' + fingerprint(subject['id']),
                        'project': inner['project'], 'component': subject['component'],
                        'collector': inner['collector'], 'series': series, 'subject': subject,
                        'context': inner['context'], 'source': source, 'artifacts': [artifact],
                        'capabilities': capabilities,
                        'status': 'measurement_error' if 'measurement_error' in states else
                                  'measured' if 'supported' in states else 'unavailable',
                        'metrics': [{'name': c['metric'], 'value': values[c['metric']], 'artifacts': ['native']}
                                    for c in capabilities if c['state'] == 'supported']})
        artifacts.append(artifact)
    evidence.validate_evidence(records, project=binding['project'], source_root=Path(inner['workspace_root']),
                               artifact_root=output, expected=inner['context'])
    return {'schema_version': '1', 'status': 'PASS', 'invocation_id': binding['invocation_id'],
            'artifacts': artifacts, 'collection': {'schema': 'harness-project-collector-response/v1',
                                                  'evidence': records, 'error': None}}
