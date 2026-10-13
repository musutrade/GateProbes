#!/usr/bin/env python3
"""Scoped file evidence derived from complete native mapping, never a gate waiver."""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import json
from pathlib import Path

import rust_native_driver as native

SCHEMA = 'rust-native-file-classification/1'


def json_hash(value):
    return native.digest(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def read_json(path):
    data = Path(path).read_bytes()
    return json.loads(gzip.decompress(data) if data.startswith(b'\x1f\x8b') else data)


def inventory_identity(report):
    return sorted((s['relative'], s['sha256']) for s in report['source_inventory'])


def load_evidence(directory, anchor, reviewed_report=None, report_sha256=None):
    """Fresh certification or explicitly anchored inspection of accepted raw evidence.

    Archive mode never touches recorded external tool/binary paths. It requires a
    separately reviewed report hash as well as the original manifest anchor.
    """
    directory = Path(directory).resolve()
    if reviewed_report is None:
        report = native.certify(directory, anchor)
        mode, missing = 'native-reexport', []
    else:
        native.require(report_sha256 and native.file_hash(reviewed_report) == report_sha256,
                       'untrusted reviewed report')
        native.require(native.file_hash(directory / 'manifest.json') == anchor, 'untrusted manifest')
        manifest = read_json(directory / 'manifest.json')
        native.require(manifest['schema'] == 'native-driver-artifacts/1', 'incompatible manifest')
        native.require(not any(p.is_symlink() for p in directory.rglob('*')), 'artifact symlink')
        actual = {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()}
        native.require(actual <= set(manifest['artifacts']) | {'manifest.json'}, 'extra evidence file')
        missing = []
        for name, expected in manifest['artifacts'].items():
            native.require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'artifact path escape')
            path = directory / name
            if not path.is_file():
                missing.append(name)
            else:
                native.require(native.file_hash(path) == expected, 'artifact tampering: ' + name)
        capture = read_json(directory / 'capture.json')
        native.require(set(missing) <= set(capture['binaries']), 'missing non-binary evidence')
        native.require(set(capture['binaries'] + capture['profiles']) <= manifest['artifacts'].keys(),
                       'unsealed binary/profile')
        native.require(capture['scope'] == 'cargo-production-targets', 'archive requires complete Cargo scope')
        metadata = read_json(directory / 'metadata.stdout')
        messages = [json.loads(line) for line in (directory / 'cargo.stdout').read_text().splitlines()]
        selection = native.cargo_selection(directory, metadata, messages, Path(capture['manifest_path']), replay=True)
        native.require(selection == (capture['units'], capture['production_sources'], capture['dependency_exclusions']),
                       'production/test/dependency selection differs from Cargo evidence')
        native.require(capture['flags'] == native.FLAGS, 'incompatible flags')
        native.require(capture['cfg'] == native.cargo_configuration(
            directory, capture['units'], capture['tools'], capture['cfg']['samples']), 'configuration mismatch')
        native.require(capture['cargo_inputs'] == native.cargo_inputs(directory, metadata, replay=True),
                       'Cargo input mismatch')
        units = [u | {'inventory': read_json(directory / u['inventory'])} for u in capture['units']]
        mapped = native.map_native(units, read_json(directory / 'native-export.stdout'),
                                   capture['production_sources'], capture['dependency_exclusions'])
        report = read_json(reviewed_report)
        native.require(report['artifact_anchor'] == anchor and report['mapping_complete_for_declared_scope']
                       and report['backend_complete'], 'reviewed report lacks complete mapping')
        for key, value in mapped.items():
            retained = report[key]
            if key == 'functions':
                retained = [{k: v for k, v in row.items() if k != 'syntax_sha256'} for row in retained]
            native.require(value == retained, 'reviewed mapping differs: ' + key)
        for key in ('scope', 'cfg', 'flags'):
            native.require(report[key] == capture[key], 'reviewed identity differs: ' + key)
        native.require(report['tools'] == {k: {a: b for a, b in v.items() if a != 'path'}
                                          for k, v in capture['tools'].items()}, 'reviewed tools differ')
        native.require(report['build_inputs'] == [{'sha256': p['sha256'], 'name': Path(p['original']).name}
                                                for p in capture['cargo_inputs']], 'reviewed Cargo inputs differ')
        mode = 'reviewed-archive-replay'
    native.require(report['series'] == native.SERIES, 'incompatible measurement series')
    capture = read_json(directory / 'capture.json')
    units = [u | {'inventory': read_json(directory / u['inventory'])} for u in capture['units']]
    return {'report': report, 'capture': capture, 'units': units, 'mode': mode,
            'missing_binaries': missing, 'directory': directory}


def compatible_witness(current, witness):
    """Only a real alternate feature/cfg compilation of identical inputs explains exclusion."""
    a, b = current['report'], witness['report']
    for key in ('series', 'tools', 'flags', 'scope', 'build_inputs', 'adapter_sha256'):
        native.require(a[key] == b[key], 'incompatible configuration witness: ' + key)
    native.require(inventory_identity(a) == inventory_identity(b), 'incompatible witness source inventory')
    native.require(isinstance(a['cfg'], dict) and isinstance(b['cfg'], dict), 'witness requires Cargo configuration')
    native.require(a['cfg']['samples'] == b['cfg']['samples'], 'incompatible witness sample selection')
    def stable_units(cfg):
        return [{k: v for k, v in u.items() if k not in ('cfg', 'features')} for u in cfg['units']]
    native.require(stable_units(a['cfg']) == stable_units(b['cfg']), 'incompatible witness target/codegen selection')
    # Target facts and non-feature cfg must match; only selected Cargo features vary.
    def non_features(cfg):
        return [[c for c in u['cfg'] if not c.startswith('feature=')] for u in cfg['units']]
    native.require(non_features(a['cfg']) == non_features(b['cfg']), 'incompatible witness target cfg')
    native.require(a['cfg'] != b['cfg'], 'witness must select different features')


def classify(evidence, witness=None):
    report, capture, units = (evidence[k] for k in ('report', 'capture', 'units'))
    native.require(report['series'] == native.SERIES and report['mapping_complete_for_declared_scope'],
                   'complete compatible mapping required')
    if witness:
        compatible_witness(evidence, witness)
    identity = {k: report[k] for k in ('series', 'scope', 'tools', 'flags', 'cfg', 'build_inputs', 'artifact_anchor')}
    identity.update(inventory_sha256=json_hash(inventory_identity(report)),
                    classifier_sha256=native.file_hash(Path(__file__)), adapter_sha256=report['adapter_sha256'])
    identity_sha = json_hash(identity)
    definitions = {(u['id'], d['id']): d for u in units for d in u['inventory']['definitions']}
    rows = []
    for source in report['source_inventory']:
        path = source['relative']
        loaded = sorted({u['id'] for u in units if u['production'] for s in u['inventory']['sources']
                         if s['source'] is not None and
                         capture['production_sources'].get(native.source_key(s['file'], u['cwd']), {}).get('relative') == path})
        defs = [d for d in report['definition_inventory'] if d['production_target']
                and any(p == path for p, _ in d['source_lines'])]
        runtime_ids = {d['id'] for d in defs if d['role'] == 'runtime'}
        owners = [f for f in report['functions'] if f['owner'] in runtime_ids or
                  any(p == path for p, _ in f['source_lines'])]
        row = source | {'identity_sha256': identity_sha, 'local_production_units': loaded,
                        'status': 'measurement_error', 'reason': 'source_not_loaded_without_selection_proof',
                        'definitions': [d | {'span': definitions[d['unit'], d['id']]['span']} for d in defs],
                        'owners': [{k: f[k] for k in ('owner', 'unit', 'name', 'kind', 'definition', 'instances', 'blocks', 'source_lines')}
                                   for f in owners], 'metrics': None}
        alternate = [] if not witness else [f['owner'] for f in witness['report']['functions']
                                            if any(p == path for p, _ in f['source_lines'])]
        if owners:
            native.require(all(f['instances'] and f['blocks'] for f in owners), 'runtime owner lacks counters')
            row.update(status='measured', reason='runtime_code',
                       execution='zero_hits' if all(c == 0 for f in owners for c in f['blocks']) else 'observed_hits')
            # Owner counters are retained as owner metrics, not fabricated file line coverage.
            row['metrics'] = {'owner_regions': {'count': sum(len(f['blocks']) for f in owners),
                                               'covered': sum(c > 0 for f in owners for c in f['blocks'])}}
            row['generated_runtime'] = any(f['definition'].get('expansion') for f in owners)
        elif alternate:
            row.update(status='not_applicable', reason='outside_selected_feature_configuration',
                       selection_witness={'anchor': witness['report']['artifact_anchor'],
                                          'cfg': witness['report']['cfg'], 'runtime_owners': alternate},
                       scope='declared compilation only; executable under witness features')
        elif loaded:
            roles = Counter(d['role'] for d in defs)
            row.update(status='not_applicable', reason='compile_time_definitions_only' if roles['compile-time']
                       else 'declarations_only', scope='declared compilation only', definition_roles=dict(roles))
        rows.append(row)
    return {'schema': SCHEMA, 'identity': identity, 'identity_sha256': identity_sha,
            'verification': {'mode': evidence['mode'], 'missing_original_binaries': evidence['missing_binaries'],
                             'native_reexport_performed': evidence['mode'] == 'native-reexport'},
            'files': rows, 'counts': dict(Counter(r['status'] for r in rows)),
            'classification_complete': all(r['status'] != 'measurement_error' for r in rows),
            'coverage': report['coverage'], 'measurement_passed': report['passed'], 'baseline_accepted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--anchor', required=True)
    parser.add_argument('--reviewed-report', type=Path)
    parser.add_argument('--report-sha256')
    parser.add_argument('--witness', type=Path)
    parser.add_argument('--witness-anchor')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        native.require(bool(args.reviewed_report) == bool(args.report_sha256), 'archive report and hash required together')
        native.require(bool(args.witness) == bool(args.witness_anchor), 'witness and anchor required together')
        evidence = load_evidence(args.evidence, args.anchor, args.reviewed_report, args.report_sha256)
        witness = load_evidence(args.witness, args.witness_anchor) if args.witness else None
        result = classify(evidence, witness)
    except (ValueError, KeyError, OSError, TypeError) as exc:
        # The list is explicitly unverified on failure, never an absence waiver.
        try:
            sources = read_json(args.evidence / 'capture.json').get('production_sources', {})
            sources = [s for s in sources.values() if isinstance(s, dict)]
        except (ValueError, OSError, AttributeError):
            sources = []
        result = {'schema': SCHEMA, 'classification_complete': False, 'status': 'measurement_error',
                  'error': str(exc), 'inventory_verified': False,
                  'files': [s | {'status': 'measurement_error', 'metrics': None} for s in sources]}
    native.write_json(args.output, result)
    print(json.dumps({k: result[k] for k in ('classification_complete', 'counts', 'error') if k in result}))
    return 0 if result['classification_complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
