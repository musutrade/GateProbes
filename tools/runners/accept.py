#!/usr/bin/env python3
"""Execute a fixed external Cargo definition with an explicit candidate Core.

Uses a temporary Rust crate and a Cargo forwarding shim to compare the exact
argv executed against RunnerExecution. No Core build or production data writes.
Requires Python 3.11+, Cargo, and a POSIX host.
"""
import argparse
import copy
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

from migrate import DEFAULT_DEFINITION, migrate, render


def run(command, **kwargs):
    return subprocess.run(command, text=True, capture_output=True, **kwargs)


def accept(core):
    cargo = shutil.which('cargo')
    if cargo is None:
        raise ValueError('Cargo is required')
    definition = tomllib.loads(DEFAULT_DEFINITION.read_text())
    records = []
    with tempfile.TemporaryDirectory(prefix='gateprobes-runner-') as temporary:
        root = Path(temporary)
        command = [str(core), '--project-root', str(root)]
        subprocess.run(command + ['init', '--preset', 'generic'], check=True, capture_output=True)
        subprocess.run(['git', 'init', str(root)], check=True, capture_output=True)
        (root / 'src').mkdir()
        (root / 'Cargo.toml').write_text('[package]\nname="runner-fixture"\nversion="0.1.0"\nedition="2021"\n')
        (root / 'src/lib.rs').write_text('#[test] fn fixture_test() { assert_eq!(2 + 2, 4); }\n')
        shim = root / 'shim'
        shim.mkdir()
        # Shell only launches Python; executable and paths are encoded as data.
        (shim / 'capture.py').write_text('import json,os,sys\nfrom pathlib import Path\n'
            'Path(os.environ["ARGV_CAPTURE"]).write_text(json.dumps(sys.argv[1:]))\n'
            'os.execv(os.environ["REAL_CARGO"], [os.environ["REAL_CARGO"], *sys.argv[1:]])\n')
        (shim / 'cargo').write_text('#!/bin/sh\nexec python3 "' + str(shim / 'capture.py') + '" "$@"\n')
        (shim / 'cargo').chmod(0o755)
        environment = dict(os.environ, PATH=str(shim) + os.pathsep + os.environ['PATH'],
                           REAL_CARGO=cargo, ARGV_CAPTURE=str(root / 'argv.json'),
                           CARGO_TARGET_DIR=str(root / 'build'))
        legacy = {
            'version': 2,
            'project': {'name': 'runner-fixture', 'default_profile': 'full', 'hook_profile': 'hook'},
            'paths': {'reports': '.harness-gate/reports', 'audit_config': '.harness-gate/audit.toml', 'secrets_config': '.harness-gate/secrets.toml'},
            'policy': {'required_steps': ['tests']},
            'parsers': {'rust': {'kind': 'regex', 'patterns': ['(?m)^running ([0-9]+) tests?$'], 'capture': 1, 'minimum': 1}},
            'scope': {'unmatched': 'all', 'rules': [{'patterns': ['**'], 'components': ['project']}]},
            'steps': [{'id': 'tests', 'label': 'tests', 'component': 'project', 'profiles': ['full', 'hook'],
                       'program': 'cargo', 'args': ['test', '--offline', '--lib'], 'cwd': '{root}',
                       'log': 'tests.log', 'timeout_secs': 30, 'parser': 'rust', 'input': 'repository',
                       'runner': {'version': 1, 'kind': 'cargo-test', 'threads': 1, 'isolation': 'shared'}}]
        }
        flow_path = root / '.harness-gate/flow.toml'
        # These expected arrays are independent of the migration implementation.
        for case, step_args, runner_args, position, expected, success in [
            ('append-separator', ['test', '--offline', '--lib'], [], None,
             ['test', '--offline', '--lib', '--', '--test-threads', '1'], True),
            ('existing-separator', ['test', '--offline', '--lib', '--', '--nocapture'], [], None,
             ['test', '--offline', '--lib', '--', '--test-threads', '1', '--nocapture'], True),
            ('positioned-args', ['test', '--offline', '--lib', '--'], ['--nocapture'], 4,
             ['test', '--offline', '--lib', '--', '--test-threads', '1', '--nocapture'], True),
            ('user-conflict', ['test', '--offline', '--lib', '--', '--test-threads=7'], [], None,
             ['test', '--offline', '--lib', '--', '--test-threads', '1', '--test-threads=7'], False),
        ]:
            flow = copy.deepcopy(legacy)
            step = flow['steps'][0]
            step['args'] = step_args
            step['runner']['args'] = runner_args
            if position is not None:
                step['runner']['args_position'] = position
            flow_path.write_text(render(migrate(flow, definition)))
            output = run(command + ['verify', '--all'], env=environment)
            assert (output.returncode == 0) == success, (case, output.stdout, output.stderr)
            report = json.loads((root / '.harness-gate/reports/test_result.json').read_text())
            row = next(step for step in report['steps'] if step['step_id'] == 'tests')
            assert json.loads((root / 'argv.json').read_text()) == expected, case
            assert row['runner']['effective_args'] == expected, case
            assert row['runner']['version'] == 2, case
            assert report['passed'] == success, case
            if success:
                assert row['parser']['observed'] == 1, row
            records.append({'case': case, 'args': expected, 'passed': success})
        # Change external definition and ID and run the exact same binary.
        alternate = copy.deepcopy(definition)
        alternate['threads_args'] += ['--nocapture']
        flow = migrate(legacy, alternate)
        flow['steps'][0]['runner'].update(kind='unknown-external-runner', threads=4, isolation='schema-per-worker')
        flow_path.write_text(render(flow))
        output = run(command + ['verify', '--all'], env=environment)
        assert output.returncode == 0, (output.stdout, output.stderr)
        report = json.loads((root / '.harness-gate/reports/test_result.json').read_text())
        row = next(step for step in report['steps'] if step['step_id'] == 'tests')
        expected = ['test', '--offline', '--lib', '--', '--test-threads', '4', '--nocapture']
        assert row['runner']['effective_args'] == json.loads((root / 'argv.json').read_text()) == expected
        assert row['runner']['threads'] == 4
        assert len(row['runner']['worker_ids']) == 4
        assert row['parser']['observed'] == 1
        records.append({'case': 'changed-definition-unknown-id', 'args': expected, 'passed': True})
        for case, mutate in [
            ('legacy-version', lambda f: f['steps'][0]['runner'].update(version=1)),
            ('wrong-program', lambda f: f['steps'][0].update(program='sh')),
            ('zero-threads', lambda f: f['steps'][0]['runner'].update(threads=0)),
            ('over-budget', lambda f: f['steps'][0]['runner'].update(threads=257)),
            ('shared-multiple-workers', lambda f: f['steps'][0]['runner'].update(threads=4)),
            ('missing-injection', lambda f: f['steps'][0]['runner'].update(threads=4, isolation='schema-per-worker', threads_args=[], threads_args_after=None)),
        ]:
            flow = migrate(legacy, definition)
            mutate(flow)
            # TOML has no null, so remove the optional field entirely.
            if flow['steps'][0]['runner'].get('threads_args_after', '') is None:
                del flow['steps'][0]['runner']['threads_args_after']
            flow_path.write_text(render(flow))
            captured = (root / 'argv.json').read_bytes()
            output = run(command + ['config', 'check'], env=environment)
            assert output.returncode != 0, case
            assert (root / 'argv.json').read_bytes() == captured, case
            records.append({'case': case, 'rejected': True})
    return {'core_sha256': hashlib.sha256(core.read_bytes()).hexdigest(),
            'definition_sha256': hashlib.sha256(DEFAULT_DEFINITION.read_bytes()).hexdigest(),
            'cases': records}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(accept(args.core.resolve(strict=True)), indent=2))
