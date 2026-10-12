#!/usr/bin/env python3
"""Mandatory real-binary acceptance. Missing tools or skipped tests fail the run."""
import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
QUALITY = HERE
sys.path[:0] = [str(QUALITY), str(QUALITY / 'tests')]
import rust_native_driver as native
import rust_native_config as native_config
from test_rust_collector_project import binding_for, request_for
from sign_fixture import sign
from native_policy_fixture import prepare as prepare_policy, set_limit


class ExternalPluginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = Path(os.environ['NATIVE_PLUGIN_BINARY']).resolve(strict=True)
        cls.sysroot = Path(os.environ['NATIVE_DRIVER_SYSROOT']).resolve(strict=True)
        cls.core = Path(os.environ['HARNESS_GATE_NATIVE_POLICY_BINARY']).resolve(strict=True)
        cls.version = subprocess.check_output([str(cls.binary), '--version'], text=True).split()[1]
        parent = Path(os.environ.get('HARNESS_GATE_NATIVE_ACCEPTANCE_ROOT',
                                     QUALITY.parents[1] / 'target/native-acceptance'))
        parent.mkdir(parents=True, exist_ok=True)
        cls.work = Path(tempfile.mkdtemp(dir=parent))
        # The copied executable runs outside the source tree with isolated Python.
        cls.binary = Path(shutil.copy2(cls.binary, native.executable(cls.work, 'collector')))
        cls.environment = os.environ | {'XDG_CACHE_HOME': str(cls.work / 'cache'),
                                        'HARNESS_GATE_PYTHON': sys.executable}
        cls.environment.pop('HARNESS_GATE_NATIVE_CACHE', None)
        cls.head = cls.work / 'head'
        result = cls.command('fixture', [str(cls.binary), 'fixture', '--sysroot', str(cls.sysroot),
            '--source', str(QUALITY / 'fixtures/rust-native/driver_complete.rs'), '--output', str(cls.head)])
        if result.returncode:
            raise RuntimeError(result.stderr)
        cls.anchor = json.loads(result.stdout)['anchor']
        result = cls.command('certify', [str(cls.binary), 'certify', '--sysroot', str(cls.sysroot),
            '--evidence', str(cls.head), '--anchor', cls.anchor])
        if result.returncode:
            raise RuntimeError(result.stderr)
        cls.report = json.loads(result.stdout)['measurement']
        cls.payload = next((cls.work / 'cache/harness-gate/native').iterdir())

    @classmethod
    def command(cls, name, args, data=None, env=None):
        result = subprocess.run(args, cwd=cls.work, env=env or cls.environment, input=data,
                                capture_output=True, text=True, timeout=300)
        (cls.work / (name + '.stdout')).write_text(result.stdout)
        (cls.work / (name + '.stderr')).write_text(result.stderr)
        return result

    def entry(self, name, *args, env=None):
        return self.command(name, [str(self.binary), *map(str, args)], env=env)

    def test_old_engine_equivalence_and_generated_owners(self):
        old = native.certify(self.head, self.anchor)
        old.pop('passed', None)
        for row in old['functions']:
            row.pop('passed', None)
        self.assertEqual(self.report, old)
        rows = {row['name']: row for row in self.report['functions']}
        self.assertEqual(rows['legacy_debt']['crap_exact'], [56, 1])
        self.assertEqual(rows['future']['blocks'][0], 1)
        self.assertEqual(rows['future::{closure#0}']['blocks'][0], 0)
        self.assertGreater(rows['closure::{closure#0}']['blocks'][0], 0)
        self.assertTrue(any('clone' in name for name in rows))
        self.assertNotEqual(rows['first']['definition']['expansion'], rows['second']['definition']['expansion'])
        self.assertEqual(len(rows['generic']['instances']), 2)
        self.assertFalse(self.report['backend_complete'])
        self.assertTrue(self.report['mapping_complete_for_declared_scope'])

    def test_metadata_needs_no_python_or_cache(self):
        cache = self.work / 'metadata-must-not-create-cache'
        environment = self.environment | {'HARNESS_GATE_NATIVE_CACHE': str(cache),
                                           'HARNESS_GATE_PYTHON': str(self.work / 'absent-python')}
        for option in ('--version', '--licenses'):
            result = self.entry('metadata-' + option[2:], option, env=environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout)
            self.assertFalse(cache.exists())

    def test_real_cargo_capture_and_features(self):
        captures = []
        for features in ([], ['--feature', 'extra']):
            name = 'cargo-extra' if features else 'cargo'
            result = self.entry(name, 'capture', '--sysroot', self.sysroot,
                '--source', QUALITY / 'fixtures/rust-native/cargo-complete/Cargo.toml',
                '--sample', 'contract', '--output', self.work / name, *features)
            self.assertEqual(result.returncode, 0, result.stderr)
            capture = json.loads(result.stdout)
            captures.append(capture)
            if os.name == 'nt':
                self.assertEqual(list((self.work / name).rglob('*.ilk')), [],
                                 'Cargo measurement must not use incremental linking')
            result = self.entry(name + '-certify', 'certify', '--sysroot', self.sysroot,
                '--evidence', capture['capture'], '--anchor', capture['anchor'])
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)['measurement']
            self.assertTrue(report['backend_complete'])
            names = {row['name'] for row in report['functions']}
            self.assertIn('production', names)
            self.assertNotIn('project_owned_contract', names)
            self.assertEqual(any(n.endswith('cfg_inactive') for n in names), bool(features))
        common = ['classify', '--sysroot', self.sysroot, '--evidence', captures[0]['capture'],
                  '--anchor', captures[0]['anchor']]
        result = self.entry('classify-incomplete', *common)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report['classification_complete'])
        self.assertTrue(any(row['reason'] == 'source_not_loaded_without_selection_proof' for row in report['files']))
        result = self.entry('classify-witness', *common, '--witness', captures[1]['capture'],
                            '--witness-anchor', captures[1]['anchor'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['classification_complete'])

    def test_wrong_missing_tools_and_overrides_block(self):
        cases = [('no-sysroot', ['doctor'], 'select external Rust'),
                 ('missing-sysroot', ['doctor', '--sysroot', str(self.work / 'absent')], 'measurement_error'),
                 ('wrong-sysroot', ['doctor', '--sysroot', str(self.work)], 'missing external rustc')]
        for name, args, message in cases:
            env = self.environment.copy()
            env.pop('HARNESS_GATE_RUST_SYSROOT', None)
            result = self.entry(name, *args, env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(message, result.stderr)
        result = self.entry('bad-python', 'doctor', env=self.environment | {'HARNESS_GATE_PYTHON': '/absent/python'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('external Python', result.stderr)
        result = self.entry('override', 'capture', '--sysroot', self.sysroot,
            '--source', QUALITY / 'fixtures/rust-native/cargo-complete/Cargo.toml',
            '--sample', 'contract', '--output', self.work / 'override',
            env=self.environment | {'RUSTFLAGS': '-C opt-level=3'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unset inherited compiler override', result.stderr)
        self.assertFalse((self.work / 'override').exists())

    def test_packaged_evaluate_retains_core_debt_rules(self):
        context = {'target': 'native', 'run': 'packaged-policy', 'commit': 'a' * 40, 'base_commit': 'b' * 40}
        prepare_policy(self.work / 'configured-policy', native.certify(self.head, self.anchor), self.head, context)
        for name, value in (('base-context', context),
                            ('head-context', context | {'commit': 'c' * 40, 'base_commit': 'a' * 40}),
                            ('hotspots', [])):
            (self.work / (name + '.json')).write_text(json.dumps(value))
        output = self.work / 'packaged-policy'
        result = self.entry('packaged-policy', 'evaluate', '--sysroot', self.sysroot,
            '--base', self.head, '--base-anchor', self.anchor, '--head', self.head, '--head-anchor', self.anchor,
            '--output', output, '--harness-gate', self.core, '--project', 'native-fixture',
            '--base-context', self.work / 'base-context.json', '--head-context', self.work / 'head-context.json',
            '--hotspots', self.work / 'hotspots.json',
            '--repository-root', self.work / 'configured-policy', '--policy-binding', 'crap')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)['state'], 'fail')
        self.assertNotIn('measurement_error', result.stderr)

    def test_configured_crap_limit_changes_core_decision(self):
        # One fully covered function makes the aggregate decision unambiguous.
        source = self.work / 'one.rs'
        # Pin identical LF bytes on every host; Windows text output adds CRLF.
        source.write_bytes(b'fn main() { println!("measured"); }\n')
        capture = self.work / 'one-capture'
        result = self.entry('one-fixture', 'fixture', '--sysroot', self.sysroot, '--source', source, '--output', capture)
        self.assertEqual(result.returncode, 0, result.stderr)
        anchor = json.loads(result.stdout)['anchor']
        report = native.certify(capture, anchor)
        self.assertEqual(report['functions'][0]['crap_exact'], [1, 1])
        context = {'target': 'native', 'run': 'configured-ceiling', 'commit': 'a' * 40, 'base_commit': 'b' * 40}
        root = self.work / 'one-project'
        prepare_policy(root, report, capture, context, hotspots=['main'], component='app')
        for name, value in [('one-base', context), ('one-head', context | {'commit': 'c' * 40, 'base_commit': 'a' * 40}),
                            ('one-hotspots', ['main'])]:
            (self.work / (name + '.json')).write_text(json.dumps(value), encoding='utf-8')
        evidence = []
        for numerator, denominator, expected in [(1, 2, 'fail'), (1, 1, 'pass'), (60, 1, 'pass')]:
            with self.subTest(limit=(numerator, denominator)):
                set_limit(root, numerator, denominator)
                name = f'ceiling-{numerator}-{denominator}'
                output = self.work / name
                result = self.entry(name, 'evaluate', '--sysroot', self.sysroot,
                    '--base', capture, '--base-anchor', anchor, '--head', capture, '--head-anchor', anchor,
                    '--output', output, '--harness-gate', self.core, '--project', 'native-fixture',
                    '--base-context', self.work / 'one-base.json', '--head-context', self.work / 'one-head.json',
                    '--hotspots', self.work / 'one-hotspots.json', '--repository-root', root, '--policy-binding', 'crap')
                self.assertEqual(result.returncode, int(expected != 'pass'), result.stderr)
                evaluated = json.loads((output / 'report.json').read_text())
                self.assertEqual(evaluated['aggregate']['state'], expected)
                gate = next(g for g in evaluated['gates'].values() if g['record']['metric'] == 'risk.crap')
                self.assertEqual(gate['state'], expected)
                self.assertEqual(gate['record']['head'], {'type': 'rational', 'numerator': 1, 'denominator': 1})
                configured = json.loads((output / 'policy-binding.json').read_text())
                self.assertEqual(configured['rule']['limit']['numerator'], numerator)
                self.assertEqual(configured['component'], 'app')
                self.assertEqual(configured['config_files']['.harness-gate/policy.json'],
                                 native.file_hash(output / 'policy-inputs/.harness-gate/policy.json'))
                evidence.append(json.loads((output / 'evidence.json').read_text()))
        self.assertEqual(evidence[0], evidence[1])
        self.assertEqual(evidence[1], evidence[2])

    def evaluate_policy_fixture(self, name, root, binding='crap', project_id='native-fixture', hotspots=('legacy_debt',)):
        context = {'target': 'native', 'run': 'configured-policy', 'commit': 'a' * 40, 'base_commit': 'b' * 40}
        for suffix, value in [('base', context), ('head', context | {'commit': 'c' * 40, 'base_commit': 'a' * 40}),
                              ('hotspots', list(hotspots))]:
            (root / (suffix + '.json')).write_text(json.dumps(value), encoding='utf-8')
        output = self.work / name
        result = self.entry(name, 'evaluate', '--sysroot', self.sysroot,
            '--base', self.head, '--base-anchor', self.anchor, '--head', self.head, '--head-anchor', self.anchor,
            '--output', output, '--harness-gate', self.core, '--project', project_id,
            '--base-context', root / 'base.json', '--head-context', root / 'head.json',
            '--hotspots', root / 'hotspots.json', '--repository-root', root, '--policy-binding', binding)
        return result, output

    def policy_fixture(self, name, hotspots=('legacy_debt',)):
        root = self.work / name
        context = {'target': 'native', 'run': 'configured-policy', 'commit': 'a' * 40, 'base_commit': 'b' * 40}
        prepare_policy(root, native.certify(self.head, self.anchor), self.head, context, hotspots=hotspots)
        return root

    def test_policy_can_forbid_unchanged_legacy_debt(self):
        root = self.policy_fixture('absolute-policy-project', hotspots=())
        for allow, expected in [(True, 'informational'), (False, 'fail')]:
            set_limit(root, 30, ratchet={'deny_regression': True, 'allow_legacy_debt': allow})
            result, output = self.evaluate_policy_fixture('absolute-policy-' + str(allow), root, hotspots=())
            self.assertNotIn('measurement_error', result.stderr)
            gates = json.loads((output / 'report.json').read_text())['gates']
            gate = next(g for g in gates.values() if g['record']['metric'] == 'risk.crap'
                        and g['record']['head']['numerator'] == 56)
            self.assertEqual(gate['state'], expected)
            self.assertEqual(gate['record']['ratchet']['legacy_debt_allowed'], allow)

    def test_configuration_changed_during_core_validation_blocks(self):
        root = self.policy_fixture('mutating-policy-project')
        run = subprocess.run
        for filename in ('quality.toml', 'policy.json', 'flow.toml'):
            with self.subTest(input=filename):
                path = root / '.harness-gate' / filename
                original = path.read_bytes()
                output = self.work / ('mutating-' + filename)
                output.mkdir()

                def changed_after_validation(*args, **kwargs):
                    checked = run(*args, **kwargs)
                    self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
                    path.write_bytes(original + b'\n')
                    return checked

                try:
                    with patch.object(native_config.subprocess, 'run', side_effect=changed_after_validation):
                        with self.assertRaisesRegex(ValueError, 'inputs changed during Core validation'):
                            native_config.load(root, 'crap', 'native-fixture', self.core, output)
                    self.assertFalse((output / 'policy-binding.json').exists())
                finally:
                    path.write_bytes(original)

    def test_configured_ceiling_above_thirty_is_not_clamped(self):
        root = self.policy_fixture('large-ceiling-project')
        for numerator, denominator, expected in [(111, 2, 'fail'), (56, 1, 'pass'), (60, 1, 'pass')]:
            with self.subTest(limit=(numerator, denominator)):
                set_limit(root, numerator, denominator)
                result, output = self.evaluate_policy_fixture(f'large-ceiling-{numerator}-{denominator}', root)
                self.assertNotIn('measurement_error', result.stderr)
                gates = json.loads((output / 'report.json').read_text())['gates']
                gate = next(g for g in gates.values() if g['record']['metric'] == 'risk.crap'
                            and g['record']['head']['numerator'] == 56)
                self.assertEqual(gate['state'], expected)
                self.assertFalse(gate['record']['ratchet']['legacy_debt_allowed'])

    def test_invalid_policy_never_falls_back_to_thirty(self):
        root = self.policy_fixture('bad-policy-project')
        quality_path = root / '.harness-gate/quality.toml'
        policy_path = root / '.harness-gate/policy.json'
        quality_bytes, policy_bytes = quality_path.read_bytes(), policy_path.read_bytes()
        cases = ['missing-quality', 'missing-policy', 'unknown-binding', 'wrong-project', 'duplicate-key',
                 'duplicate-rule', 'zero-denominator', 'negative-limit', 'boolean-limit', 'extra-limit-field', 'wrong-type', 'wrong-operator',
                 'optional-rule', 'missing-ratchet', 'disabled-ratchet', 'disabled-baseline',
                 'wrong-series', 'outside-policy', 'outside-component']
        for name in cases:
            with self.subTest(case=name):
                quality_path.write_bytes(quality_bytes)
                policy_path.write_bytes(policy_bytes)
                binding, project_id = 'crap', 'native-fixture'
                document = json.loads(policy_bytes)
                rule = document['rules'][0]
                if name == 'missing-quality':
                    quality_path.unlink()
                elif name == 'missing-policy':
                    policy_path.unlink()
                elif name == 'unknown-binding':
                    binding = 'absent'
                elif name == 'wrong-project':
                    project_id = 'unrelated'
                elif name == 'duplicate-key':
                    policy_path.write_text(policy_bytes.decode().replace('"numerator": 30', '"numerator": 30, "numerator": 60'))
                elif name == 'duplicate-rule':
                    document['rules'].append(copy.deepcopy(rule))
                elif name == 'zero-denominator':
                    rule['limit']['denominator'] = 0
                elif name == 'negative-limit':
                    rule['limit']['numerator'] = -1
                elif name == 'boolean-limit':
                    rule['limit']['numerator'] = True
                elif name == 'extra-limit-field':
                    rule['limit']['fallback'] = 30
                elif name == 'wrong-type':
                    rule['limit'] = {'type': 'count', 'value': 60}
                elif name == 'wrong-operator':
                    rule['operator'] = 'gt'
                elif name == 'optional-rule':
                    rule['required'] = False
                elif name == 'missing-ratchet':
                    rule.pop('ratchet')
                elif name == 'disabled-ratchet':
                    rule['ratchet']['deny_regression'] = False
                elif name == 'disabled-baseline':
                    quality_path.write_text(quality_bytes.decode().replace('[baseline]\nrequired = true', '[baseline]\nrequired = false'))
                elif name == 'wrong-series':
                    # Replace both producer and consumer, preserving valid Core configuration.
                    quality_path.write_text(re.sub(r'measurement-series/v1:[0-9a-f]{64}',
                        'measurement-series/v1:' + 'f' * 64, quality_bytes.decode()))
                elif name == 'outside-policy':
                    quality_path.write_text(quality_bytes.decode().replace(
                        'policy_file = ".harness-gate/policy.json"', 'policy_file = "../policy.json"'))
                elif name == 'outside-component':
                    (root / 'src').mkdir(exist_ok=True)
                    quality_path.write_text(quality_bytes.decode().replace('source_roots = ["."]', 'source_roots = ["src"]'))
                if name in ('duplicate-rule', 'zero-denominator', 'negative-limit', 'boolean-limit', 'extra-limit-field', 'wrong-type',
                            'wrong-operator', 'optional-rule', 'missing-ratchet', 'disabled-ratchet'):
                    policy_path.write_text(json.dumps(document))
                result, output = self.evaluate_policy_fixture('bad-policy-' + name, root, binding, project_id)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('measurement_error', result.stderr)
                self.assertFalse((output / 'report.json').exists(), result.stderr)
        quality_path.write_bytes(quality_bytes)
        policy_path.write_bytes(policy_bytes)

    def test_modified_cache_is_never_used_or_repaired(self):
        path = self.payload / 'app/native_external.py'
        original = path.read_bytes()
        for mode in ('bytes', 'extra', 'symlink', 'permissions'):
            with self.subTest(mode=mode):
                extra = self.payload / 'app/unexpected.py'
                if mode == 'bytes':
                    path.write_bytes(original + b'\n')
                elif mode == 'extra':
                    extra.write_text('raise RuntimeError("must never run")\n')
                elif mode == 'symlink':
                    extra.symlink_to(path)
                else:
                    path.chmod(0o444)
                try:
                    result = self.entry('bad-cache-' + mode, 'doctor', '--sysroot', self.sysroot)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('native collector:', result.stderr)
                finally:
                    path.chmod(0o644)
                    path.write_bytes(original)
                    extra.unlink(missing_ok=True)

    def test_missing_corrupt_evidence_and_wrong_anchor_block(self):
        path = self.head / 'native-export.stdout'
        original = path.read_bytes()
        for mode in ('anchor', 'missing', 'corrupt'):
            if mode == 'missing':
                path.unlink()
            elif mode == 'corrupt':
                path.write_bytes(original + b' ')
            try:
                result = self.entry('bad-evidence-' + mode, 'certify', '--sysroot', self.sysroot,
                    '--evidence', self.head, '--anchor', '0' * 64 if mode == 'anchor' else self.anchor)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('measurement_error', result.stderr)
                self.assertEqual(result.stdout, '')
            finally:
                path.write_bytes(original)
        native.verified_files(self.head, self.anchor)
        output = self.head / 'unsealed-report.json'
        result = self.entry('output-inside-evidence', 'certify', '--sysroot', self.sysroot,
            '--evidence', self.head, '--anchor', self.anchor, '--output', output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('outside retained evidence', result.stderr)
        self.assertFalse(output.exists())
        native.verified_files(self.head, self.anchor)

    def test_core_authenticates_collect_and_rejects_tamper_and_replay(self):
        output = self.work / 'core'
        output.mkdir()
        artifacts = output / 'artifacts'
        artifacts.mkdir()
        # Core canonicalizes this directory before exporting its environment.
        # Exercise equivalent path spellings on Linux as well as Windows.
        binding = binding_for(self.report, self.head, artifacts / '..' / 'artifacts', self.version)
        request, _ = request_for(binding, output / 'binding.json')
        request['args'] += ['--sysroot', str(self.sysroot)]
        request['adapter'].update(executable=str(self.binary), source_digest=native.file_hash(self.binary),
            signature={'algorithm': 'ed25519', 'key_id': 'configured-test', 'value': ''})
        request.update(nonce='native-external-positive', timeout_ms=120000, issued_at_ms=int(time.time() * 1000))
        request['expires_at_ms'] = request['issued_at_ms'] + 240000
        # Core reserves HARNESS_GATE_*; its authenticated environment uses
        # standard PATH/XDG options and its own invocation marker variables.
        # Deliberately use non-sorted insertion order on every host. Core signs
        # its BTreeMap ordering, including SystemRoot on Windows.
        request['environment'] = {'XDG_CACHE_HOME': str(self.work / 'cache'),
                                  'PATH': str(Path(sys.executable).parent) + os.pathsep + os.environ['PATH']}
        if os.name == 'nt':
            request['environment']['SystemRoot'] = os.environ['SystemRoot']
        request['capabilities']['environment'] = sorted(request['environment'])
        trusted = sign(self, output, request)
        single = output / 'trusted-key.json'
        single.write_text(json.dumps(json.loads(trusted.read_text())[0]))
        command = [str(self.core), 'adapter', 'run', '--trusted-key', str(single)]
        for name in request['environment']:
            command += ['--allow-environment', name]
        path = output / 'request.json'
        tampered = copy.deepcopy(request)
        tampered['args'][-1] = '/untrusted/toolchain'
        path.write_text(json.dumps(tampered))
        result = self.command('core-tamper', command + ['--request', str(path)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('signature verification failed', result.stderr)
        self.assertEqual(list(artifacts.iterdir()), [])
        path.write_text(json.dumps(request))
        result = self.command('core-collect', command + ['--request', str(path)])
        if result.returncode:
            # Core reports the failed exit code without forwarding adapter stderr.
            # Retain a separate diagnostic under its documented environment;
            # this cannot replace the failed authenticated Core acceptance.
            canonical_root = str(artifacts.resolve(strict=True))
            if os.name == 'nt' and not canonical_root.startswith('\\\\?\\'):
                canonical_root = '\\\\?\\' + canonical_root
            self.command('core-failed-adapter-diagnostic', [str(self.binary), *request['args']],
                data=json.dumps(request), env=request['environment'] | {
                    'HARNESS_GATE_INVOCATION_ID': request['invocation_id'],
                    'HARNESS_GATE_STEP_ID': request['step_id'],
                    'HARNESS_GATE_ARTIFACT_ROOT': canonical_root})
        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertTrue(response['collection']['evidence'])
        self.assertEqual(len(response['collection']['evidence']), len(self.report['functions']))
        environment = request['environment'] | {
            'HARNESS_GATE_INVOCATION_ID': request['invocation_id'],
            'HARNESS_GATE_STEP_ID': request['step_id'],
            'HARNESS_GATE_ARTIFACT_ROOT': str(artifacts.resolve(strict=True))}
        other_root = output / 'artifacts-other'
        other_root.mkdir()
        original = {p.name: native.file_hash(p) for p in artifacts.iterdir()}
        for name, variable, value in (
                ('invocation', 'HARNESS_GATE_INVOCATION_ID', 'other-invocation'),
                ('step', 'HARNESS_GATE_STEP_ID', 'other-step'),
                ('directory', 'HARNESS_GATE_ARTIFACT_ROOT', str(other_root)),
                ('missing-directory', 'HARNESS_GATE_ARTIFACT_ROOT', None)):
            candidate = environment.copy()
            if value is None:
                candidate.pop(variable)
            else:
                candidate[variable] = value
            rejected = self.command('core-environment-' + name, [str(self.binary), *request['args']],
                                    data=json.dumps(request), env=candidate)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('Core invocation environment mismatch: ' + variable, rejected.stderr)
            self.assertEqual({p.name: native.file_hash(p) for p in artifacts.iterdir()}, original)
        other_executable = Path(os.environ['NATIVE_PLUGIN_BINARY']).resolve(strict=True)
        self.assertFalse(other_executable.samefile(self.binary))
        self.assertEqual(native.file_hash(other_executable), native.file_hash(self.binary))
        other_request = copy.deepcopy(request)
        other_request['adapter']['executable'] = str(other_executable)
        rejected = self.command('core-executable-identity', [str(self.binary), *request['args']],
                                data=json.dumps(other_request), env=environment)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn('adapter executable identity mismatch', rejected.stderr)
        self.assertEqual({p.name: native.file_hash(p) for p in artifacts.iterdir()}, original)
        result = self.command('core-replay', command + ['--request', str(path)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('nonce has already been used', result.stderr)


if __name__ == '__main__':
    for name in ('NATIVE_PLUGIN_BINARY', 'NATIVE_DRIVER', 'NATIVE_DRIVER_SYSROOT', 'HARNESS_GATE_NATIVE_POLICY_BINARY'):
        if not os.environ.get(name):
            raise SystemExit('required acceptance input is missing: ' + name)
    if not shutil.which('openssl'):
        raise SystemExit('openssl is required for real Core signature verification')
    os.environ['HARNESS_GATE_LEGACY_EXPERIMENT'] = '1'
    from test_rust_native_driver import NativeDriverTests
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
        for case in (ExternalPluginTests, NativeDriverTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print('Retained acceptance artifacts:', ExternalPluginTests.work)
    raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)
