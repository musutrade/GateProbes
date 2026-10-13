"""Standalone positives use real private tools; failures keep their original bytes."""
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

QUALITY = Path(__file__).resolve().parents[1]
ROOT = QUALITY.parents[1]
sys.path.insert(0, str(QUALITY))
import build_rust_collector as builder
import rust_native_policy as policy
from native_policy_fixture import CRAP_RULE


class BuildInputTests(unittest.TestCase):
    def test_changed_source_and_unsafe_destination_reject_before_assembly(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.write_text('original')
            lock = {'schema': 'rust-collector-build-inputs/1', 'build_inputs': {},
                    'files': {'../escape': {'source': str(source), 'sha256': builder.sha(source), 'mode': 0o644}}}
            with self.assertRaisesRegex(ValueError, 'unsafe payload'):
                builder.build(lock, root / 'output')
            self.assertFalse((root / 'output').exists())
            lock['files'] = {'file': lock['files']['../escape']}
            source.write_text('changed')
            with self.assertRaisesRegex(ValueError, 'changed build input'):
                builder.build(lock, root / 'output')
            self.assertFalse((root / 'output').exists())


class InstalledLayoutTests(unittest.TestCase):
    """The assembled runtime resolves host contracts without a source checkout."""

    def test_installed_runtime_resolves_the_host_contract_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / 'runtime'
            app = runtime / 'app'
            (app / 'schema').mkdir(parents=True)
            for name in builder.MODULES:
                shutil.copyfile(QUALITY / (name + '.py'), app / (name + '.py'))
            for filename, destination in builder.HOST_SCHEMA_FILES.items():
                source = builder.ROOT.parents[1] / 'schema' / filename
                self.assertTrue(source.is_file(), source)
                shutil.copyfile(source, runtime / destination)
            request = {'schema': 'harness-collector-request/v1', 'project': 'project',
                       'component': 'component', 'collector': {'name': 'collector', 'version': '1'},
                       'context': {'commit': 'a' * 40}, 'requested_capabilities': ['coverage.line'],
                       'workspace_root': '/workspace', 'output_root': '/output', 'parameters': {}}
            code = ('import json, sys; sys.path.insert(0, sys.argv[1]); '
                    'import collector_runner as runner; '
                    'runner._shape(json.loads(sys.argv[2]), "Request"); print("installed-layout ok")')
            result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', code, str(app),
                                     json.dumps(request)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('installed-layout ok', result.stdout)


class StandaloneNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime = os.environ.get('RUST_COLLECTOR_RUNTIME')
        if not runtime:
            raise unittest.SkipTest('RUST_COLLECTOR_RUNTIME required: assembled private Linux runtime')
        cls.runtime = Path(runtime).resolve(strict=True)
        base = Path(os.environ.get('RUST_COLLECTOR_TEST_OUTPUT', ROOT / 'target/gh-230/runtime-tests'))
        base.mkdir(parents=True, exist_ok=True)
        cls.work = Path(tempfile.mkdtemp(dir=base))
        cls.command_index = 0
        (cls.work / 'commands').mkdir()
        (cls.work / 'tmp').mkdir()
        (cls.work / 'cargo-home').mkdir()
        cls.environment = {'PATH': str(cls.runtime / 'bin'),
                           'LD_LIBRARY_PATH': str(cls.runtime / 'lib') + ':' + str(cls.runtime / 'rust/lib'),
                           'TMPDIR': str(cls.work / 'tmp'), 'CARGO_HOME': str(cls.work / 'cargo-home'),
                           'CARGO_NET_OFFLINE': 'true'}
        shutil.copyfile(QUALITY / 'fixtures/rust-native/driver_complete.rs', cls.work / 'fixture.rs')
        cls.anchors = {}
        for name in ('base', 'head'):
            code = ('import sys; from pathlib import Path; r=Path(sys.argv[1]); '
                    'sys.path.insert(0,str(r/"app")); import rust_native_driver as n; '
                    'print(n.collect_fixture(Path(sys.argv[2]),Path(sys.argv[3]),'
                    'r/"bin/harness-gate-rust-native-driver",r/"rust"))')
            result = cls.command(name + '-capture', [str(cls.runtime / 'python/bin/python3'), '-I', '-S', '-B',
                '-c', code, str(cls.runtime), str(cls.work / 'fixture.rs'), str(cls.work / name)])
            if result.returncode:
                raise AssertionError(result.stderr)
            cls.anchors[name] = result.stdout.strip()
        (cls.work / 'anchors.json').write_text(json.dumps(cls.anchors))

    @classmethod
    def command(cls, name, args, data=None):
        cls.command_index += 1
        record = cls.work / 'commands' / f'{cls.command_index:04d}-{name}'
        started = time.monotonic()
        result = subprocess.run(args, cwd=cls.work, env=cls.environment,
                                input=data, text=True, capture_output=True)
        # Repeated certification must retain every original command and result.
        # These records count direct test calls, not descendant producer launches.
        Path(str(record) + '.stdout').write_text(result.stdout)
        Path(str(record) + '.stderr').write_text(result.stderr)
        Path(str(record) + '.command.json').write_text(json.dumps({
            'command': args, 'cwd': str(cls.work), 'environment': cls.environment,
            'stdin': data, 'exit_code': result.returncode,
            'wall_seconds': time.monotonic() - started}, indent=2))
        return result

    def entry(self, name, *args, data=None):
        return self.command(name, [str(self.runtime / 'bin/harness-gate-rust-collector'), *args], data)

    def measurement(self, name):
        result = self.entry(name + '-certify', 'certify', '--evidence', name, '--anchor', self.anchors[name])
        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertIsNone(response['error'])
        return response['measurement']

    def test_real_low_coverage_is_completion_and_legacy_exit_is_preserved(self):
        report = self.measurement('base')
        self.assertNotIn('passed', report)
        self.assertEqual(report['coverage']['lines'], {'count': 35, 'covered': 26})
        debt = next(f for f in report['functions'] if f['name'] == 'legacy_debt')
        self.assertEqual(debt['crap_exact'], [56, 1])
        self.assertNotIn('passed', debt)
        result = self.command('legacy-certify', [str(self.runtime / 'python/bin/python3'), '-I', '-S', '-B',
            '-c', 'import sys; sys.path.insert(0,sys.argv.pop(1)); import rust_native_driver as n; sys.exit(n.main())',
            str(self.runtime / 'app'), 'certify', '--evidence', str(self.work / 'base'),
            '--anchor', self.anchors['base'], '--output', str(self.work / 'legacy.json')])
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(json.loads((self.work / 'legacy.json').read_text())['passed'])

    def test_doctor_and_unknown_collect_never_sample(self):
        result = self.entry('doctor', 'doctor', '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['runtime_complete'])
        result = self.entry('malformed-collect', 'collect', data='{"schema":1,"schema":2}')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['evidence'], [])
        self.assertIsNotNone(json.loads(result.stdout)['error'])
        record = json.loads((QUALITY / 'fixtures/harness-evidence/polyglot.json').read_text())[0]
        project = json.loads((QUALITY / 'fixtures/project-model/base.json').read_text())
        output = self.work / 'must-not-sample'
        request = {'schema': 'harness-collector-request/v1', 'project': project['id'],
                   'component': record['component'], 'collector': record['collector'],
                   'context': record['context'], 'requested_capabilities': ['coverage.line'],
                   'workspace_root': str(self.work), 'output_root': str(output), 'parameters': {}}
        result = self.entry('unknown-collect', 'collect', data=json.dumps(request))
        self.assertEqual(result.returncode, 1)
        self.assertIn('unknown tested Core/protocol/ABI', json.loads(result.stdout)['error']['message'])
        self.assertEqual(json.loads(result.stdout)['evidence'], [])
        self.assertFalse(output.exists())

    def test_private_c_dependency_compiles_archives_and_links(self):
        import shlex

        source = self.work / 'native-dependency.c'
        source.write_text('#include <stdint.h>\n#include <openssl/crypto.h>\n'
                          'int main(void) { uint64_t v = OpenSSL_version_num(); return v == 0; }\n')
        flags = self.command('private-pkg-config', [str(self.runtime / 'bin/pkg-config'),
                                                  '--cflags', '--libs', 'openssl'])
        self.assertEqual(flags.returncode, 0, flags.stderr)
        args = shlex.split(flags.stdout)
        for arg in args:
            if arg.startswith(('-I', '-L')):
                self.assertTrue(Path(arg[2:]).is_relative_to(self.runtime), arg)
        obj, archive, binary = (self.work / name for name in ('native.o', 'libnative.a', 'native-c'))
        for name, command in (
            ('private-c-compile', [str(self.runtime / 'bin/cc'), '-c', str(source), '-o', str(obj)]),
            ('private-c-archive', [str(self.runtime / 'bin/ar'), 'rcs', str(archive), str(obj)]),
            ('private-c-link', [str(self.runtime / 'bin/cc'), str(archive), *args, '-o', str(binary)]),
            ('private-c-run', [str(binary)]),
        ):
            result = self.command(name, command)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrong_anchor_has_no_measurement(self):
        result = self.entry('wrong-anchor', 'certify', '--evidence', 'base', '--anchor', '0' * 64)
        self.assertEqual(result.returncode, 1)
        self.assertIsNone(json.loads(result.stdout)['measurement'])

    def test_private_cargo_capture_preserves_incomplete_classification(self):
        vendor = Path(os.environ['RUST_COLLECTOR_TEST_VENDOR']).resolve(strict=True)
        (self.work / 'cargo-home/config.toml').write_text(
            '[source.crates-io]\nreplace-with = "fixture-inputs"\n'
            '[source.fixture-inputs]\ndirectory = ' + json.dumps(str(vendor)) + '\n')
        project = self.work / 'project'
        shutil.copytree(QUALITY / 'fixtures/rust-native/file-classification', project)
        code = ('import sys; from pathlib import Path; r=Path(sys.argv[1]); '
                'sys.path.insert(0,str(r/"app")); import rust_native_driver as n; '
                'print(n.collect_cargo(Path(sys.argv[2]),Path(sys.argv[3]),'
                'r/"bin/harness-gate-rust-native-driver",r/"rust",["contract"],runtime=r))')
        result = self.command('cargo-capture', [str(self.runtime / 'python/bin/python3'), '-I', '-S', '-B', '-c',
            code, str(self.runtime), str(project / 'Cargo.toml'), str(self.work / 'cargo')])
        self.assertEqual(result.returncode, 0, result.stderr)
        anchor = result.stdout.strip()
        result = self.entry('classify', 'classify', '--evidence', 'cargo/raw', '--anchor', anchor)
        # This existing negative fixture deliberately includes orphan.rs and an
        # unloaded conditional module. Successful capture cannot waive either.
        self.assertEqual(result.returncode, 1)
        self.assertIsNone(json.loads(result.stdout)['measurement'])
        self.assertIn('incomplete classification', json.loads(result.stdout)['error']['message'])

    def test_complete_fixture_classifies_with_private_reexport(self):
        result = self.entry('complete-classify', 'classify', '--evidence', 'base',
                            '--anchor', self.anchors['base'])
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)['measurement']
        self.assertTrue(report['classification_complete'])
        self.assertNotIn('measurement_passed', report)
        self.assertNotIn('baseline_accepted', report)

    def test_released_core_evaluates_typed_private_measurements(self):
        binary = os.environ.get('HARNESS_GATE_NATIVE_POLICY_BINARY')
        if not binary:
            self.skipTest('HARNESS_GATE_NATIVE_POLICY_BINARY required for real Rust Core evaluation')
        base, head = self.measurement('base'), self.measurement('head')
        reports = (base, head)
        contexts = ({'target': 'native', 'run': 'private-runtime', 'commit': 'a' * 40, 'base_commit': 'b' * 40},
                    {'target': 'native', 'run': 'private-runtime', 'commit': 'c' * 40, 'base_commit': 'a' * 40})
        output = self.work / 'core'
        output.mkdir()
        projections = []
        for name, report, context in zip(('base', 'head'), reports, contexts):
            sources = output / (name + '-sources')
            sources.mkdir()
            shutil.copyfile(self.work / name / 'fixture.rs', sources / 'fixture.rs')
            projections.append(policy.project(report, output / name, sources, context, 'private-runtime', []))
        declared, mappings, _ = policy.policy_and_lineage(base, head, *projections, [], CRAP_RULE)
        command = [str(Path(binary).resolve()), 'quality', 'evaluate', '--output', str(output / 'report.json')]
        for name, value in [('policy', declared), ('mappings', mappings)]:
            path = output / (name + '.json')
            path.write_text(json.dumps(value))
            command.extend(['--' + name, str(path)])
        for prefix, projection in zip(('base-', ''), projections):
            for name, value in projection.items():
                path = value if name.endswith('-root') else str(output / (prefix + name + '.json'))
                if not name.endswith('-root'):
                    Path(path).write_text(json.dumps(value))
                command.extend(['--' + prefix + name, path])
        result = self.command('core-evaluate', command)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads((output / 'report.json').read_text())
        self.assertEqual(report['aggregate']['state'], 'fail')
        self.assertNotIn('measurement_error', {r['state'] for r in report['gates'].values()})
        self.assertTrue(any(r['record']['head'].get('numerator') == 56 for r in report['gates'].values()))

    def test_private_generic_projection_is_decided_by_actual_core(self):
        """Native diagnostic; unsigned preparation does not authorize a delivery tuple."""
        from test_rust_collector_project import binding_for, request_for

        binary = os.environ.get('HARNESS_GATE_NATIVE_POLICY_BINARY')
        if not binary:
            self.skipTest('HARNESS_GATE_NATIVE_POLICY_BINARY required for actual Core evaluation')
        reports = [self.measurement(name) for name in ('base', 'head')]
        output = self.work / 'generic-core'
        output.mkdir()
        projections = []
        for name, report, commit, parent in zip(('base', 'head'), reports, ('a', 'c'), ('b', 'a')):
            artifacts = output / name
            artifacts.mkdir()
            binding = binding_for(report, self.work / name, artifacts)
            binding['input']['context'].update(commit=commit * 40, base_commit=parent * 40)
            binding['config_digest'] = commit * 64
            binding_path = output / (name + '-binding.json')
            request, digest = request_for(binding, binding_path)
            request_path = output / (name + '-request.json')
            request_path.write_text(json.dumps(request))
            report_path = output / (name + '-native.json')
            report_path.write_text(json.dumps(report))
            # Exercise the installed projection with private Python and certified
            # fresh reports. The public collect entry remains blocked while the
            # reviewed delivery matrix is empty; this is no substitute for it.
            code = ('import sys,json; from pathlib import Path; '
                    'sys.path.insert(0,str(Path(sys.argv[1])/"app")); '
                    'import rust_collector_project as p, rust_collector_delivery as d, rust_native_driver as n; '
                    'b=p.load_binding(json.loads(Path(sys.argv[2]).read_text()),'
                    'Path(sys.argv[3]),sys.argv[4]); '
                    # Exercise v2 project configuration separation against real
                    # native captures and private code. This diagnostic manifest
                    # is not a signed distribution or compatibility approval.
                    'r=Path(sys.argv[1]); '
                    'm={"schema":"rust-collector-delivery/v2","measurement":{'
                    '"native_series":n.SERIES,"compiler_commit":n.RUSTC_COMMIT,'
                    '"llvm_version":"22.1.6","compiler_inventory_schema":n.SCHEMA,'
                    '"configuration_authority":"quality-trusted-state/v1",'
                    '"adapter_sha256":n.file_hash(r/"app/rust_native_driver.py"),'
                    '"classifier_sha256":n.file_hash(r/"app/rust_native_classify.py"),'
                    '"projection_sha256":n.file_hash(r/"app/rust_collector_project.py")}}; '
                    'd.require_measurement_identity(r,m,b); '
                    'print(json.dumps(p.project_report(json.loads(Path(sys.argv[5]).read_text()),b)))')
            result = self.command(name + '-generic-project', [str(self.runtime / 'python/bin/python3'),
                '-I', '-S', '-B', '-c', code, str(self.runtime), str(request_path), str(binding_path),
                digest, str(report_path)])
            self.assertEqual(result.returncode, 0, result.stderr)
            response = json.loads(result.stdout)
            self.assertEqual(response['status'], 'PASS')
            projections.append({'project': binding['project'], 'evidence': response['collection']['evidence'],
                                'expected': binding['input']['context'],
                                'source-root': str(self.work / name), 'artifact-root': str(artifacts)})
        declared, mappings, _ = policy.policy_and_lineage(*reports, *projections, ['legacy_debt'], CRAP_RULE)
        command = [str(Path(binary).resolve()), 'quality', 'evaluate', '--output', str(output / 'report.json')]
        for name, value in [('policy', declared), ('mappings', mappings)]:
            path = output / (name + '.json')
            path.write_text(json.dumps(value))
            command.extend(['--' + name, str(path)])
        for prefix, projection in zip(('base-', ''), projections):
            for name, value in projection.items():
                path = value if name.endswith('-root') else str(output / (prefix + name + '.json'))
                if not name.endswith('-root'):
                    Path(path).write_text(json.dumps(value))
                command.extend(['--' + prefix + name, path])
        result = self.command('generic-core-evaluate', command)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads((output / 'report.json').read_text())
        self.assertEqual(report['aggregate']['state'], 'fail')
        self.assertNotIn('measurement_error', {r['state'] for r in report['gates'].values()})
        self.assertTrue(any(r['record']['head'].get('numerator') == 56 and r['state'] == 'fail'
                            for r in report['gates'].values()))
        # Inject unavailable outcomes into the projection, then ask actual Core
        # to decide requiredness. These are synthetic negatives over fresh native
        # evidence, not successful captures of unsupported tool combinations.
        for state, gate_state in [('unsupported', 'unsupported'),
                                  ('not_configured', 'blocked'),
                                  ('not_collected', 'skipped'),
                                  ('not_applicable', 'not_applicable'),
                                  ('measurement_error', 'measurement_error')]:
            with self.subTest(capability=state):
                artifacts = output / state
                artifacts.mkdir()
                unavailable = copy.deepcopy(binding)
                unavailable['input']['output_root'] = str(artifacts)
                for capability in unavailable['capabilities']:
                    capability.update(state=state, reason='explicit synthetic capability diagnostic')
                binding_path = output / (state + '-binding.json')
                request, digest = request_for(unavailable, binding_path)
                request_path = output / (state + '-request.json')
                request_path.write_text(json.dumps(request))
                result = self.command(state + '-generic-project',
                    [str(self.runtime / 'python/bin/python3'), '-I', '-S', '-B', '-c', code,
                     str(self.runtime), str(request_path), str(binding_path), digest, str(report_path)])
                self.assertEqual(result.returncode, 0, result.stderr)
                response = json.loads(result.stdout)
                self.assertEqual(response['status'], 'PASS')
                records = response['collection']['evidence']
                self.assertTrue(records)
                for record in records:
                    self.assertEqual({c['state'] for c in record['capabilities']}, {state})
                    self.assertEqual(record['metrics'], [])
                evidence_path = output / (state + '-evidence.json')
                evidence_path.write_text(json.dumps(records))
                decision_path = output / (state + '-report.json')
                unavailable_command = command.copy()
                for option, value in [('--evidence', evidence_path), ('--artifact-root', artifacts),
                                      ('--output', decision_path)]:
                    unavailable_command[unavailable_command.index(option) + 1] = str(value)
                result = self.command(state + '-core-evaluate', unavailable_command)
                self.assertEqual(result.returncode, 1, result.stderr)
                decision = json.loads(decision_path.read_text())
                self.assertTrue(decision['gates'])
                self.assertEqual({gate['state'] for gate in decision['gates'].values()}, {gate_state})
                aggregate = 'measurement_error' if state == 'measurement_error' else 'blocked'
                self.assertEqual(decision['aggregate']['state'], aggregate)
        unknown_output = output / 'unknown-combination'
        unknown_output.mkdir()
        binding['input']['output_root'] = str(unknown_output)
        binding_path = output / 'unknown-binding.json'
        request, _ = request_for(binding, binding_path)
        result = self.entry('generic-unknown-combination', *request['args'], data=json.dumps(request))
        self.assertEqual(result.returncode, 1, result.stderr)
        response = json.loads(result.stdout)
        self.assertEqual(response['invocation_id'], request['invocation_id'])
        self.assertEqual(response['status'], 'FAIL')
        self.assertEqual(response['collection']['evidence'], [])
        self.assertIn('unknown tested Core/protocol/ABI', response['collection']['error'])
        self.assertEqual(list(unknown_output.iterdir()), [])

    def test_actual_core_authenticates_private_collector_and_rejects_replay(self):
        """A disposable test signer does not establish delivery or capture trust."""
        from test_rust_collector_project import binding_for, request_for

        binary = os.environ.get('HARNESS_GATE_NATIVE_POLICY_BINARY')
        if not binary:
            self.skipTest('HARNESS_GATE_NATIVE_POLICY_BINARY required for actual Core invocation')
        openssl = shutil.which('openssl')
        if not openssl:
            self.skipTest('openssl required to sign the disposable trusted-request fixture')
        output = self.work / 'authenticated-core'
        output.mkdir()
        artifacts = output / 'artifacts'
        artifacts.mkdir()
        binding = binding_for(self.measurement('head'), self.work / 'head', artifacts)
        request, _ = request_for(binding, output / 'binding.json')
        executable = self.runtime / 'bin/harness-gate-rust-collector'
        request['adapter'].update(executable=str(executable), source_digest=builder.sha(executable),
            signature={'algorithm': 'ed25519', 'key_id': 'disposable-integration-test', 'value': ''})
        request.update(nonce='authenticated-core-test', timeout_ms=30000,
                       issued_at_ms=int(time.time() * 1000))
        request['expires_at_ms'] = request['issued_at_ms'] + 120000
        private_key = output / 'disposable-test-key.pem'
        public_key = output / 'disposable-test-key.der'
        for name, args in (
            ('generate', ['genpkey', '-algorithm', 'ED25519', '-out', str(private_key)]),
            ('public', ['pkey', '-in', str(private_key), '-pubout', '-outform', 'DER', '-out', str(public_key)]),
        ):
            result = self.command('test-key-' + name, [openssl, *args])
            self.assertEqual(result.returncode, 0, result.stderr)
        public_bytes = public_key.read_bytes()
        self.assertEqual(public_bytes[:12], bytes.fromhex('302a300506032b6570032100'))
        self.assertEqual(len(public_bytes), 44)
        trusted_key = output / 'trusted-key.json'
        trusted_key.write_text(json.dumps({'key_id': 'disposable-integration-test',
            'public_key': base64.b64encode(public_bytes[12:]).decode()}))
        # Match the existing v2 signed struct order; JSON Value maps and
        # BTreeMaps inside that struct have lexically sorted keys. Core itself
        # verifies these bytes, so an incompatible encoding fails the test.
        declaration = request['adapter']
        unsigned = {'domain': 'harness-gate/adapter-request/v2',
            'protocol_version': request['protocol_version'], 'result_schema_version': request['result_schema_version'],
            'adapter': {key: declaration[key] for key in ('name', 'version', 'executable', 'source_digest')}}
        unsigned['adapter']['signature'] = {key: declaration['signature'][key] for key in ('algorithm', 'key_id')}
        for key in ('invocation_id', 'step_id', 'timeout_ms', 'config_digest', 'artifact_root',
                    'nonce', 'issued_at_ms', 'expires_at_ms', 'args', 'environment', 'capabilities', 'input'):
            unsigned[key] = request[key]
        unsigned['input'] = json.loads(json.dumps(request['input'], sort_keys=True))
        payload = output / 'signed-payload.json'
        payload.write_bytes(json.dumps(unsigned, separators=(',', ':'), ensure_ascii=False).encode())
        signature = output / 'signature.bin'
        result = self.command('test-key-sign', [openssl, 'pkeyutl', '-sign', '-rawin',
            '-inkey', str(private_key), '-in', str(payload), '-out', str(signature)])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(signature.read_bytes()), 64)
        request['adapter']['signature']['value'] = base64.b64encode(signature.read_bytes()).decode()
        command = [str(Path(binary).resolve()), 'adapter', 'run', '--trusted-key', str(trusted_key), '--request']
        tampered = copy.deepcopy(request)
        tampered['input']['context']['commit'] = 'f' * 40
        tampered_path = output / 'tampered-request.json'
        tampered_path.write_text(json.dumps(tampered))
        result = self.command('authenticated-tampered-context', command + [str(tampered_path)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('adapter signature verification failed', result.stderr)
        self.assertFalse((output / '.harness-gate-adapter-replay').exists())
        request_path = output / 'request.json'
        request_path.write_text(json.dumps(request))
        result = self.command('authenticated-unknown-combination', command + [str(request_path)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('adapter exited with', result.stderr)
        # The public entry rejects an uncertified combination. A generic host
        # treats its nonzero exit as an operational failure before parsing it.
        direct = self.entry('authenticated-direct-response', *request['args'], data=json.dumps(request))
        self.assertEqual(direct.returncode, 1, direct.stderr)
        response = json.loads(direct.stdout)
        self.assertEqual(response['invocation_id'], request['invocation_id'])
        self.assertIn('unknown tested Core/protocol/ABI', response['collection']['error'])
        self.assertEqual(response['collection']['evidence'], [])
        self.assertEqual(response['artifacts'], [])
        result = self.command('authenticated-replay', command + [str(request_path)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('nonce has already been used', result.stderr)
        self.assertEqual(list(artifacts.iterdir()), [])

    def test_actual_core_configures_installed_collector_once_and_rejects_replay(self):
        from rust_collector_config_fixture import configured_rejection

        binary = os.environ.get('HARNESS_GATE_NATIVE_POLICY_BINARY')
        if not binary:
            self.skipTest('HARNESS_GATE_NATIVE_POLICY_BINARY required for configured Core invocation')
        configured_rejection(self, str(Path(binary).resolve(strict=True)))

    def test_actual_core_rejects_malformed_output_once_and_consumes_nonce(self):
        from rust_collector_config_fixture import configured_malformed_rejection

        binary = os.environ.get('HARNESS_GATE_NATIVE_POLICY_BINARY')
        if not binary:
            self.skipTest('HARNESS_GATE_NATIVE_POLICY_BINARY required for configured Core invocation')
        configured_malformed_rejection(self, str(Path(binary).resolve(strict=True)))
