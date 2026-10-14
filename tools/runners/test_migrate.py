import copy
import importlib.util
from pathlib import Path
import tomllib
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('migration', HERE / 'migrate.py')
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)
DEFINITION = tomllib.loads(migration.DEFAULT_DEFINITION.read_text())


class MigrationTests(unittest.TestCase):
    def flow(self, kind='cargo-test', threads=4):
        return {'version': 2, 'policy': {'required_steps': ['tests'], 'waivers': []},
                'execution': {'retries': {'tests': 2}, 'shards': {'tests': {'index': 1, 'total': 2}}},
                'steps': [{'id': 'tests', 'program': 'cargo', 'args': ['test', '--', '--test-threads=8'],
                           'runner': {'version': 1, 'kind': kind, 'threads': threads,
                                      'args': ['--nocapture'], 'args_position': 2,
                                      'isolation': 'schema-per-worker', 'result_format': 'regex'}}]}

    def test_migration_preserves_all_non_runner_values_and_legacy_fields(self):
        flow = self.flow()
        before = copy.deepcopy(flow)
        output = migration.migrate(flow, DEFINITION)
        self.assertEqual(flow, before)
        for key in ('version', 'policy', 'execution'):
            self.assertEqual(output[key], before[key])
        step = output['steps'][0]
        for key, value in before['steps'][0].items():
            if key != 'runner':
                self.assertEqual(step[key], value)
        for key, value in before['steps'][0]['runner'].items():
            self.assertEqual(step['runner'][key], 2 if key == 'version' else value)
        self.assertEqual(step['runner']['threads_args'], ['--test-threads', '{threads}'])
        self.assertEqual(step['runner']['threads_args_after'], '--')
        self.assertEqual(tomllib.loads(migration.render(output)), output)

    def test_generic_runner_and_no_thread_cargo_runner(self):
        flow = self.flow('future-runner')
        output = migration.migrate(flow, DEFINITION)
        self.assertNotIn('threads_args', output['steps'][0]['runner'])
        flow = self.flow()
        del flow['steps'][0]['runner']['threads']
        output = migration.migrate(flow, DEFINITION)
        self.assertNotIn('threads_args', output['steps'][0]['runner'])
        self.assertEqual(output['steps'][0]['runner']['required_program'], 'cargo')

    def test_cli_accepts_inline_and_table_blocks_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for declaration in [
                'runner = { version = 1, kind = "cargo-test", threads = 1, isolation = "shared" }',
                '[steps.runner]\nversion = 1\nkind = "cargo-test"\nthreads = 1\nisolation = "shared"',
            ]:
                source = root / 'source.toml'
                source.write_text('version = 2\n[[steps]]\nid = "tests"\nprogram = "cargo"\n' + declaration + '\n')
                original = source.read_bytes()
                result = subprocess.run([sys.executable, str(HERE / 'migrate.py'), str(source)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(tomllib.loads(result.stdout)['steps'][0]['runner']['version'], 2)
                result = subprocess.run([sys.executable, str(HERE / 'migrate.py'), str(source), '--output', str(source)], capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(source.read_bytes(), original)

    def test_bad_program_version_and_mixed_contract_are_rejected(self):
        for field, value in [('version', 2), ('threads_args', ['{threads}'])]:
            flow = self.flow()
            flow['steps'][0]['runner'][field] = value
            with self.assertRaises(ValueError):
                migration.migrate(flow, DEFINITION)
        flow = self.flow()
        flow['steps'][0]['program'] = 'sh'
        with self.assertRaises(ValueError):
            migration.migrate(flow, DEFINITION)


if __name__ == '__main__':
    unittest.main()
