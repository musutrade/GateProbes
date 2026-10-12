import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from plugin import COLLECTOR, TYPES, canonical, file, project, relative, series, sha

class ProtocolTests(unittest.TestCase):
    def test_manifest_matches_protocol_identity(self):
        manifest = json.loads(Path(__file__).with_name("plugin.json").read_text())
        self.assertEqual(manifest["version"], COLLECTOR["version"])

    def test_relative_paths_and_symlinks_rejected(self):
        for value in ('../a', '/a', 'a/../b', 'a//b', '.', 'a\\b'):
            with self.assertRaises(ValueError): relative(value)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'real').write_text('x')
            (root / 'alias').symlink_to(root / 'real')
            with self.assertRaisesRegex(ValueError, 'symlink'): file(root, 'alias')

    def test_series_binds_method_and_toolchain_not_tool_location(self):
        request = {'parameters': {'receipt': {'pipeline': {'tools': {'llvm-cov': {'path': '/a', 'sha256': 'a'*64, 'version': 'v1'}}}}}, 'context': {'target': 'test'}}
        original = series(request)
        request['parameters']['receipt']['pipeline']['tools']['llvm-cov']['path'] = '/b'
        self.assertEqual(series(request), original)
        request['parameters']['receipt']['pipeline']['tools']['llvm-cov']['sha256'] = 'b'*64
        self.assertNotEqual(series(request), original)

    def test_signed_binding_and_claims_checked_before_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'binding.json'
            request = {'project': 'test', 'collector': COLLECTOR, 'context': {'run': 'run', 'target': 'target'},
                       'workspace_root': tmp, 'output_root': tmp + '/output', 'parameters': {'subjects': [{'id': 'subject'}],
                       'receipt': {'pipeline': {'tools': {}}}}}
            identity = series(request)
            inner = {k: request[k] for k in ('project','collector','context','workspace_root','output_root')}
            inner.update(schema='harness-project-collector-request/v1', bindings=[{'subject': 'subject', 'capability': m, 'series': identity['id']} for m in sorted(TYPES)])
            binding = {'schema': 'rust-source-project-binding/v1', 'config_digest': 'digest', 'input': inner, 'request': request}
            p.write_text(canonical(binding))
            args = ['project', '--binding', str(p), '--binding-sha256', sha(p.read_bytes())]
            invocation = {'protocol_version': 2, 'result_schema_version': '1', 'args': args, 'input': inner,
                          'adapter': COLLECTOR, 'config_digest': 'digest', 'invocation_id': 'run', 'step_id': 'backend', 'artifact_root': tmp + '/output'}
            environment = {'HARNESS_GATE_INVOCATION_ID': 'run', 'HARNESS_GATE_STEP_ID': 'backend', 'HARNESS_GATE_ARTIFACT_ROOT': tmp + '/output'}
            with patch.dict(os.environ, environment), patch('plugin.collect') as collect:
                changed = copy.deepcopy(invocation)
                changed['args'][-1] = '0'*64
                with self.assertRaises(ValueError): project(changed, changed['args'])
                changed = copy.deepcopy(invocation)
                changed['input']['bindings'] = []
                with self.assertRaises(ValueError): project(changed, args)
                collect.assert_not_called()

if __name__ == '__main__': unittest.main()
