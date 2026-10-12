import gzip
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from plugin import COLLECTOR, TYPES, collect, sha

class CompressedArtifacts(unittest.TestCase):
    def test_full_raw_bytes_and_per_source_bindings_are_retained(self):
        raw = b'{"unfiltered":"all LLVM records retained"}\n' * 100
        sources = {'src/a.rs': 'a' * 64, 'src/b.rs': 'b' * 64, 'src/types.rs': 'c' * 64}
        def reexport(request, path):
            path.write_bytes(raw)
            return {'functions': [{'source': path, 'complexity': 1, 'source_sha256': sources[path], **{name: None for name in TYPES if name != 'complexity.cyclomatic'}} for path in list(sources)[:2]]}
        with tempfile.TemporaryDirectory() as tmp:
            request = {'schema': 'harness-collector-request/v1', 'collector': COLLECTOR, 'project': 'test', 'component': 'backend',
                       'requested_capabilities': list(TYPES), 'output_root': tmp,
                       'workspace_root': '/source', 'context': {'run': 'test'},
                       'parameters': {'artifact_subdir': 'backend', 'subjects': [{'id': 's:a'}, {'id': 's:b'}],
                                      'receipt': {'sources': sources}}}
            with patch('plugin.reexport', reexport), patch('plugin.inventory', return_value=sources), patch('plugin.series', return_value={}), patch('plugin.subject', side_effect=lambda request, row: {'id': 's:' + row['source'][4]}):
                result = collect(request)
            self.assertEqual(len(result['artifacts']), 4)
            self.assertEqual(len({a['path'] for a in result['artifacts']}), 4)
            for artifact in result['artifacts']:
                content = (Path(tmp) / artifact['path']).read_bytes()
                self.assertEqual(sha(content), artifact['sha256'])
                self.assertEqual(len(content), artifact['bytes'])
                self.assertEqual(sources[artifact['source']['path']], artifact['source']['sha256'])
                if artifact['media_type'] == 'application/gzip':
                    self.assertEqual(gzip.decompress(content), raw)
                    self.assertEqual(content, gzip.compress(raw, mtime=0))
            with patch('plugin.reexport', reexport), patch('plugin.inventory', return_value=sources), patch('plugin.series', return_value={}), patch('plugin.subject', side_effect=lambda request, row: {'id': 's:' + row['source'][4]}):
                with self.assertRaisesRegex(ValueError, 'fresh'):
                    collect(request)

if __name__ == '__main__': unittest.main()
