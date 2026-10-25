"""Published-byte rejection boundaries and actual workflow selection/aggregate scripts."""
import copy
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'plugins/rust-source-risk'))
sys.path.insert(0, str(ROOT / 'tools/release'))
sys.path.insert(0, str(ROOT / 'tools/ci'))
import published_acceptance as gate
import release_inventory as inventory
import classify


def synthetic_dist(root, mutation=None):
    """Repin outer digests to exercise semantic checks, independently of hash rejection."""
    pins = copy.deepcopy(gate.load_pins())
    product = pins['validator_manifest']['candidate']
    files = {name: b'fixture' for name in product['members']}
    files['plugin.json'] = json.dumps({'name': 'rust-source-risk', 'version': '0.3.0'}).encode()
    product['members'] = {name: gate.digest(data) for name, data in files.items()}
    if mutation == 'member':
        files['capture.py'] = b'changed'
    if mutation == 'version':
        files['plugin.json'] = json.dumps({'name': 'rust-source-risk', 'version': '9.0.0'}).encode()
        product['members']['plugin.json'] = gate.digest(files['plugin.json'])
    archive = root / product['archive']
    with tarfile.open(archive, 'w:gz') as stream:
        for name, data in files.items():
            item = tarfile.TarInfo('package/' + name); item.size = len(data)
            stream.addfile(item, io.BytesIO(data))
    product['archive_sha256'] = gate.file_digest(archive)
    sbom = {'bomFormat': 'CycloneDX', 'metadata': {'component': {
        'name': 'harness-gate-rust-source-inventory', 'version': '0.3.0'}, 'properties': [
            {'name': 'source.commit', 'value': pins['source_commit']},
            {'name': 'cargo.lock.sha256', 'value': product['members']['ast/Cargo.lock']}]}}
    if mutation == 'sbom-version': sbom['metadata']['component']['version'] = '0.2.0'
    if mutation == 'sbom-source': sbom['metadata']['properties'][0]['value'] = 'f' * 40
    gate.write(root / product['sbom'], sbom)
    product['sbom_sha256'] = gate.file_digest(root / product['sbom'])
    inv = inventory.generate(root, root / 'release-inventory.json', [product['archive']], product['sbom'],
                             pins['tag'], 'f' * 40 if mutation == 'source' else pins['source_commit'],
                             'https://github.com/' + pins['repository'])
    (root / 'SHA256SUMS').write_text(''.join(gate.file_digest(root / n) + '  ' + n + '\n'
                                                  for n in inv['checksum_subjects']))
    for name in inv['signature_products']: (root / name).write_text('synthetic, never crypto accepted')
    pins['assets'] = {p.name: gate.file_digest(p) for p in root.iterdir()}
    return pins


class Published03Tests(unittest.TestCase):
    def test_manifest_version_source_and_identity_are_pinned(self):
        original = gate.load_pins()
        for case in ['manifest', 'version', 'source', 'identity']:
            pins = copy.deepcopy(original)
            if case == 'manifest': pins['validator_manifest_sha256'] = '0' * 64
            if case == 'version':
                pins['validator_manifest']['candidate']['version'] = '0.2.0'
                pins['validator_manifest_sha256'] = gate.digest((json.dumps(pins['validator_manifest'], indent=2) + '\n').encode())
            if case == 'source': pins['source_commit'] = 'f' * 40
            if case == 'identity': pins['certificate_identity'] += '.wrong'
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                p = Path(tmp) / 'pins.json'; gate.write(p, pins)
                with self.assertRaises(gate.AcceptanceError): gate.load_pins(p)

    def test_archive_sbom_source_and_members_reject_even_after_outer_repin(self):
        for case in [None, 'version', 'source', 'member', 'sbom-version', 'sbom-source', 'digest']:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); dist = root / 'dist'; dist.mkdir()
                pins = synthetic_dist(dist, case)
                if case == 'digest': (dist / 'SHA256SUMS').write_text('tampered')
                if case is None:
                    gate.verify_local_bytes(pins, dist, root / 'unpack', inventory)
                else:
                    with self.assertRaises((gate.AcceptanceError, inventory.InventoryError)):
                        gate.verify_local_bytes(pins, dist, root / 'unpack', inventory)

    def test_missing_measurements_cannot_pass_outer_receipt(self):
        pins = gate.load_pins()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); bundle = root / 'bundle.json'; bundle.write_text('{}')
            receipt = {'schema': 'rust-source-risk-local-candidate-acceptance/v1',
                'scope': 'local-unpublished-candidate', 'candidate': pins['validator_manifest']['candidate'],
                'candidate_manifest_sha256': pins['validator_manifest_sha256'],
                'fixture': {'bundle_sha256': gate.file_digest(bundle)},
                'positive': {'evidence_records': 4}}
            gate.write(root / 'accepted-collection.json', {'evidence': []})
            with self.assertRaisesRegex(gate.AcceptanceError, 'missing measured records'):
                gate.verify_fresh_result(pins, receipt, bundle, root)

    def test_network_signature_and_corrupt_cache_stop_before_execution_no_fallback(self):
        for failure in ['network', 'signature', 'cache']:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); seed = root / 'seed'; seed.mkdir(); pins = synthetic_dist(seed)
                cache = root / 'cache'; cache.mkdir()
                tool = cache / 'cosign-linux-amd64'; tool.write_bytes(b'fixture-tool')
                pins['cosign']['sha256'] = gate.file_digest(tool)
                if failure == 'cache': tool.write_bytes(b'corrupted-cache')
                release = {'id': pins['release_id'], 'tag_name': pins['tag'], 'immutable': True,
                    'draft': False, 'prerelease': False, 'assets': [{'name': n, 'digest': 'sha256:' + d,
                    'size': (seed / n).stat().st_size} for n, d in pins['assets'].items()]}
                ref = {'object': {'type': 'tag', 'sha': pins['tag_object']}}
                tag = {'tag': pins['tag'], 'object': {'type': 'commit', 'sha': pins['source_commit']}}
                calls = []
                def run(argv, **kwargs):
                    calls.append(argv)
                    code, stdout, stderr = 0, '', ''
                    if argv[:2] == ['gh', 'api']:
                        if failure == 'network': code, stderr = 1, 'network-error'
                        else: stdout = json.dumps(tag if '/git/tags/' in argv[2] else ref if '/git/ref/' in argv[2] else release)
                    elif argv[:3] == ['gh', 'release', 'download']:
                        shutil.copytree(seed, root / 'out/download', dirs_exist_ok=True)
                    elif 'worktree' in argv:
                        fixed = root / 'out/fixed-source'; fixed.mkdir()
                        for n in pins['fixed_source_files']:
                            p = fixed / n; p.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(ROOT / n, p)
                    elif 'rev-parse' in argv: stdout = pins['source_tree']
                    elif 'verify-blob' in argv: code, stderr = 1, 'signature-error'
                    return subprocess.CompletedProcess(argv, code, stdout, stderr)
                with patch.object(gate, 'load_pins', return_value=pins), patch.object(gate.subprocess, 'run', side_effect=run):
                    with self.assertRaisesRegex(gate.AcceptanceError, {'network': 'network-error', 'signature': 'signature-error', 'cache': 'digest mismatch'}[failure]):
                        gate.main(['--output', str(root / 'out'), '--tool-cache', str(cache)])
                self.assertFalse((root / 'out/receipt.json').exists())
                self.assertFalse(any('capture.py' in ' '.join(c) or 'candidate_acceptance.py' in ' '.join(c) for c in calls))
                self.assertFalse(any('sigstore/cosign' in c for c in calls))  # corrupt cache never redownloaded

    def test_classifier_covers_pins_runner_fixture_harness_and_workflow(self):
        registry = classify.load_registry(ROOT)
        for name in ['published_acceptance.json', 'published_acceptance.py', 'fixtures/thiserror-subset/tests/integration.rs', 'core_acceptance.py']:
            result = classify.classify(['plugins/rust-source-risk/' + name], registry)
            self.assertTrue(result['selection']['run_plugins'])
        self.assertTrue(classify.classify(['.github/workflows/ci.yml'], registry)['selection']['run_plugins'])

    def test_literal_aggregate_script_rejects_selected_skip_cancel_and_invalid_selection(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('source-risk-candidate, source-risk-published03, presets', workflow)
        block = workflow.split('      - name: Require selected published03 download acceptance\n', 1)[1].split('      - name:', 1)[0]
        script = block.split("python3 - <<'PYPUBLISHED'\n", 1)[1].split('          PYPUBLISHED', 1)[0]
        script = '\n'.join(line[10:] for line in script.splitlines())
        import os
        for selected, result, valid in [('true', 'success', True), ('true', 'skipped', False),
                ('true', 'cancelled', False), ('true', 'failure', False), ('', 'success', False),
                ('false', 'skipped', True), ('false', 'cancelled', False)]:
            env = dict(os.environ, SELECTED=selected, RESULT=result)
            r = subprocess.run([sys.executable, '-c', script], env=env, capture_output=True)
            self.assertEqual(r.returncode == 0, valid, (selected, result))


if __name__ == '__main__':
    unittest.main()
