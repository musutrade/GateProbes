"""Reject incomplete native protection and altered public assets."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools/release'))
import verify_native_release as publication


class NativePublicationTests(unittest.TestCase):
    def test_preflight_requires_enabled_boolean(self):
        for value in (False, None, 'true', 1):
            with self.subTest(value=value), patch.object(publication, 'api', return_value={'enabled': value}):
                with self.assertRaises(ValueError):
                    publication.preflight()
        with patch.object(publication, 'api', return_value={'enabled': True}):
            self.assertEqual(publication.preflight(), {'enabled': True})

    def test_actual_state_is_required(self):
        state = dict(tag_name=publication.HISTORICAL_TAG, draft=False, prerelease=True, immutable=True)
        publication.check_state(state, publication.HISTORICAL_TAG, False)
        for key, values in {'draft': [True, None], 'prerelease': [False, None],
                            'immutable': [False, None, 'true'], 'tag_name': ['wrong']}.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    publication.check_state({**state, key: value}, publication.HISTORICAL_TAG, False)

    def test_legacy_exception_cannot_apply_to_future_tags(self):
        state = dict(tag_name=publication.HISTORICAL_TAG, draft=False, prerelease=True, immutable=False)
        publication.check_state(state, publication.HISTORICAL_TAG, True)
        tag = 'rust-collector-v0.1.0-rc.9'
        with self.assertRaises(ValueError):
            publication.check_state({**state, 'tag_name': tag}, tag, True)
        with patch.object(publication, 'preflight') as preflight, self.assertRaises(ValueError):
            publication.verify(tag, 'a' * 40, 'cosign', True)
        preflight.assert_not_called()

    def test_stable_release_must_not_be_prerelease(self):
        tag = 'rust-collector-v0.1.0'
        state = dict(tag_name=tag, draft=False, prerelease=False, immutable=True)
        publication.check_state(state, tag, False)
        with self.assertRaises(ValueError):
            publication.check_state({**state, 'prerelease': True}, tag, False)

    def test_source_and_identity_require_exact_inputs(self):
        for tag, commit in [('bad', 'a'*40), (publication.HISTORICAL_TAG, 'short')]:
            with self.assertRaises(ValueError):
                publication.identity(tag, commit)
        self.assertTrue(publication.identity(publication.HISTORICAL_TAG, 'a'*40).endswith(publication.HISTORICAL_TAG))

    def test_asset_set_and_bytes_are_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            dist = Path(directory)
            (dist / 'binary').write_bytes(b'original')
            row = {'name': 'binary', 'id': 1, 'size': 8,
                   'digest': 'sha256:' + hashlib.sha256(b'original').hexdigest()}
            with patch.object(publication.inventory, 'expected_upload_names', return_value=['binary']):
                publication.check_assets({'assets': [row]}, dist, {})
                for assets in ([], [row, row], [row, {**row, 'name': 'extra'}],
                               [{**row, 'size': 9}], [{**row, 'digest': 'sha256:wrong'}]):
                    with self.subTest(assets=assets), self.assertRaises(ValueError):
                        publication.check_assets({'assets': assets}, dist, {})
                (dist / 'binary').write_bytes(b'modified')
                with self.assertRaises(ValueError):
                    publication.check_assets({'assets': [row]}, dist, {})

    def test_verification_binds_every_subject_to_exact_source_and_tag(self):
        tag, commit = publication.HISTORICAL_TAG, 'a' * 40
        state = dict(id=2, tag_name=tag, draft=False, prerelease=True, immutable=False)
        manifest = {'tag': tag, 'source': {'repository': 'https://github.com/' + publication.REPOSITORY,
                                         'commit': commit}, 'integrity_subjects': ['binary', 'inventory']}
        with patch.object(publication, 'preflight', return_value={'enabled': True}), \
                patch.object(publication, 'api', return_value=state), \
                patch.object(publication, 'run', return_value='') as run, \
                patch.object(publication.inventory, 'load', return_value=manifest), \
                patch.object(publication.inventory, 'verify') as verify, \
                patch.object(publication, 'check_assets', return_value=[]):
            receipt = publication.verify(tag, commit, 'cosign', True)
            self.assertEqual(receipt['protection_status'], 'legacy-mutable')
            self.assertFalse(receipt['immutable'])
            self.assertEqual(receipt['signed_and_attested_subjects'], 2)
            verify.assert_called_once()
            attestations = [call.args[0] for call in run.call_args_list if 'attestation' in call.args[0]]
            self.assertEqual(len(attestations), 2)
            for arguments in attestations:
                for flag, value in [('--source-digest', commit), ('--signer-digest', commit),
                                    ('--source-ref', 'refs/tags/' + tag),
                                    ('--cert-identity', publication.identity(tag, commit))]:
                    self.assertEqual(arguments[arguments.index(flag) + 1], value)
            run.side_effect = RuntimeError('signature failure')
            with self.assertRaises(RuntimeError):
                publication.verify(tag, commit, 'cosign', True)
            run.side_effect = None
            for changed in ({**state, 'id': 3}, {**state, 'immutable': True}):
                publication.api.side_effect = [state, changed]
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    publication.verify(tag, commit, 'cosign', True)

    def test_workflow_preflight_and_postcheck_are_mandatory(self):
        text = (ROOT / '.github/workflows/native-collector-release.yml').read_text()
        self.assertLess(text.index('verify_native_release.py preflight'), text.index('name: Download release assets'))
        self.assertGreater(text.index('verify_native_release.py verify'), text.index('gh release create'))
        self.assertNotIn('--historical-rc8', text)
        self.assertIn('path: receipts/*.json', text)
        self.assertIn('needs: [ policy, build ]', text)
        self.assertIn('environment: release', text)


if __name__ == '__main__':
    unittest.main()
