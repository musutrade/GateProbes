"""Delivery preflight failures must occur before execution or re-export."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rust_collector_delivery as delivery
import rust_native_driver as native


class ObservedDeliveryTests(unittest.TestCase):
    def test_host_configuration_changes_preserve_immutable_code_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'app').mkdir()
            hashes = {}
            for field, filename in (
                ('adapter_sha256', 'rust_native_driver.py'),
                ('projection_sha256', 'rust_collector_project.py'),
                ('classifier_sha256', 'rust_native_classify.py'),
            ):
                path = root / 'app' / filename
                path.write_text(filename)
                hashes[field] = native.file_hash(path)
            identity = dict(hashes, native_series=native.SERIES,
                            compiler_commit=native.RUSTC_COMMIT, llvm_version='22.1.6',
                            compiler_inventory_schema=native.SCHEMA,
                            configuration_authority='quality-trusted-state/v1')
            manifest = {'schema': 'rust-collector-delivery/v2', 'measurement': identity}
            binding = {'config_digest': 'a' * 64,
                       'native_identity': {'projection_sha256': hashes['projection_sha256']},
                       'series': {'id': 'measurement-series/v1:' + 'a' * 64,
                                  'normalization': {'version': hashes['projection_sha256']},
                                  'runtime': {'version': native.RUSTC_COMMIT}}}
            delivery.require_measurement_identity(root, manifest, binding)
            changed = copy.deepcopy(binding)
            changed['config_digest'] = 'b' * 64
            changed['series']['id'] = 'measurement-series/v1:' + 'b' * 64
            delivery.require_measurement_identity(root, manifest, changed)
            legacy = copy.deepcopy(manifest)
            legacy['schema'] = 'rust-collector-delivery/v1'
            del legacy['measurement']['configuration_authority']
            legacy['measurement'].update(configuration_sha256=binding['config_digest'],
                                         normalized_series=[binding['series']['id']])
            delivery.require_measurement_identity(root, legacy, binding)
            with self.assertRaisesRegex(ValueError, 'measurement identity'):
                delivery.require_measurement_identity(root, legacy, changed)
            for part in ('native_identity', 'normalization', 'runtime'):
                damaged = copy.deepcopy(changed)
                if part == 'native_identity':
                    damaged[part]['projection_sha256'] = '0' * 64
                else:
                    damaged['series'][part]['version'] = '0' * 64
                with self.subTest(part=part), self.assertRaisesRegex(ValueError, 'normalization identity'):
                    delivery.require_measurement_identity(root, manifest, damaged)
            (root / 'app/rust_collector_project.py').write_text('changed code')
            with self.assertRaisesRegex(ValueError, 'measurement identity'):
                delivery.require_measurement_identity(root, manifest, binding)

    def test_wrong_core_bytes_are_rejected_before_executing_them(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'core'
            binary.write_bytes(b'untrusted executable')
            with patch.object(delivery, 'version') as version, self.assertRaisesRegex(ValueError, 'Core bytes'):
                delivery.observe(root, binary, {'sha256': '0' * 64})
            version.assert_not_called()

    def test_pinned_metadata_rejects_changed_duplicate_and_symlink_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'metadata.json'
            path.write_text('{"key":1}')
            ref = {'path': str(path), 'sha256': native.file_hash(path)}
            self.assertEqual(delivery.pinned(ref), {'key': 1})
            path.write_text('{"key":2}')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                delivery.pinned(ref)
            path.write_text('{"key":1,"key":2}')
            ref['sha256'] = native.file_hash(path)
            with self.assertRaises(ValueError):
                delivery.pinned(ref)
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                delivery.pinned(dict(ref, path=str(link)))

    def test_unconfigured_delivery_does_not_probe_or_certify(self):
        with patch.object(delivery, 'observe') as observe, patch.object(native, 'certify') as certify:
            with self.assertRaisesRegex(ValueError, 'unknown tested'):
                delivery.preflight(Path('/unused'), {})
            observe.assert_not_called()
            certify.assert_not_called()

    def test_relocated_capture_is_not_series_equivalence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'capture.json').write_text(json.dumps({'tools': {'rustc': {'path': '/another/rustc'}}}))
            with self.assertRaisesRegex(ValueError, 'no relocation equivalence'):
                delivery.capture_paths(root, root)
