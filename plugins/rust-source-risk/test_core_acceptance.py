import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import core_acceptance as acceptance


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_archive(path: Path, root: str, files: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(root + "/" + name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


class ArchiveTests(unittest.TestCase):
    def test_exact_member_inventory_and_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = {"plugin.py": b"print('ok')\n", "README.md": b"readme\n"}
            archive = root / "release.tar.gz"
            make_archive(archive, "package", files)
            pins = {"release": {
                "archive_sha256": sha(archive.read_bytes()),
                "members": {name: sha(data) for name, data in files.items()},
            }}
            plugin = acceptance.verify_archive(archive, pins, root / "unpack")
            self.assertEqual(plugin.name, "package")
            self.assertEqual((plugin / "plugin.py").read_bytes(), b"print('ok')\n")

    def test_changed_member_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "release.tar.gz"
            make_archive(archive, "package", {"plugin.py": b"original\n"})
            pins = {"release": {
                "archive_sha256": sha(archive.read_bytes()),
                "members": {"plugin.py": sha(b"original\n")},
            }}
            make_archive(archive, "package", {"plugin.py": b"changed\n"})
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.verify_archive(archive, pins, root / "unpack")

    def test_unsafe_member_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "release.tar.gz"
            with tarfile.open(archive, "w:gz") as stream:
                info = tarfile.TarInfo("../escape")
                info.size = 1
                stream.addfile(info, io.BytesIO(b"x"))
            pins = {"release": {
                "archive_sha256": sha(archive.read_bytes()),
                "members": {},
            }}
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.verify_archive(archive, pins, root / "unpack")

    def test_extra_member_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = {"plugin.py": b"ok\n"}
            archive = root / "release.tar.gz"
            make_archive(archive, "package", files)
            pins = {"release": {
                "archive_sha256": sha(archive.read_bytes()),
                "members": {name: sha(data) for name, data in files.items()},
            }}
            make_archive(archive, "package", {**files, "extra.py": b"extra\n"})
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.verify_archive(archive, pins, root / "unpack")


class CoreTests(unittest.TestCase):
    def test_core_version_and_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            core = root / "harness-gate"
            core.write_text("#!/bin/sh\necho 'harness-gate 0.14.1'\n")
            core.chmod(0o700)
            pins = {"core": {
                "sha256": sha(core.read_bytes()),
                "version": "harness-gate 0.14.1",
            }}
            self.assertEqual(acceptance.verify_core(core, pins)["version"],
                             "harness-gate 0.14.1")

    def test_wrong_core_version_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            core = root / "harness-gate"
            core.write_text("#!/bin/sh\necho 'harness-gate 0.14.0'\n")
            core.chmod(0o700)
            pins = {"core": {
                "sha256": sha(core.read_bytes()),
                "version": "harness-gate 0.14.1",
            }}
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.verify_core(core, pins)

    def test_wrong_core_digest_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            core = root / "harness-gate"
            core.write_text("#!/bin/sh\necho 'harness-gate 0.14.1'\n")
            core.chmod(0o700)
            pins = {"core": {
                "sha256": "0" * 64,
                "version": "harness-gate 0.14.1",
            }}
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.verify_core(core, pins)


class ReleaseInventoryTests(unittest.TestCase):
    def test_source_and_archive_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory = {
                "tag": "rust-source-risk-v0.2.0",
                "source": {
                    "repository": "https://github.com/musutrade/GateProbes",
                    "commit": "a" * 40,
                },
                "assets": [{"name": "archive.tar.gz", "sha256": "b" * 64}],
            }
            path = root / "release-inventory.json"
            path.write_text(json.dumps(inventory) + "\n")
            pins = {"release": {
                "tag": inventory["tag"],
                "source_commit": "a" * 40,
                "archive": "archive.tar.gz",
                "archive_sha256": "b" * 64,
                "inventory_sha256": sha(path.read_bytes()),
            }}
            acceptance.verify_release_inventory(path, pins)
            inventory["source"]["commit"] = "c" * 40
            path.write_text(json.dumps(inventory) + "\n")
            pins["release"]["inventory_sha256"] = sha(path.read_bytes())
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.verify_release_inventory(path, pins)


class EnvironmentTests(unittest.TestCase):
    def test_cargo_home_must_be_outside_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "workspace"
            root.mkdir()
            cargo = Path(temporary) / "cargo-home"
            cargo.mkdir()
            with mock.patch.dict(os.environ, {"CARGO_HOME": str(cargo)}, clear=False):
                for name in ("RUSTFLAGS", "CARGO_BUILD_TARGET", "RUSTC_WRAPPER"):
                    os.environ.pop(name, None)
                acceptance.verify_cargo_environment(root)

    def test_cargo_override_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "workspace"
            root.mkdir()
            cargo = Path(temporary) / "cargo-home"
            cargo.mkdir()
            with mock.patch.dict(os.environ, {"CARGO_HOME": str(cargo),
                                              "RUSTFLAGS": "--cfg changed"},
                                 clear=False):
                with self.assertRaises(acceptance.AcceptanceError):
                    acceptance.verify_cargo_environment(root)


class MatrixTests(unittest.TestCase):
    def test_ten_negative_cases_are_layered(self):
        self.assertEqual(len(acceptance.NEGATIVE_LAYERS), 10)
        self.assertEqual(acceptance.NEGATIVE_LAYERS["tampered-artifact"], "evaluate")
        self.assertEqual(
            [name for name, layer in acceptance.NEGATIVE_LAYERS.items()
             if layer == "collect"],
            ["stale-context", "expired", "tampered-signature", "replay"])
        self.assertEqual(len(acceptance.EVALUATE_REASONS), 5)

    def test_negative_requires_failure_and_expected_reason(self):
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.check_negative(
                "stale-context", "collect", 0, "", "mismatch")
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.check_negative(
                "stale-context", "collect", 1, "some other error", "mismatch")
        record = acceptance.check_negative(
            "stale-context", "collect", 1, "roots/selection mismatch",
            "roots/selection mismatch")
        self.assertTrue(record["passed"])
        self.assertEqual(record["exit"], 1)

    def test_negative_layer_mismatch_fails(self):
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.check_negative(
                "tampered-artifact", "collect", 1, "mismatch", "mismatch")

    def test_report_reasons_walks_nested_reports(self):
        report = {
            "gates": [{"reason": "source identity mismatch"}],
            "policy_result": {"results": [{"reason": "policy limit violated"}]},
        }
        self.assertEqual(set(acceptance.report_reasons(report)),
                         {"source identity mismatch", "policy limit violated"})

    def test_policy_with_limit_does_not_mutate_input(self):
        policy = {"rules": [{"metric": "risk.crap",
                             "limit": {"type": "rational", "numerator": 10,
                                       "denominator": 1}}]}
        changed = acceptance.policy_with_limit(
            policy, "risk.crap",
            {"type": "rational", "numerator": 1, "denominator": 1})
        self.assertEqual(policy["rules"][0]["limit"]["numerator"], 10)
        self.assertEqual(changed["rules"][0]["limit"]["numerator"], 1)


class PinTests(unittest.TestCase):
    def test_published_pins_are_complete(self):
        pins = json.loads(Path(acceptance.__file__).with_name(
            "core_acceptance.json").read_text())
        self.assertEqual(pins["schema"], "rust-source-risk-core-acceptance/v1")
        self.assertEqual(pins["release"]["archive_sha256"],
                         "737eddfffe625c402680d62034e29d02ce95c4ed7c5db7d95ddcc0deb2836eb9")
        self.assertEqual(len(pins["release"]["members"]), 9)
        self.assertEqual(pins["core"]["sha256"],
                         "6b4f36d432266e43e22d82776729d76f04098c5cf63ae2295f508359a37e060c")
        self.assertEqual(pins["core"]["version"], "harness-gate 0.14.1")
        self.assertEqual(pins["fixture"]["target"], "x86_64-unknown-linux-gnu")
        self.assertEqual(len(pins["fixture"]["inputs"]), 4)



class CandidateSeparationTests(unittest.TestCase):
    def candidate_rejection(self, mutate, expected, *, wrong_digest=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'presets').mkdir()
            (root / 'presets/catalog.json').write_text('{}')
            published = json.loads(Path(acceptance.__file__).with_name('core_acceptance.json').read_text())
            pins = {'schema':'rust-source-risk-local-candidate/v1',
                    'candidate':{}, 'core':published['core']}
            mutate(pins)
            path = root / 'pins.json'
            path.write_text(json.dumps(pins))
            argv = ['--pins',str(path),'--pins-sha256','0'*64 if wrong_digest else sha(path.read_bytes()),
                    '--archive',str(root/'missing.tar.gz'),'--sbom',str(root/'missing.sbom.json'),'--bundle',str(root/'bundle.json'),
                    '--core',str(root/'core'),'--output',str(root/'receipt.json'),
                    '--presets-dir',str(root/'presets')]
            with self.assertRaisesRegex(acceptance.AcceptanceError, expected):
                acceptance.main(argv, candidate=True)
            self.assertFalse((root / 'receipt.json').exists())

    def test_candidate_requires_externally_pinned_manifest(self):
        self.candidate_rejection(lambda p: None, 'candidate manifest digest mismatch', wrong_digest=True)

    def test_candidate_cannot_claim_release_or_change_published_core(self):
        self.candidate_rejection(lambda p: p.update(release={}), 'must not claim a published release')
        self.candidate_rejection(lambda p: p['candidate'].update(tag='rust-source-risk-v0.2.0'), 'must not claim a published release')
        self.candidate_rejection(lambda p: p['core'].update(sha256='0'*64), 'must use fixed published Core')

    def test_published_pins_are_rejected_in_candidate_route(self):
        self.candidate_rejection(lambda p: p.update(schema='rust-source-risk-core-acceptance/v1'),
                                 'unexpected acceptance pins schema')



class CandidateSbomTests(unittest.TestCase):
    def test_sbom_binds_version_source_lock_and_bytes(self):
        import copy
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'sbom.json'
            value={'bomFormat':'CycloneDX','metadata':{
                'component':{'name':'harness-gate-rust-source-inventory','version':'0.3.0'},
                'properties':[{'name':'source.commit','value':'a'*40},{'name':'cargo.lock.sha256','value':'b'*64}]}}
            def check(document, bad_digest=False):
                path.write_text(json.dumps(document))
                pins={'candidate':{'version':'0.3.0','source_commit':'a'*40,'members':{'ast/Cargo.lock':'b'*64},
                                   'sbom_sha256':'0'*64 if bad_digest else sha(path.read_bytes())}}
                acceptance.verify_candidate_sbom(path,pins)
            check(value)
            for key in ['version','source','lock','digest']:
                with self.subTest(key=key):
                    wrong=copy.deepcopy(value)
                    if key=='version':wrong['metadata']['component']['version']='0.2.0'
                    if key=='source':wrong['metadata']['properties'][0]['value']='c'*40
                    if key=='lock':wrong['metadata']['properties'][1]['value']='d'*64
                    with self.assertRaises(acceptance.AcceptanceError):check(wrong,bad_digest=key=='digest')


if __name__ == "__main__":
    unittest.main()
