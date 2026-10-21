"""Independent filesystem-boundary tests for the offline runtime installer."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/runtime_import"))
sys.path.insert(0, str(Path(__file__).parent))

import install  # noqa: E402
import preflight  # noqa: E402
import test_preflight as fixture  # noqa: E402


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class InstallCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="runtime-install-test-")
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.pin, archive, sbom, inventory, checksums = fixture.valid()
        self.assets = self.root / "assets"
        self.assets.mkdir(mode=0o700)
        (self.assets / fixture.ARCHIVE_NAME).write_bytes(archive)
        (self.assets / (fixture.ARCHIVE_NAME + ".sbom.cdx.json")).write_bytes(sbom)
        (self.assets / "release-inventory.json").write_bytes(inventory)
        (self.assets / "SHA256SUMS").write_bytes(checksums)
        self.pin_path = self.root / "pin.json"
        self.pin_path.write_bytes(self.pin)
        os.chmod(self.pin_path, 0o600)
        self.parent = self.root / "install-parent"
        self.parent.mkdir(mode=0o700)
        self.destination = self.parent / "installation"

    def tearDown(self):
        self.temporary.cleanup()

    def install(self):
        return install.import_release(self.pin_path, self.assets, self.destination)

    def assert_rejected(self):
        with self.assertRaises((install.ImportRejected, preflight.InvalidRelease, OSError, ValueError)):
            self.install()
        self.assertFalse(os.path.lexists(self.destination))

    def test_valid_install_exact_modes_descriptor_and_no_execution(self):
        result = self.install()
        self.assertEqual(result, self.destination / "installation.json")
        for name, data in fixture.FILES.items():
            path = self.destination / name
            self.assertTrue(path.is_file())
            self.assertEqual(path.read_bytes(), data)
            expected = 0o500 if name == preflight.BINARY else 0o400
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected)
        descriptor = json.loads((self.destination / "installation.json").read_text())
        self.assertEqual(descriptor["schema"], "gate-runtime-installation/v1")
        self.assertEqual(descriptor["tag"], "docker-runtime-v0.1.1")
        self.assertEqual(descriptor["source_commit"], fixture.SOURCE)
        self.assertEqual(descriptor["archive_sha256"], sha((self.assets / fixture.ARCHIVE_NAME).read_bytes()))
        self.assertEqual(descriptor["executable"]["path"], str(self.destination / preflight.BINARY))
        self.assertEqual(descriptor["executable"]["sha256"], sha(fixture.FILES[preflight.BINARY]))
        self.assertEqual(descriptor["executable"]["version"], fixture.VERSION)
        self.assertEqual(stat.S_IMODE((self.destination / "installation.json").stat().st_mode), 0o400)

    def test_pin_symlink_fifo_hardlink_mode_oversize_and_parent(self):
        link = self.root / "pin-link"
        link.symlink_to(self.pin_path)
        self.pin_path = link
        self.assert_rejected()

        self.pin_path = self.root / "pin-fifo"
        os.mkfifo(self.pin_path, 0o600)
        self.assert_rejected()

        self.pin_path = self.root / "pin.json"
        hard = self.root / "pin-hard"
        os.link(self.pin_path, hard)
        self.assert_rejected()

        self.pin_path.write_bytes(self.pin)
        os.chmod(self.pin_path, 0o644)
        self.assert_rejected()

        self.pin_path.write_bytes(b"x" * (65536 + 1))
        os.chmod(self.pin_path, 0o600)
        self.assert_rejected()

        self.pin_path.write_bytes(self.pin)
        os.chmod(self.pin_path, 0o600)
        os.chmod(self.parent, 0o777)
        self.assert_rejected()
        os.chmod(self.parent, 0o700)

        linked_parent = self.root / "linked-parent"
        linked_parent.symlink_to(self.parent)
        self.destination = linked_parent / "installation"
        self.assert_rejected()

    def test_destination_existing_and_asset_symlink_fifo_hardlink(self):
        self.destination.mkdir()
        keep = self.destination / "keep"
        keep.write_text("keep")
        with self.assertRaises((install.ImportRejected, preflight.InvalidRelease, OSError, ValueError)):
            self.install()
        self.assertEqual(keep.read_text(), "keep")

        self.destination = self.parent / "next"
        archive = self.assets / fixture.ARCHIVE_NAME
        link = self.root / "asset-link"
        link.symlink_to(archive)
        archive.unlink()
        link.rename(archive)
        self.assert_rejected()

        self.destination = self.parent / "next2"
        archive.unlink()
        os.mkfifo(archive, 0o644)
        self.assert_rejected()

        self.destination = self.parent / "next3"
        archive.unlink()
        (self.assets / "real-archive").write_bytes(fixture.archive())
        os.link(self.assets / "real-archive", archive)
        self.assert_rejected()

        self.destination = self.parent / "next4"
        archive.write_bytes(b"x" * (preflight.MAX_ARCHIVE + 1))
        self.assert_rejected()

    def test_destination_race_is_noreplace_and_preserves_new_target(self):
        real_publish = install.publish

        def race(parent_fd, source, target):
            # The no-replace syscall must lose to a target created after the
            # precheck and preserve whatever appeared there.
            (self.parent / target).mkdir()
            return real_publish(parent_fd, source, target)

        with mock.patch.object(install, "publish", side_effect=race):
            with self.assertRaises(install.ImportRejected):
                self.install()
        self.assertTrue(self.destination.is_dir())
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_input_replacement_is_revalidated_before_publish(self):
        original = install.write_file
        calls = 0

        def mutate_after_first(path, data, mode):
            nonlocal calls
            original(path, data, mode)
            calls += 1
            if calls == 1:
                with (self.assets / fixture.ARCHIVE_NAME).open("ab") as stream:
                    stream.write(b"x")

        with mock.patch.object(install, "write_file", side_effect=mutate_after_first):
            self.assert_rejected()

    def test_write_failure_and_stage_fsync_failure_leave_no_destination(self):
        with mock.patch.object(install, "write_file", side_effect=OSError("write")):
            self.assert_rejected()

        real_fsync = os.fsync
        directory_calls = 0

        def fail_first_directory(fd):
            nonlocal directory_calls
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                directory_calls += 1
                if directory_calls == 1:
                    raise OSError("stage fsync")
            return real_fsync(fd)

        with mock.patch.object(install.os, "fsync", side_effect=fail_first_directory):
            self.assert_rejected()

    def test_publish_failure_leaves_no_destination(self):
        with mock.patch.object(install, "publish", side_effect=OSError("publish")):
            self.assert_rejected()

    def test_parent_fsync_failure_retains_published_destination(self):
        real_fsync = os.fsync
        directory_calls = 0

        def fail_second_directory(fd):
            nonlocal directory_calls
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                directory_calls += 1
                if directory_calls == 2:
                    raise OSError("parent fsync")
            return real_fsync(fd)

        with mock.patch.object(install.os, "fsync", side_effect=fail_second_directory):
            with self.assertRaises(OSError):
                self.install()
        self.assertTrue(self.destination.is_dir())
        self.assertTrue((self.destination / preflight.BINARY).is_file())
        self.assertTrue((self.destination / "installation.json").is_file())

    def test_environment_is_not_used_for_authority(self):
        with mock.patch.dict(os.environ, {"GATEHOUSE_RUNTIME_PIN": "ignored", "GATEHOUSE_CORE": "ignored"}):
            self.install()
        self.assertTrue((self.destination / "installation.json").is_file())

    def test_joint_core_main_capabilities_with_published_assets(self):
        core = os.environ.get("GATEHOUSE_CORE_MAIN")
        assets_dir = os.environ.get("RUNTIME_IMPORT_ASSETS")
        if not core or not assets_dir:
            return
        root = self.root
        asset_path = Path(assets_dir)
        archive_bytes = (asset_path / fixture.ARCHIVE_NAME).read_bytes()
        sbom_bytes = (asset_path / (fixture.ARCHIVE_NAME + ".sbom.cdx.json")).read_bytes()
        inventory_bytes = (asset_path / "release-inventory.json").read_bytes()
        checksum_bytes = (asset_path / "SHA256SUMS").read_bytes()
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as stream:
            binary = stream.extractfile(f"{fixture.PREFIX}/{preflight.BINARY}").read()
        values = json.loads(fixture.pin(archive_bytes, sbom_bytes, inventory_bytes, checksum_bytes))
        values["executable_sha256"] = sha(binary)
        pin_bytes = json.dumps(values, sort_keys=True).encode()
        self.pin_path.write_bytes(pin_bytes)
        os.chmod(self.pin_path, 0o600)
        for name, data in [
            (fixture.ARCHIVE_NAME, archive_bytes),
            (fixture.ARCHIVE_NAME + ".sbom.cdx.json", sbom_bytes),
            ("release-inventory.json", inventory_bytes),
            ("SHA256SUMS", checksum_bytes),
        ]:
            (self.assets / name).write_bytes(data)
        installed = self.install()
        descriptor = installed
        binary_path = descriptor.parent / preflight.BINARY
        socket_path = root / "fake-docker.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        listener.listen(1)
        listener.setblocking(False)
        os.chmod(socket_path, 0o600)
        config = json.dumps({
            "schema": "gate-runtime-engine-config/v2", "engine": "docker", "transport": "unix-http",
            "socket_path": str(socket_path), "socket_uid": os.geteuid(), "principal_uid": os.geteuid(),
            "rootless": False, "api_version": "1.47", "server_version": "27.0.1",
            "daemon_id": "daemon-1", "scope": "scope-1",
        }, separators=(",", ":")).encode()
        digest = sha(binary)
        request = {
            "binding": {
                "protocol": "gate-runtime/v2", "adapter_sha256": digest, "adapter_version": "0.1.1",
                "invocation": "inv-1", "operation_key": "op-1", "generation": "gen-1",
                "adapter_config_sha256": sha(config), "engine": "docker", "transport": "unix-http",
                "socket_path": str(socket_path), "socket_uid": os.geteuid(), "principal_uid": os.geteuid(),
                "rootless": False, "api_version": "1.47", "server_version": "27.0.1",
                "daemon_id": "daemon-1", "scope": "scope-1",
            },
            "operation": "capabilities",
        }
        expected = json.dumps(request, separators=(",", ":")).encode()
        config_path, expected_path, actual_path = root / "config.json", root / "expected.json", root / "actual.json"
        host_path = root / "host.json"
        for path, data in ((config_path, config), (expected_path, expected), (actual_path, expected)):
            path.write_bytes(data); os.chmod(path, 0o600)
        host = {
            "schema": "gate-runtime-host/installed-v1",
            "installation": {"path": str(descriptor), "sha256": sha(descriptor.read_bytes()), "schema": "gate-runtime-installation/v1"},
            "executable": {"path": str(binary_path), "sha256": digest, "version": "0.1.1"},
            "config": {"path": str(config_path), "sha256": sha(config), "schema": "gate-runtime-engine-config/v2"},
            "expected": {"path": str(expected_path), "sha256": sha(expected), "schema": "gate-runtime/v2"},
            "cwd": str(root), "timeout_ms": 5000,
        }
        host_path.write_text(json.dumps(host)); os.chmod(host_path, 0o600)
        result = subprocess.run([core, "adapter", "runtime-probe-installed", "--request", str(actual_path), "--trusted-host", str(host_path)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertEqual(response["outcome"], {"capabilities": {"supported": ["inspect"]}})
        with self.assertRaises(BlockingIOError):
            listener.accept()
        listener.close()


if __name__ == "__main__":
    unittest.main()
