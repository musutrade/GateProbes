#!/usr/bin/env python3
"""Joint v3 doctor acceptance with a local fake Unix HTTP socket, never a daemon.
Exercise the extracted importer, then its installed descriptor and executable.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_bytes(json.dumps(value, separators=(",", ":")).encode())
    path.chmod(0o600)
    return {"path": str(path), "sha256": digest(path.read_bytes()), "schema": value["schema"]}


class Fake:
    def __init__(self, path, case):
        self.case, self.requests, self.stop = case, [], threading.Event()
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(str(path))
        self.sock.listen(8)
        self.sock.settimeout(0.05)
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.sock.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(1)
                raw = b""
                while b"\r\n\r\n" not in raw and len(raw) < 16384:
                    chunk = connection.recv(1024)
                    if not chunk:
                        break
                    raw += chunk
                route = raw.split(b" ")[1].decode()
                self.requests.append(route)
                status = 200
                if route == "/version":
                    value = {"Version": "27.0.1", "ApiVersion": "1.47", "MinAPIVersion": "1.24"}
                elif route == "/v1.47/info":
                    value = {"ID": "other" if self.case == "changed" and len(self.requests) > 3 else "daemon-1"}
                elif route == "/v1.47/images/registry%3A5000%2Frepo%3Atag/json":
                    value = {"Id": "sha256:" + "a" * 64}
                    if self.case == "missing":
                        status, value = 404, {"message": "No such image"}
                    elif self.case == "unavailable":
                        status, value = 500, {"message": "failure"}
                    elif self.case == "timeout":
                        time.sleep(1.2)
                else:
                    status, value = 500, {"message": "unexpected route"}
                body = json.dumps(value).encode()
                try:
                    connection.sendall(f"HTTP/1.1 {status} OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

    def close(self):
        self.stop.set()
        self.thread.join(timeout=3)
        assert not self.thread.is_alive()
        self.sock.close()


def accept(args, bundle):
    core, assets = args.core.resolve(strict=True), args.assets.resolve(strict=True)
    from importer_core_v3 import EXPECTED
    pin = json.loads((bundle / 'plugins/runtime-importer/core-pin-v3.json').read_bytes())
    assert pin == EXPECTED and digest(core.read_bytes()) == pin['sha256'], 'Core0.9 pin mismatch'
    version = subprocess.run([str(core), '--version'], capture_output=True, text=True, check=True)
    assert version.stdout.strip() == 'harness-gate 0.9.0' and not version.stderr
    base = Path.home() / ".cache"
    for parent in [base, *base.parents]:
        st = parent.lstat()
        assert parent.is_dir() and not parent.is_symlink() and st.st_uid in (0, os.geteuid()) and not st.st_mode & 0o022, "protected HOME/.cache required"
    results = []
    with tempfile.TemporaryDirectory(prefix="joint-v3-", dir=base) as temp:
        root = Path(temp)
        reviewed = bundle / 'tools/runtime_import/release-pin-v3.json'
        runtime = json.loads(reviewed.read_bytes())
        assert runtime['tag'] == 'docker-readiness-v0.2.0'
        local_pin = root / 'pin.json'
        local_pin.write_bytes(reviewed.read_bytes()); local_pin.chmod(0o600)
        installed = root / 'installed'
        command = ['python3', '-I', '-B', str(bundle / 'tools/runtime_import/install.py'),
                   '--pin', str(local_pin), '--assets', str(assets), '--destination', str(installed)]
        isolated = dict(os.environ, PYTHONPATH='', HOME=str(root))
        installation_run = subprocess.run(command, cwd=root, env=isolated, capture_output=True, timeout=30)
        assert installation_run.returncode == 0 and not installation_run.stderr, installation_run.stderr
        executable = installed / 'gateprobes-docker-readiness'
        descriptor = installed / 'installation.json'
        exe = {'path':str(executable), 'sha256':runtime['executable_sha256'], 'version':'0.2.0'}
        expected_descriptor = {'schema':'gate-runtime-installation/v1', 'repository':runtime['repository'],
            'tag':runtime['tag'], 'source_commit':runtime['source_commit'],
            'archive_sha256':runtime['archive_sha256'], 'executable':exe}
        assert json.loads(descriptor.read_bytes()) == expected_descriptor
        assert digest(executable.read_bytes()) == exe['sha256']
        for member in installed.iterdir():
            assert member.stat().st_mode & 0o777 == (0o500 if member == executable else 0o400)
        installation = {'path':str(descriptor), 'sha256':digest(descriptor.read_bytes()), 'schema':'gate-runtime-installation/v1'}
        original_descriptor, original_executable = descriptor.read_bytes(), executable.read_bytes()
        config = write_json(root / "engine.json", {"schema": "gate-runtime-engine-config/v3", "engine": "docker", "transport": "unix-http", "socket_path": str(root / "fake.sock"), "socket_uid": os.geteuid(), "principal_uid": os.geteuid(), "rootless": False, "api_version": "1.47", "server_version": "27.0.1", "daemon_id": "daemon-1", "scope": "fake-only"})
        host = root / "host.json"
        host_value = {"schema": "gate-runtime-host/installed-v2", "installation": installation, "executable": exe, "config": config, "cwd": str(root), "timeout_ms": 1000}
        write_json(host, host_value)
        project = root / "project"
        project.mkdir()
        subprocess.run(["git", "init", "-q", str(project)], check=True)
        subprocess.run([str(core), "--project-root", str(project), "init", "--preset", "generic"], check=True, capture_output=True, text=True)
        flow = project / "flow.toml"
        flow.write_text(f'''version = 2
[project]
name = "readiness-fixture"
default_profile = "full"
hook_profile = "full"
[paths]
reports = ".harness-gate/reports"
audit_config = ".harness-gate/audit.toml"
[policy]
required_steps = ["noop"]
[scope]
unmatched = "all"
[[scope.rules]]
patterns = ["**"]
components = ["app"]
[services.fixture]
kind = "docker"
readiness_host = {json.dumps(str(host))}
image = "registry:5000/repo:tag"
inject_env = "FIXTURE_URL"
startup_timeout_secs = 2
container_port = 1234
healthcheck = ["true"]
connection = "fixture:{{host_port}}"
[[doctor.checks]]
id = "fixture.readiness"
label = "v3 fixture readiness"
kind = "service"
service = "fixture"
required = true
timeout_secs = 2
[[steps]]
id = "noop"
label = "unused"
component = "app"
profiles = ["full"]
program = "true"
args = []
cwd = "{{root}}"
log = "noop.log"
timeout_secs = 1
''')
        fakebin = root / "fakebin"
        fakebin.mkdir()
        marker = root / "legacy-cli-called"
        for name in ("docker", "podman"):
            script = fakebin / name
            script.write_text(f"#!/bin/sh\nprintf called >> '{marker}'\nexit 77\n")
            script.chmod(0o700)
        env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ.get("PATH", ""))
        for case in ("present", "missing", "unavailable", "changed", "timeout", "fixed-expected", "tampered-descriptor", "tampered-executable"):
            write_json(host, dict(host_value, **({"expected": "/untrusted"} if case == "fixed-expected" else {})))
            descriptor.chmod(0o600); descriptor.write_bytes(original_descriptor); descriptor.chmod(0o400)
            executable.chmod(0o700); executable.write_bytes(original_executable); executable.chmod(0o500)
            if case == 'tampered-descriptor':
                descriptor.chmod(0o600); descriptor.write_bytes(original_descriptor + b' '); descriptor.chmod(0o400)
            if case == 'tampered-executable':
                executable.chmod(0o700); executable.write_bytes(b'tampered'); executable.chmod(0o500)
            fake = Fake(root / "fake.sock", case)
            try:
                run = subprocess.run([str(core), "--project-root", str(project), "--config", str(flow), "doctor", "--json"], env=env, capture_output=True, text=True, timeout=10)
                assert (run.returncode == 0) == (case == "present"), (case, run.stdout, run.stderr)
                assert not run.stderr, (case, run.stderr)
                report = json.loads(run.stdout)
                assert report['failures'] == (0 if case == 'present' else 1)
                assert len(report['checks']) == 1
                assert report['checks'][0]['level'] == ('pass' if case == 'present' else 'fail')
                assert not marker.exists(), "readiness escaped to legacy CLI"
                if case in ("fixed-expected", "tampered-descriptor", "tampered-executable"):
                    assert not fake.requests, fake.requests
                elif case == "present":
                    assert fake.requests == ["/version", "/v1.47/info", "/v1.47/images/registry%3A5000%2Frepo%3Atag/json", "/version", "/v1.47/info"], fake.requests
                results.append({"case": case, "exit": run.returncode, "stderr": run.stderr, "requests": fake.requests, "report": report})
            finally:
                fake.close()
                (root / "fake.sock").unlink()
    report = {"passed": len(results), "cases": results,
              "importer_archive_sha256": args.archive_sha256,
              "importer_sbom_sha256": args.sbom_sha256,
              "readiness_archive_sha256": runtime['archive_sha256'],
              "installed_descriptor_sha256": digest(original_descriptor),
              "core_sha256": digest(core.read_bytes()), "adapter_sha256": runtime["executable_sha256"],
              "runtime_tag": runtime["tag"], "limits": "extracted importer and installed-v3 readiness with downloaded inputs; fake socket only, no daemon/containment proof"}
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--sbom', type=Path, required=True)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--sbom-sha256', required=True)
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    from verify_importer_archive import extract, LIMIT
    def bounded(path):
        with path.open('rb') as stream:
            return stream.read(LIMIT + 1)
    # The verifier is loaded from this trusted checkout before extraction, never
    # from the supplied archive. Version authority is fixed by this v3 caller.
    with tempfile.TemporaryDirectory(prefix='importer-v3-verified-', dir=Path.home()) as temporary:
        bundle = extract(bounded(args.archive), bounded(args.sbom), args.archive_sha256,
                         args.sbom_sha256, Path(temporary) / 'verified', '0.2.0')
        accept(args, bundle)


if __name__ == "__main__":
    main()
