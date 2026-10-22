#!/usr/bin/env python3
"""Joint v3 doctor acceptance with a local fake Unix HTTP socket, never a daemon.
Run with explicitly built Core and gateprobes-docker-readiness ELF paths.
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--version", choices=["0.2.0"], required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    core, adapter = args.core.resolve(strict=True), args.binary.resolve(strict=True)
    version = subprocess.run([str(core), "--version"], capture_output=True, text=True, check=True)
    assert version.stdout.strip() == "harness-gate 0.9.0", "Core0.9.0 required; version alone is not artifact trust"
    base = Path.home() / ".cache"
    for parent in [base, *base.parents]:
        st = parent.lstat()
        assert parent.is_dir() and not parent.is_symlink() and st.st_uid in (0, os.geteuid()) and not st.st_mode & 0o022, "protected HOME/.cache required"
    results = []
    with tempfile.TemporaryDirectory(prefix="joint-v3-", dir=base) as temp:
        root = Path(temp)
        executable = root / "readiness"
        shutil.copyfile(adapter, executable)
        executable.chmod(0o700)
        exe = {"path": str(executable), "sha256": digest(executable.read_bytes()), "version": "0.2.0"}
        installation = write_json(root / "installation.json", {"schema": "gate-runtime-installation/v1", "repository": "fixture-only", "tag": "unreleased", "source_commit": "a" * 40, "archive_sha256": "b" * 64, "executable": exe})
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
        for case in ("present", "missing", "unavailable", "changed", "timeout", "fixed-expected"):
            write_json(host, dict(host_value, **({"expected": "/untrusted"} if case == "fixed-expected" else {})))
            fake = Fake(root / "fake.sock", case)
            try:
                run = subprocess.run([str(core), "--project-root", str(project), "--config", str(flow), "doctor", "--json"], env=env, capture_output=True, text=True, timeout=10)
                assert (run.returncode == 0) == (case == "present"), (case, run.stdout, run.stderr)
                assert not run.stderr, (case, run.stderr)
                report = json.loads(run.stdout)
                assert not marker.exists(), "readiness escaped to legacy CLI"
                if case == "fixed-expected":
                    assert not fake.requests, fake.requests
                elif case == "present":
                    assert fake.requests == ["/version", "/v1.47/info", "/v1.47/images/registry%3A5000%2Frepo%3Atag/json", "/version", "/v1.47/info"], fake.requests
                results.append({"case": case, "exit": run.returncode, "stderr": run.stderr, "requests": fake.requests, "report": report})
            finally:
                fake.close()
                (root / "fake.sock").unlink()
    report = {"passed": len(results), "cases": results,
              "core_sha256": digest(core.read_bytes()), "adapter_sha256": digest(adapter.read_bytes()),
              "limits": "fake socket with supplied binaries; no downloaded-release/daemon/containment proof"}
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
