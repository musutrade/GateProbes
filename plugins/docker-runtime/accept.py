#!/usr/bin/env python3
"""Accept an extracted native Docker runtime with the released Core 0.7.1 CLI.

The native entry is deliberately argument-free.  Its identity comes from the
explicit --version argument and the SHA-256 of --binary; this command never
invokes the native executable to discover a version.  All trusted acceptance
paths are created under a temporary protected directory.  The fake Docker
socket is local, bounded and disposable; no daemon is contacted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA = "gatehouse-native-docker-acceptance/v1"
CORE_VERSION = "0.7.1"
CORE_VERSION_LINE = f"harness-gate {CORE_VERSION}"
OBJECT_ID = "d" * 64
LIMIT = 65_536
SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
PROTECTED_MODE = 0o600


class AcceptanceError(Exception):
    """The explicit acceptance inputs are not valid."""


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def strict_file(value: str, label: str, executable: bool = True) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise AcceptanceError(f"{label} must be an absolute path")
    if path.is_symlink():
        raise AcceptanceError(f"{label} must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise AcceptanceError(f"{label} is unavailable: {error}") from error
    if resolved != path:
        raise AcceptanceError(f"{label} must be a canonical path")
    try:
        info = path.stat()
    except OSError as error:
        raise AcceptanceError(f"{label} is unavailable: {error}") from error
    if not stat.S_ISREG(info.st_mode):
        raise AcceptanceError(f"{label} must be a regular file")
    if executable and not os.access(path, os.X_OK):
        raise AcceptanceError(f"{label} must be executable")
    if executable:
        try:
            if path.read_bytes()[:4] != b"\x7fELF":
                raise AcceptanceError(f"{label} must be an ELF executable")
        except OSError as error:
            raise AcceptanceError(f"{label} cannot be read: {error}") from error
    return path


def validate_inputs(args: argparse.Namespace) -> tuple[Path, Path, str, Path]:
    binary = strict_file(args.binary, "--binary")
    core = strict_file(args.core, "--core")
    if binary == core:
        raise AcceptanceError("--binary and --core must be distinct files")
    if SEMVER.fullmatch(args.version) is None:
        raise AcceptanceError("--version must be an exact SemVer")
    report = Path(args.report)
    if not report.is_absolute():
        raise AcceptanceError("--report must be an absolute path")
    if report.is_symlink():
        raise AcceptanceError("--report must not be a symlink")
    if report.exists() and report.is_dir():
        raise AcceptanceError("--report must name a file")
    if not report.parent.is_dir():
        raise AcceptanceError("--report parent directory must exist")
    if report.parent.resolve() != report.parent:
        raise AcceptanceError("--report parent must be a canonical path")
    if report in (binary, core):
        raise AcceptanceError("--report must not overwrite an input")
    return binary, core, args.version, report


def core_identity(core: Path) -> tuple[str, str]:
    try:
        result = subprocess.run(
            [str(core), "--version"],
            env={},
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AcceptanceError(f"cannot query --core version: {error}") from error
    actual = result.stdout.strip()
    if result.returncode != 0 or actual != CORE_VERSION_LINE:
        raise AcceptanceError(
            f"--core must be released {CORE_VERSION_LINE}, got {actual or '<empty>'!r}"
        )
    return actual, digest(core)


def write_protected(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, PROTECTED_MODE)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    os.chmod(path, PROTECTED_MODE)


def replace_protected(path: Path, data: bytes) -> None:
    path.unlink()
    write_protected(path, data)


def make_root() -> Path:
    home = Path.home()
    if not home.is_dir():
        raise AcceptanceError("HOME must name an existing protected directory")
    root = Path(tempfile.mkdtemp(prefix="gatehouse-native-accept-", dir=home)).resolve()
    os.chmod(root, 0o700)
    return root


def config_for(socket_path: Path) -> bytes:
    return json.dumps(
        {
            "schema": "gate-runtime-engine-config/v2",
            "engine": "docker",
            "transport": "unix-http",
            "socket_path": str(socket_path),
            "socket_uid": os.geteuid(),
            "principal_uid": os.geteuid(),
            "rootless": False,
            "api_version": "1.47",
            "server_version": "27.0.1",
            "daemon_id": "daemon-1",
            "scope": "scope-1",
        },
        separators=(",", ":"),
    ).encode()


def request_for(
    config: bytes, socket_path: Path, binary_digest: str, version: str, operation: Any
) -> dict[str, Any]:
    return {
        "binding": {
            "protocol": "gate-runtime/v2",
            "adapter_sha256": binary_digest,
            "adapter_version": version,
            "invocation": "inv-1",
            "operation_key": "op-1",
            "generation": "gen-1",
            "adapter_config_sha256": hashlib.sha256(config).hexdigest(),
            "engine": "docker",
            "transport": "unix-http",
            "socket_path": str(socket_path),
            "socket_uid": os.geteuid(),
            "principal_uid": os.geteuid(),
            "rootless": False,
            "api_version": "1.47",
            "server_version": "27.0.1",
            "daemon_id": "daemon-1",
            "scope": "scope-1",
        },
        "operation": operation,
    }


class FakeDocker:
    """Bounded disposable Docker API double; records every server failure."""

    def __init__(self, root: Path, mode: str) -> None:
        self.path = root / "docker.sock"
        self.mode = mode
        self.count = 0
        self.errors: list[str] = []
        self._stop = threading.Event()
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener.bind(str(self.path))
        os.chmod(self.path, 0o600)
        self._listener.listen(8)
        self._listener.settimeout(0.05)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _error(self, message: str) -> None:
        self.errors.append(message[:500])

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError as error:
                if not self._stop.is_set():
                    self._error(f"accept failed: {error}")
                break
            self.count += 1
            try:
                self._serve(connection)
            except Exception as error:  # server faults must fail acceptance
                self._error(f"handler failed: {error!r}")
            finally:
                try:
                    connection.close()
                except OSError:
                    pass

    def _serve(self, connection: socket.socket) -> None:
        connection.settimeout(2)
        data = b""
        while b"\r\n\r\n" not in data and len(data) <= 16_384:
            chunk = connection.recv(1024)
            if not chunk:
                break
            data += chunk
        if b"\r\n\r\n" not in data:
            self._error("request did not terminate its headers")
            return
        first = data.split(b"\r\n", 1)[0].decode("ascii", "strict")
        parts = first.split()
        if len(parts) < 2 or parts[0] != "GET":
            self._error(f"invalid request line: {first!r}")
            return
        path = parts[1]
        if path == "/version":
            status, body = 200, {
                "Version": "27.0.1",
                "ApiVersion": "1.47",
                "MinAPIVersion": "1.24",
            }
        elif path == "/v1.47/info":
            status, body = 200, {"ID": "daemon-1"}
        elif path == f"/v1.47/containers/{OBJECT_ID}/json":
            if self.mode == "404":
                status, body = 404, {"message": "not found"}
            else:
                status, body = 200, {
                    "Id": OBJECT_ID,
                    "Config": {"Labels": {"b": "2", "a": "1"}},
                }
        else:
            self._error(f"unexpected Docker API route: {path}")
            status, body = 404, {"message": "not found"}
        encoded = json.dumps(body, separators=(",", ":")).encode()
        reason = "OK" if status == 200 else "Not Found"
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(encoded)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        connection.sendall(head + encoded)

    def close(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        self._thread.join(timeout=2)
        if self._thread.is_alive():
            self._error("server thread did not stop")
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def add_error(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def run_case(
    name: str,
    root: Path,
    binary: Path,
    binary_digest: str,
    version: str,
    core: Path,
    operation: Any,
    mode: str,
    expect_success: bool,
    expected_connections: int,
    expected_error: str | None = None,
    mutate_host=None,
    mutate_actual=None,
    mutate_config=None,
) -> dict[str, Any]:
    case_root = root / name
    case_root.mkdir(mode=0o700)
    socket_path = case_root / "docker.sock"
    config = config_for(socket_path)
    expected = request_for(config, socket_path, binary_digest, version, operation)
    expected_bytes = json.dumps(expected, separators=(",", ":")).encode()
    actual_value = expected
    if mutate_actual is not None:
        actual_value = json.loads(json.dumps(expected))
        mutate_actual(actual_value)
    actual_bytes = json.dumps(actual_value, separators=(",", ":")).encode()

    write_protected(case_root / "config.json", config)
    write_protected(case_root / "expected.json", expected_bytes)
    write_protected(case_root / "actual.json", actual_bytes)
    host = {
        "schema": "gate-runtime-host/v2",
        "executable": {
            "path": str(binary),
            "sha256": binary_digest,
            "version": version,
        },
        "config": {
            "path": str(case_root / "config.json"),
            "sha256": hashlib.sha256(config).hexdigest(),
            "schema": "gate-runtime-engine-config/v2",
        },
        "expected": {
            "path": str(case_root / "expected.json"),
            "sha256": hashlib.sha256(expected_bytes).hexdigest(),
            "schema": "gate-runtime/v2",
        },
        "cwd": str(case_root),
        "timeout_ms": 5000,
    }
    if mutate_host is not None:
        mutate_host(host)
    write_protected(case_root / "host.json", json.dumps(host, separators=(",", ":")).encode())
    if mutate_config is not None:
        replace_protected(case_root / "config.json", mutate_config(config))

    server = FakeDocker(case_root, mode)
    errors: list[str] = []
    process = None
    try:
        process = subprocess.run(
            [
                str(core),
                "adapter",
                "runtime-probe-v2",
                "--request",
                str(case_root / "actual.json"),
                "--trusted-host",
                str(case_root / "host.json"),
            ],
            cwd=case_root,
            env={},
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        errors.append(f"Core invocation failed: {error!r}")
    finally:
        # Let the adapter's final descriptor checks finish before stopping.
        time.sleep(0.05)
        server.close()
    if server.errors:
        errors.extend(server.errors)

    parsed = None
    if process is not None:
        if expect_success:
            add_error(errors, process.returncode == 0, f"exit {process.returncode}, expected 0")
            add_error(errors, process.stderr == b"", "successful run wrote stderr")
            try:
                parsed = json.loads(process.stdout) if process.stdout else None
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                errors.append(f"stdout is not JSON: {error}")
            add_error(errors, isinstance(parsed, dict), "stdout is not an object")
            if expected_error is not None:
                errors.append("positive case has an expected error")
        else:
            add_error(errors, process.returncode != 0, "refusal exited zero")
            add_error(errors, process.stdout == b"", "refusal wrote stdout")
            if expected_error is not None:
                add_error(
                    errors,
                    expected_error in process.stderr.decode(errors="replace"),
                    f"missing refusal diagnostic {expected_error!r}",
                )
    add_error(
        errors,
        server.count == expected_connections,
        f"connections {server.count}, expected {expected_connections}",
    )

    if expect_success and isinstance(parsed, dict):
        binding = parsed.get("binding", {})
        add_error(errors, binding.get("adapter_sha256") == binary_digest, "wrong adapter digest")
        add_error(errors, binding.get("adapter_version") == version, "wrong adapter version")
        add_error(errors, binding.get("socket_path") == str(socket_path), "wrong socket path")
        add_error(errors, parsed.get("operation") == operation, "wrong operation")
        if name == "capabilities":
            add_error(
                errors,
                parsed.get("outcome") == {"capabilities": {"supported": ["inspect"]}},
                "capabilities outcome is not Inspect-only",
            )
            add_error(errors, parsed.get("observations") is None, "capabilities observed data")
        elif name == "present":
            outcome = parsed.get("outcome")
            expected_object = {
                "object_id": OBJECT_ID,
                "labels": [{"key": "a", "value": "1"}, {"key": "b", "value": "2"}],
            }
            add_error(
                errors,
                outcome == {"present": {"object": expected_object}},
                "present outcome/object mismatch",
            )
            observations = parsed.get("observations")
            identity = {
                "api_version": "1.47",
                "server_version": "27.0.1",
                "daemon_id": "daemon-1",
            }
            add_error(
                errors,
                observations == {
                    "observed_before": identity,
                    "observed_after": identity,
                },
                "present observations mismatch",
            )
        elif name == "unavailable":
            add_error(errors, parsed.get("outcome") == "unavailable", "404 is not Unavailable")
            add_error(errors, parsed.get("observations") is None, "404 has observations")
            add_error(errors, "absent" not in json.dumps(parsed), "404 emitted Absent")

    return {
        "case": name,
        "ok": not errors,
        "errors": errors,
        "exit": None if process is None else process.returncode,
        "connections": server.count,
        "stdout": "" if process is None else process.stdout.decode(errors="replace")[:4000],
        "stderr": "" if process is None else process.stderr.decode(errors="replace")[:2000],
        "server_errors": list(server.errors),
        "parsed": parsed,
    }


def write_report(path: Path, data: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--binary", required=True, help="extracted native adapter")
    command.add_argument("--core", required=True, help="downloaded released Core CLI")
    command.add_argument("--version", required=True, help="explicit native adapter SemVer")
    command.add_argument("--report", required=True, help="JSON acceptance report path")
    return command


def main(argv: list[str] | None = None) -> int:
    command = parser()
    args = command.parse_args(argv)
    try:
        binary, core, version, report = validate_inputs(args)
        core_version, core_digest = core_identity(core)
        binary_digest = digest(binary)
    except AcceptanceError as error:
        command.error(str(error))
    root = make_root()
    try:
        cases = []
        cases.append(
            run_case(
                "capabilities",
                root,
                binary,
                binary_digest,
                version,
                core,
                "capabilities",
                "present",
                True,
                0,
            )
        )
        cases.append(
            run_case(
                "present",
                root,
                binary,
                binary_digest,
                version,
                core,
                {"inspect": {"object_id": OBJECT_ID}},
                "present",
                True,
                5,
            )
        )
        cases.append(
            run_case(
                "unavailable",
                root,
                binary,
                binary_digest,
                version,
                core,
                {"inspect": {"object_id": OBJECT_ID}},
                "404",
                True,
                3,
            )
        )
        cases.append(
            run_case(
                "remove",
                root,
                binary,
                binary_digest,
                version,
                core,
                {"remove": {"object_id": OBJECT_ID}},
                "present",
                False,
                0,
                "runtime mutation refused",
            )
        )
        cases.append(
            run_case(
                "wrong-executable-digest",
                root,
                binary,
                binary_digest,
                version,
                core,
                "capabilities",
                "present",
                False,
                0,
                "runtime executable pin mismatch",
                mutate_host=lambda host: host["executable"].__setitem__("sha256", "0" * 64),
            )
        )
        cases.append(
            run_case(
                "wrong-executable-version",
                root,
                binary,
                binary_digest,
                version,
                core,
                "capabilities",
                "present",
                False,
                0,
                "runtime executable pin mismatch",
                mutate_host=lambda host: host["executable"].__setitem__("version", "9.9.9"),
            )
        )
        cases.append(
            run_case(
                "wrong-actual",
                root,
                binary,
                binary_digest,
                version,
                core,
                "capabilities",
                "present",
                False,
                0,
                "runtime request mismatch",
                mutate_actual=lambda actual: actual["binding"].__setitem__(
                    "operation_key", "different"
                ),
            )
        )
        cases.append(
            run_case(
                "wrong-config-bytes",
                root,
                binary,
                binary_digest,
                version,
                core,
                "capabilities",
                "present",
                False,
                0,
                "runtime protected input rejected",
                mutate_config=lambda config: config + b"\n",
            )
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)
    passed = all(case["ok"] for case in cases)
    data = {
        "schema": SCHEMA,
        "passed": passed,
        "binary": {"path": str(binary), "sha256": binary_digest, "version": version},
        "core": {
            "path": str(core),
            "sha256": core_digest,
            "version": core_version,
        },
        "fake_socket": True,
        "daemon_contacted": False,
        "cases": cases,
    }
    try:
        write_report(report, data)
    except OSError as error:
        command.error(f"cannot write --report: {error}")
    print(f"{'PASS' if passed else 'FAIL'}: {len(cases)} native Docker acceptance cases")
    for case in cases:
        if not case["ok"]:
            print(f"  {case['case']}: {'; '.join(case['errors'])}", file=sys.stderr)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
