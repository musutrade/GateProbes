//! Independent Linux bootstrap tests. The test binary doubles as a child helper
//! invoked with no arguments so the real bootstrap argv boundary is exercised.

use gateprobes_docker_runtime::bootstrap;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const HELPER_ENV: &str = "GATEPROBES_BOOTSTRAP_HELPER";
const OUT_ENV: &str = "GATEPROBES_BOOTSTRAP_OUT";
const LIMIT: usize = 65_536;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn test_dir() -> TestDir {
    let path = std::env::temp_dir().join(format!(
        "gateprobes-bootstrap-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    TestDir(path)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn config_value() -> Value {
    json!({
        "schema": "gate-runtime-engine-config/v2",
        "engine": "docker",
        "transport": "unix-http",
        "socket_path": "/run/docker.sock",
        "socket_uid": 1000,
        "principal_uid": 1000,
        "rootless": false,
        "api_version": "1.47",
        "server_version": "27.0.1",
        "daemon_id": "daemon-1",
        "scope": "scope-1"
    })
}

fn fixtures() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let config = serde_json::to_vec(&config_value()).unwrap();
    let expected = serde_json::to_vec(&json!({
        "binding": {
            "protocol": "gate-runtime/v2",
            "adapter_sha256": "a".repeat(64),
            "adapter_version": "1.0.0",
            "invocation": "inv-1",
            "operation_key": "op-1",
            "generation": "gen-1",
            "adapter_config_sha256": digest(&config),
            "engine": "docker",
            "transport": "unix-http",
            "socket_path": "/run/docker.sock",
            "socket_uid": 1000,
            "principal_uid": 1000,
            "rootless": false,
            "api_version": "1.47",
            "server_version": "27.0.1",
            "daemon_id": "daemon-1",
            "scope": "scope-1"
        },
        "operation": "capabilities"
    }))
    .unwrap();
    let actual = expected.clone();
    (config, expected, actual)
}

fn create_fd(name: &str, bytes: &[u8], seals: bool, mode: u32) -> OwnedFd {
    let name = std::ffi::CString::new(name).unwrap();
    let flags = libc::MFD_CLOEXEC | if seals { libc::MFD_ALLOW_SEALING } else { 0 };
    let fd = unsafe { libc::memfd_create(name.as_ptr(), flags) };
    assert!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes).unwrap();
    assert_eq!(unsafe { libc::fchmod(file.as_raw_fd(), mode) }, 0);
    if seals {
        let required =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, required) },
            0
        );
    }
    file.into()
}

fn duplicate_high(file: &File, minimum: RawFd) -> OwnedFd {
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
    assert!(fd >= 0);
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn duplicate_fd(fd: &OwnedFd, minimum: RawFd) -> OwnedFd {
    let copy = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
    assert!(copy >= 0);
    unsafe { OwnedFd::from_raw_fd(copy) }
}

struct Run {
    status: std::process::ExitStatus,
    output: String,
}

fn run_case(
    directory: &Path,
    config: Option<OwnedFd>,
    expected: Option<OwnedFd>,
    extra: Option<OwnedFd>,
    actual: &[u8],
    args: &[&str],
    offsets: bool,
) -> Run {
    let out = directory.join("result.txt");
    let config = config.map(|fd| duplicate_fd(&fd, 10));
    let expected = expected.map(|fd| duplicate_fd(&fd, 10));
    let extra = extra.map(|fd| duplicate_fd(&fd, 10));
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(args);
    command.env(HELPER_ENV, "1").env(OUT_ENV, &out);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut duplicates = Vec::new();
    if let Some(fd) = &config {
        duplicates.push((fd.as_raw_fd(), 3));
    }
    if let Some(fd) = &expected {
        duplicates.push((fd.as_raw_fd(), 4));
    }
    if let Some(fd) = &extra {
        duplicates.push((fd.as_raw_fd(), 5));
    }
    let mut reserved: Vec<RawFd> = duplicates.iter().map(|(_, target)| *target).collect();
    reserved.sort_unstable();
    reserved.dedup();
    let dups = duplicates.clone();
    unsafe {
        command.pre_exec(move || {
            for (source, target) in &dups {
                if libc::dup2(*source, *target) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if offsets {
                for target in [3, 4] {
                    libc::lseek(target, 0, libc::SEEK_END);
                }
            }
            for fd in 3..2048 {
                if !reserved.contains(&fd) {
                    libc::close(fd);
                }
            }
            Ok(())
        });
    }
    let mut child = command.spawn().expect("spawn helper");
    child.stdin.take().unwrap().write_all(actual).unwrap();
    let status = child.wait().unwrap();
    let output = fs::read_to_string(out).unwrap_or_default();
    Run { status, output }
}

#[test]
fn bootstrap_helper() {
    let Ok(_) = std::env::var(HELPER_ENV) else {
        bootstrap_matrix();
        return;
    };
    let out = PathBuf::from(std::env::var_os(OUT_ENV).expect("helper output"));
    let result = match bootstrap::read() {
        Ok((request, config)) => format!("ok {} {}", request.binding.scope, config.scope),
        Err(error) => format!("err {error}"),
    };
    fs::write(out, result).unwrap();
}

fn bootstrap_matrix() {
    // The unprivileged test process cannot create a foreign-uid memfd. Owner/euid
    // checks therefore rely on the implementation plus wrong-mode/regular-file
    // negatives; no root-owned positive claim is made here.
    let root = test_dir();
    let (config, expected, actual) = fixtures();

    let run = run_case(
        root.path(),
        Some(create_fd("config", &config, true, 0o600)),
        Some(create_fd("expected", &expected, true, 0o600)),
        None,
        &actual,
        &[],
        false,
    );
    assert!(run.status.success());
    assert_eq!(run.output, "ok scope-1 scope-1", "valid sealed inputs");

    let run = run_case(
        root.path(),
        None,
        Some(create_fd("expected", &expected, true, 0o600)),
        None,
        &actual,
        &[],
        false,
    );
    assert!(run.output.starts_with("err "), "missing fd3");
    let run = run_case(
        root.path(),
        Some(create_fd("config", &config, true, 0o600)),
        None,
        None,
        &actual,
        &[],
        false,
    );
    assert!(run.output.starts_with("err "), "missing fd4");
    let run = run_case(
        root.path(),
        Some(create_fd("config", &config, false, 0o600)),
        Some(create_fd("expected", &expected, true, 0o600)),
        None,
        &actual,
        &[],
        false,
    );
    assert!(run.output.starts_with("err "), "unsealed fd3");
    let run = run_case(
        root.path(),
        Some(create_fd("config", &config, true, 0o644)),
        Some(create_fd("expected", &expected, true, 0o600)),
        None,
        &actual,
        &[],
        false,
    );
    assert!(run.output.starts_with("err "), "wrong mode");
    let run = run_case(
        root.path(),
        Some(create_fd("config", &config, true, 0o600)),
        Some(create_fd("expected", &expected, false, 0o600)),
        None,
        &actual,
        &[],
        false,
    );
    assert!(run.output.starts_with("err "), "unsealed fd4");

    let run = run_case(
        root.path(),
        Some(create_fd("config", &config, true, 0o600)),
        Some(create_fd("expected", &vec![b'x'; LIMIT + 1], true, 0o600)),
        None,
        &actual,
        &[],
        false,
    );
    assert!(run.output.starts_with("err "), "oversize fd4");

    let run = run_case(
        root.path(),
        Some(create_fd("config", &config, true, 0o600)),
        Some(create_fd("expected", &expected, true, 0o600)),
        Some(create_fd("extra", b"extra", true, 0o600)),
        &actual,
        &[],
        false,
    );
    assert!(run.output.starts_with("err "), "extra live fd");

    let regular_path = root.path().join("regular-config");
    let mut regular = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&regular_path)
        .unwrap();
    regular.write_all(&config).unwrap();
    let regular = duplicate_high(&regular, 10);
    let run = run_case(
        root.path(),
        Some(regular),
        Some(create_fd("expected", &expected, true, 0o600)),
        None,
        &actual,
        &[],
        false,
    );
    assert!(run.output.starts_with("err "), "regular-file fd");

    let oversized = vec![b'x'; LIMIT + 1];
    let run = run_case(
        root.path(),
        Some(create_fd("oversize", &oversized, true, 0o600)),
        Some(create_fd("expected", &expected, true, 0o600)),
        None,
        &actual,
        &[],
        false,
    );
    assert!(run.output.starts_with("err "), "oversize fd3");

    let run = run_case(
        root.path(),
        Some(create_fd("config", &config, true, 0o600)),
        Some(create_fd("expected", &expected, true, 0o600)),
        None,
        &actual,
        &["--exact", "bootstrap_helper"],
        false,
    );
    assert!(run.output.starts_with("err "), "arguments rejected");

    let run = run_case(
        root.path(),
        Some(create_fd("config", &config, true, 0o600)),
        Some(create_fd("expected", &expected, true, 0o600)),
        None,
        &actual,
        &[],
        true,
    );
    assert_eq!(run.output, "ok scope-1 scope-1", "pread ignores offsets");

    let mut changed = expected.clone();
    changed[0] = b' ';
    let run = run_case(
        root.path(),
        Some(create_fd("config", &config, true, 0o600)),
        Some(create_fd("expected", &expected, true, 0o600)),
        None,
        &changed,
        &[],
        false,
    );
    assert!(run.output.starts_with("err "), "actual mismatch");

    let run = run_case(
        root.path(),
        Some(create_fd("config", &config, true, 0o600)),
        Some(create_fd("expected", &expected, true, 0o600)),
        None,
        &vec![b' '; LIMIT + 1],
        &[],
        false,
    );
    assert!(run.output.starts_with("err "), "oversize actual");
}
