//! Native compiled-entry tests: sealed fd3/fd4, stdin, noargs, fake socket.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let base = std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".cache"))
            .filter(|path| protected(path))
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", euid())));
        let path = base.join(format!(
            "gateprobes-entry-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn socket(&self) -> PathBuf {
        self.0.join("docker.sock")
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn euid() -> u32 {
    unsafe { libc::geteuid() }
}
fn protected(path: &Path) -> bool {
    path.ancestors().all(|parent| {
        fs::symlink_metadata(parent)
            .map(|m| m.is_dir() && (m.uid() == 0 || m.uid() == euid()) && m.mode() & 0o022 == 0)
            .unwrap_or(false)
    })
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn config_bytes(root: &Root) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema":"gate-runtime-engine-config/v2","engine":"docker","transport":"unix-http",
        "socket_path":root.socket().to_string_lossy(),"socket_uid":euid(),"principal_uid":euid(),
        "rootless":false,"api_version":"1.47","server_version":"27.0.1","daemon_id":"daemon-1","scope":"scope-1"
    })).unwrap()
}
fn request(config: &[u8], operation: Value) -> Value {
    json!({
        "binding": {
            "protocol":"gate-runtime/v2","adapter_sha256":"a".repeat(64),"adapter_version":"0.0.0",
            "invocation":"inv-1","operation_key":"op-1","generation":"gen-1",
            "adapter_config_sha256":digest(config),"engine":"docker","transport":"unix-http",
            "socket_path":"/run/docker.sock","socket_uid":euid(),"principal_uid":euid(),
            "rootless":false,"api_version":"1.47","server_version":"27.0.1","daemon_id":"daemon-1","scope":"scope-1"
        },
        "operation":operation
    })
}
fn request_with_socket(mut value: Value, root: &Root) -> Value {
    value["binding"]["socket_path"] = json!(root.socket().to_string_lossy());
    value
}
fn create_fd(name: &str, bytes: &[u8]) -> OwnedFd {
    let name = std::ffi::CString::new(name).unwrap();
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    assert!(fd >= 0);
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes).unwrap();
    assert_eq!(unsafe { libc::fchmod(file.as_raw_fd(), 0o600) }, 0);
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    assert_eq!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) },
        0
    );
    file.into()
}
fn duplicate(fd: &OwnedFd, minimum: RawFd) -> OwnedFd {
    let copy = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
    assert!(copy >= 0);
    unsafe { OwnedFd::from_raw_fd(copy) }
}
fn run(
    root: &Root,
    expected: Option<Value>,
    config: Option<Vec<u8>>,
    actual: &[u8],
    args: &[&str],
) -> Output {
    let config_fd = config.map(|bytes| duplicate(&create_fd("config", &bytes), 10));
    let expected_bytes =
        expected.map(|value| serde_json::to_vec(&request_with_socket(value, root)).unwrap());
    let expected_fd = expected_bytes.map(|bytes| duplicate(&create_fd("expected", &bytes), 10));
    let mut command = Command::new(env!("CARGO_BIN_EXE_gateprobes-docker-runtime"));
    command
        .args(args)
        .env_clear()
        .current_dir(root_placeholder(root))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut duplicates = Vec::new();
    if let Some(fd) = &config_fd {
        duplicates.push((fd.as_raw_fd(), 3));
    }
    if let Some(fd) = &expected_fd {
        duplicates.push((fd.as_raw_fd(), 4));
    }
    let reserved: Vec<RawFd> = duplicates.iter().map(|(_, target)| *target).collect();
    let dups = duplicates.clone();
    unsafe {
        command.pre_exec(move || {
            for (source, target) in &dups {
                if libc::dup2(*source, *target) < 0 {
                    return Err(std::io::Error::last_os_error());
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
    let mut child = command.spawn().expect("spawn native entry");
    child.stdin.take().unwrap().write_all(actual).unwrap();
    child.wait_with_output().unwrap()
}
fn root_placeholder(root: &Root) -> &Path {
    root.0.as_path()
}
fn fresh_listener(root: &Root) -> UnixListener {
    let _ = fs::remove_file(root.socket());
    UnixListener::bind(root.socket()).unwrap()
}
fn assert_no_connect(listener: &UnixListener) {
    listener.set_nonblocking(true).unwrap();
    assert!(matches!(listener.accept(), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock));
}
#[derive(Clone)]
struct Script {
    container: Value,
}
impl Default for Script {
    fn default() -> Self {
        Self {
            container: json!({"Id":ID,"Config":{"Labels":{"b":"2","a":"1"}}}),
        }
    }
}
struct Fake {
    path: PathBuf,
    count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Fake {
    fn start(root: &Root, script: Script) -> Self {
        let listener = fresh_listener(root);
        listener.set_nonblocking(true).unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let tc = Arc::clone(&count);
        let ts = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !ts.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        tc.fetch_add(1, Ordering::SeqCst);
                        let mut req = Vec::new();
                        let mut b = [0u8; 1024];
                        loop {
                            let n = stream.read(&mut b).unwrap_or(0);
                            if n == 0 {
                                break;
                            }
                            req.extend_from_slice(&b[..n]);
                            if req.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                            if req.len() > 16384 {
                                break;
                            }
                        }
                        let text = String::from_utf8_lossy(&req);
                        let path = text
                            .lines()
                            .next()
                            .and_then(|l| l.split_whitespace().nth(1))
                            .unwrap_or("");
                        let (status, body) = if path == "/version" {
                            (200, serde_json::to_vec(&json!({"Version":"27.0.1","ApiVersion":"1.47","MinAPIVersion":"1.24"})).unwrap())
                        } else if path == "/v1.47/info" {
                            (200, serde_json::to_vec(&json!({"ID":"daemon-1"})).unwrap())
                        } else if path == format!("/v1.47/containers/{ID}/json") {
                            (200, serde_json::to_vec(&script.container).unwrap())
                        } else {
                            (404, b"{}".to_vec())
                        };
                        let head = format!(
                            "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.write_all(&body);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            path: root.socket(),
            count,
            stop,
            thread: Some(thread),
        }
    }
    fn connections(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}
impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = fs::remove_file(&self.path);
    }
}

#[test]
fn capabilities_is_compiled_elf_inspect_only_and_zero_connect() {
    let root = Root::new();
    let listener = fresh_listener(&root);
    let config = config_bytes(&root);
    let output = run(
        &root,
        Some(request(&config, json!("capabilities"))),
        Some(config.clone()),
        &serde_json::to_vec(&request_with_socket(
            request(&config, json!("capabilities")),
            &root,
        ))
        .unwrap(),
        &[],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["outcome"],
        json!({"capabilities":{"supported":["inspect"]}})
    );
    assert_eq!(value["observations"], Value::Null);
    assert_no_connect(&listener);
}
#[test]
fn present_and_unavailable_through_real_entry() {
    let root = Root::new();
    let config = config_bytes(&root);
    let fake = Fake::start(&root, Script::default());
    let expected = request(&config, json!({"inspect":{"object_id":ID}}));
    let actual = serde_json::to_vec(&request_with_socket(expected.clone(), &root)).unwrap();
    let output = run(&root, Some(expected), Some(config.clone()), &actual, &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["outcome"]["present"]["object"]["object_id"], ID);
    assert_eq!(
        value["observations"]["observed_before"]["daemon_id"],
        "daemon-1"
    );
    drop(fake);

    let root = Root::new();
    let config = config_bytes(&root);
    let script = Script {
        container: json!(null),
    };
    let fake = Fake::start(&root, script);
    let expected = request(&config, json!({"inspect":{"object_id":ID}}));
    let actual = serde_json::to_vec(&request_with_socket(expected.clone(), &root)).unwrap();
    let output = run(&root, Some(expected), Some(config.clone()), &actual, &[]);
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["outcome"], "unavailable");
    assert_eq!(value["observations"], Value::Null);
    drop(fake);
}
#[test]
fn remove_mismatch_missing_fd_argv_and_oversize_are_static() {
    assert_remove_and_mismatch_refused();
    assert_missing_fd_and_argv_refused();
    assert_oversize_present_refused();
}

fn assert_refusal(output: &Output, listener: &UnixListener) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_no_connect(listener);
}

fn assert_remove_and_mismatch_refused() {
    let root = Root::new();
    let listener = fresh_listener(&root);
    let config = config_bytes(&root);
    let remove = request(&config, json!({"remove":{"object_id":ID}}));
    let actual = serde_json::to_vec(&request_with_socket(remove.clone(), &root)).unwrap();
    let output = run(&root, Some(remove), Some(config.clone()), &actual, &[]);
    assert_refusal(&output, &listener);

    let root = Root::new();
    let config = config_bytes(&root);
    let listener = fresh_listener(&root);
    let expected = request(&config, json!("capabilities"));
    let mut changed = expected.clone();
    changed["binding"]["operation_key"] = json!("other");
    let output = run(
        &root,
        Some(expected),
        Some(config.clone()),
        &serde_json::to_vec(&request_with_socket(changed, &root)).unwrap(),
        &[],
    );
    assert_refusal(&output, &listener);
}

fn assert_missing_fd_and_argv_refused() {
    let root = Root::new();
    let config = config_bytes(&root);
    let listener = fresh_listener(&root);
    let expected = request(&config, json!("capabilities"));
    let output = run(&root, Some(expected), None, b"", &[]);
    assert_refusal(&output, &listener);

    let root = Root::new();
    let config = config_bytes(&root);
    let listener = fresh_listener(&root);
    let output = run(
        &root,
        Some(request(&config, json!("capabilities"))),
        Some(config.clone()),
        b"",
        &["--bad"],
    );
    assert_refusal(&output, &listener);
}

fn assert_oversize_present_refused() {
    let root = Root::new();
    let config = config_bytes(&root);
    let labels = "x".repeat(70_000);
    let script = Script {
        container: json!({"Id":ID,"Config":{"Labels":{"a":labels}}}),
    };
    let fake = Fake::start(&root, script);
    let expected = request(&config, json!({"inspect":{"object_id":ID}}));
    let actual = serde_json::to_vec(&request_with_socket(expected.clone(), &root)).unwrap();
    let output = run(&root, Some(expected), Some(config.clone()), &actual, &[]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(fake.connections() > 0);
}
#[test]
fn invalid_input_does_not_echo_sentinel() {
    let root = Root::new();
    let config = config_bytes(&root);
    let listener = fresh_listener(&root);
    let mut expected = request(&config, json!("capabilities"));
    expected["binding"]["adapter_version"] = json!("");
    let output = run(
        &root,
        Some(expected),
        Some(config.clone()),
        b"SENTINEL-NATIVE-ENTRY",
        &[],
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("SENTINEL"));
    assert!(!stderr.contains("/run/docker.sock"));
    assert_no_connect(&listener);
}
