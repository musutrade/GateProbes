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
            "gateprobes-v3-entry-{}-{}",
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
        "schema":"gate-runtime-engine-config/v3","engine":"docker","transport":"unix-http",
        "socket_path":root.socket().to_string_lossy(),"socket_uid":euid(),"principal_uid":euid(),
        "rootless":false,"api_version":"1.47","server_version":"27.0.1","daemon_id":"daemon-1","scope":"scope-1"
    })).unwrap()
}
fn request(config: &[u8], operation: Value) -> Value {
    json!({
        "binding": {
            "protocol":"gate-runtime/v3","adapter_sha256":"a".repeat(64),"adapter_version":"0.2.0",
            "invocation":"1".repeat(32),"operation_key":"b".repeat(64),"generation":"c".repeat(64),
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
    let mut command = Command::new(env!("CARGO_BIN_EXE_gateprobes-docker-readiness"));
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
            container: json!({"Id":format!("sha256:{ID}")}),
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
                        } else if path == "/v1.47/images/repo%3Atag/json" {
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
fn sealed_request_reaches_dedicated_v3_entry() {
    let root = Root::new();
    let cfg = config_bytes(&root);
    let fake = Fake::start(&root, Script::default());
    let expected = request(&cfg, json!({"readiness":{"image":"repo:tag"}}));
    let actual = serde_json::to_vec(&request_with_socket(expected.clone(), &root)).unwrap();
    let out = run(&root, Some(expected), Some(cfg), &actual, &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["outcome"]["readiness"]["image_present"], true);
    assert_eq!(fake.connections(), 5);
}
#[test]
fn v2_capabilities_remove_and_changed_actual_refused_without_connect() {
    for operation in [
        json!("capabilities"),
        json!({"inspect":{"object_id":ID}}),
        json!({"remove":{"object_id":ID}}),
        json!({"readiness":{"image":"bad?image"}}),
    ] {
        let root = Root::new();
        let listener = fresh_listener(&root);
        let cfg = config_bytes(&root);
        let req = request(&cfg, operation);
        let actual = serde_json::to_vec(&request_with_socket(req.clone(), &root)).unwrap();
        let out = run(&root, Some(req), Some(cfg), &actual, &[]);
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
        assert_no_connect(&listener);
    }
    let root = Root::new();
    let listener = fresh_listener(&root);
    let cfg = config_bytes(&root);
    let req = request(&cfg, json!({"readiness":{"image":"repo:tag"}}));
    let mut actual = request_with_socket(req.clone(), &root);
    actual["binding"]["invocation"] = json!("2".repeat(32));
    let out = run(
        &root,
        Some(req),
        Some(cfg),
        &serde_json::to_vec(&actual).unwrap(),
        &[],
    );
    assert!(!out.status.success());
    assert_no_connect(&listener);
}
#[test]
fn missing_sealed_inputs_and_argv_are_refused_without_connect() {
    for missing in [true, false] {
        let root = Root::new();
        let listener = fresh_listener(&root);
        let cfg = config_bytes(&root);
        let req = request(&cfg, json!({"readiness":{"image":"repo:tag"}}));
        let actual = serde_json::to_vec(&request_with_socket(req.clone(), &root)).unwrap();
        let out = if missing {
            run(&root, None, Some(cfg), &actual, &[])
        } else {
            run(&root, Some(req), Some(cfg), &actual, &["--unexpected"])
        };
        assert!(!out.status.success());
        assert_no_connect(&listener);
    }
}
