//! Fake protected-root Docker observation tests. No real daemon connection.

use gateprobes_docker_runtime::input::Config;
use gateprobes_docker_runtime::observation;
use gateprobes_docker_runtime::socket_identity::SocketIdentity;
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
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
            "gateprobes-observation-{}-{}",
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
fn config(root: &Root) -> Config {
    Config {
        schema: "gate-runtime-engine-config/v2".into(),
        engine: "docker".into(),
        transport: "unix-http".into(),
        socket_path: root.socket().to_string_lossy().into_owned(),
        socket_uid: euid(),
        principal_uid: euid(),
        rootless: false,
        api_version: "1.47".into(),
        server_version: "27.0.1".into(),
        daemon_id: "daemon-1".into(),
        scope: "scope-1".into(),
    }
}
#[derive(Clone)]
enum Container {
    Json(Value),
    Raw(u16, Vec<u8>),
}
struct Script {
    version: Value,
    info: Value,
    after_info: Option<Value>,
    container: Container,
    delay: Duration,
}
impl Default for Script {
    fn default() -> Self {
        Self {
            version: json!({"Version":"27.0.1","ApiVersion":"1.47","MinAPIVersion":"1.24"}),
            info: json!({"ID":"daemon-1"}),
            after_info: None,
            container: Container::Json(json!({"Id":ID,"Config":{"Labels":{"b":"2","a":"1"}}})),
            delay: Duration::ZERO,
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
        let listener = UnixListener::bind(root.socket()).unwrap();
        listener.set_nonblocking(true).unwrap();
        let path = root.socket();
        let count = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_count = Arc::clone(&count);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let info_hits = AtomicUsize::new(0);
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        thread_count.fetch_add(1, Ordering::SeqCst);
                        let _ = handle(&mut stream, &script, &info_hits);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            path,
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
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.path);
    }
}
fn handle(
    stream: &mut UnixStream,
    script: &Script,
    info_hits: &AtomicUsize,
) -> std::io::Result<()> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..count]);
        if request.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if request.len() > 16_384 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&request);
    let path = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("");
    if !script.delay.is_zero() {
        thread::sleep(script.delay);
    }
    let (status, body) = if path == "/version" {
        (200, serde_json::to_vec(&script.version).unwrap())
    } else if path == "/v1.47/info" {
        let first = info_hits.fetch_add(1, Ordering::SeqCst) == 0;
        let value = if first {
            &script.info
        } else {
            script.after_info.as_ref().unwrap_or(&script.info)
        };
        (200, serde_json::to_vec(value).unwrap())
    } else if path == format!("/v1.47/containers/{ID}/json") {
        match &script.container {
            Container::Json(value) => (200, serde_json::to_vec(value).unwrap()),
            Container::Raw(status, body) => (*status, body.clone()),
        }
    } else {
        (404, b"{\"message\":\"not found\"}".to_vec())
    };
    let head = format!(
        "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&body)
}
struct Observed {
    value: Value,
    connections: usize,
}
fn run_with(script: Script, timeout: Duration, cancelled: impl Fn() -> bool) -> Observed {
    let root = Root::new();
    let cfg = config(&root);
    let fake = Fake::start(&root, script);
    let socket = SocketIdentity::verify(&cfg).unwrap();
    let value = observation::inspect(&cfg, &socket, ID, timeout, &cancelled);
    let connections = fake.connections();
    Observed { value, connections }
}
fn outcome(value: &Value) -> &str {
    value["outcome"].as_str().unwrap_or("object")
}
#[test]
fn present_has_sorted_labels_and_before_after_identity() {
    let observed = run_with(Script::default(), Duration::from_secs(2), || false);
    assert_eq!(outcome(&observed.value), "object");
    assert_eq!(
        observed.value["outcome"]["present"]["object"]["object_id"],
        ID
    );
    assert_eq!(
        observed.value["outcome"]["present"]["object"]["labels"][0]["key"],
        "a"
    );
    assert_eq!(
        observed.value["outcome"]["present"]["object"]["labels"][1]["key"],
        "b"
    );
    assert_eq!(
        observed.value["observations"]["observed_before"]["daemon_id"],
        "daemon-1"
    );
    assert_eq!(
        observed.value["observations"]["observed_after"]["daemon_id"],
        "daemon-1"
    );
    assert_eq!(observed.connections, 5);
}
#[test]
fn raw404_is_unavailable_not_absent() {
    let script = Script {
        container: Container::Raw(404, b"nope".to_vec()),
        ..Script::default()
    };
    let observed = run_with(script, Duration::from_secs(2), || false);
    assert_eq!(
        observed.value,
        json!({"outcome":"unavailable","observations":null})
    );
    assert_eq!(observed.connections, 3);
}
#[test]
fn version_and_minmax_and_info_mismatches_are_unavailable() {
    let mut script = Script::default();
    script.version["Version"] = json!("other");
    assert_eq!(
        run_with(script, Duration::from_secs(2), || false).value,
        json!({"outcome":"unavailable","observations":null})
    );

    let script = Script {
        version: json!({"Version":"27.0.1","ApiVersion":"1.49","MinAPIVersion":"1.48"}),
        ..Script::default()
    };
    assert_eq!(
        outcome(&run_with(script, Duration::from_secs(2), || false).value),
        "unavailable"
    );

    let script = Script {
        info: json!({"ID":"other"}),
        ..Script::default()
    };
    assert_eq!(
        outcome(&run_with(script, Duration::from_secs(2), || false).value),
        "unavailable"
    );
}
#[test]
fn changed_identity_before_after_is_unavailable() {
    let script = Script {
        after_info: Some(json!({"ID":"daemon-2"})),
        ..Script::default()
    };
    let observed = run_with(script, Duration::from_secs(2), || false);
    assert_eq!(outcome(&observed.value), "unavailable");
    assert_eq!(observed.connections, 5);
}
#[test]
fn invalid_labels_are_unavailable() {
    for labels in [
        json!({}),
        json!({"a": 1}),
        json!({"a": " "}),
        json!({"a": "x\u{0}"}),
    ] {
        let script = Script {
            container: Container::Json(json!({"Id":ID,"Config":{"Labels":labels}})),
            ..Script::default()
        };
        assert_eq!(
            outcome(&run_with(script, Duration::from_secs(2), || false).value),
            "unavailable"
        );
    }
}
#[test]
fn invalid_id_cancel_and_timeout_make_no_or_bounded_connections() {
    let root = Root::new();
    let cfg = config(&root);
    let fake = Fake::start(&root, Script::default());
    let socket = SocketIdentity::verify(&cfg).unwrap();
    let value = observation::inspect(
        &cfg,
        &socket,
        &"A".repeat(64),
        Duration::from_secs(2),
        &|| false,
    );
    assert_eq!(value, json!({"outcome":"unavailable","observations":null}));
    assert_eq!(fake.connections(), 0);

    let value = observation::inspect(&cfg, &socket, ID, Duration::from_secs(2), &|| true);
    assert_eq!(value, json!({"outcome":"unavailable","observations":null}));
    assert_eq!(fake.connections(), 0);

    let root = Root::new();
    let cfg = config(&root);
    let script = Script {
        delay: Duration::from_millis(300),
        ..Script::default()
    };
    let fake = Fake::start(&root, script);
    let socket = SocketIdentity::verify(&cfg).unwrap();
    let value = observation::inspect(&cfg, &socket, ID, Duration::from_millis(50), &|| false);
    assert_eq!(value, json!({"outcome":"unavailable","observations":null}));
    assert!(fake.connections() <= 1);
}
#[test]
fn duplicate_json_keys_are_unavailable() {
    let mut script = Script::default();
    let body = format!(r#"{{"Id":"{ID}","Id":"{ID}","Config":{{"Labels":{{"a":"1"}}}}}}"#);
    script.container = Container::Raw(200, body.into_bytes());
    assert_eq!(
        run_with(script, Duration::from_secs(2), || false).value,
        json!({"outcome":"unavailable","observations":null})
    );
}
