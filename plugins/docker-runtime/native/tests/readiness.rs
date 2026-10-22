//! Fake protected-root Docker observation tests. No real daemon connection.

use gateprobes_docker_runtime::input::Config;
use gateprobes_docker_runtime::readiness;
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
            "gateprobes-readiness-{}-{}",
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
        schema: "gate-runtime-engine-config/v3".into(),
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
    after_version: Option<Value>,
    image_path: String,
    container: Container,
    delay: Duration,
    delay_on: Option<String>,
}
impl Default for Script {
    fn default() -> Self {
        Self {
            version: json!({"Version":"27.0.1","ApiVersion":"1.47","MinAPIVersion":"1.24"}),
            info: json!({"ID":"daemon-1"}),
            after_info: None,
            after_version: None,
            image_path: "/v1.47/images/registry%3A5000%2Frepo%3Atag/json".into(),
            container: Container::Json(json!({"Id":format!("sha256:{ID}")})),
            delay: Duration::ZERO,
            delay_on: None,
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
fn read_route(stream: &mut UnixStream) -> std::io::Result<String> {
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
    Ok(text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("")
        .to_owned())
}
fn handle(
    stream: &mut UnixStream,
    script: &Script,
    info_hits: &AtomicUsize,
) -> std::io::Result<()> {
    let path = read_route(stream)?;
    if !script.delay.is_zero()
        && script
            .delay_on
            .as_deref()
            .is_none_or(|target| target == path)
    {
        thread::sleep(script.delay);
    }
    let (status, body) = if path == "/version" {
        (
            200,
            serde_json::to_vec(if info_hits.load(Ordering::SeqCst) > 0 {
                script.after_version.as_ref().unwrap_or(&script.version)
            } else {
                &script.version
            })
            .unwrap(),
        )
    } else if path == "/v1.47/info" {
        let first = info_hits.fetch_add(1, Ordering::SeqCst) == 0;
        let value = if first {
            &script.info
        } else {
            script.after_info.as_ref().unwrap_or(&script.info)
        };
        (200, serde_json::to_vec(value).unwrap())
    } else if path == script.image_path {
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
fn run_with(
    script: Script,
    image: &str,
    timeout: Duration,
    cancelled: impl Fn() -> bool,
) -> Observed {
    let root = Root::new();
    let cfg = config(&root);
    let fake = Fake::start(&root, script);
    let socket = SocketIdentity::verify(&cfg).unwrap();
    let value = readiness::check(&cfg, &socket, image, timeout, &cancelled);
    Observed {
        value,
        connections: fake.connections(),
    }
}
const IMAGE: &str = "registry:5000/repo:tag";
fn unavailable(v: &Value) {
    assert_eq!(v["outcome"], "unavailable");
    assert!(v["observations"].is_null());
}
#[test]
fn exact_encoded_tag_lookup_has_five_requests_and_stable_observations() {
    let r = run_with(Script::default(), IMAGE, Duration::from_secs(2), || false);
    assert_eq!(r.value["outcome"]["readiness"]["image_present"], true);
    assert_eq!(
        r.value["outcome"]["readiness"]["image_id"],
        format!("sha256:{ID}")
    );
    assert_eq!(
        r.value["observations"]["observed_before"],
        r.value["observations"]["observed_after"]
    );
    assert_eq!(r.connections, 5);
}
#[test]
fn only_exact_image_404_is_missing_other_failures_are_unavailable() {
    for (status, body) in [
        (404, br#"{"message":"No such image"}"#.to_vec()),
        (403, b"{}".to_vec()),
        (500, b"{}".to_vec()),
        (200, b"not json".to_vec()),
        (200, b"{}".to_vec()),
        (200, br#"{"Id":"wrong"}"#.to_vec()),
        (
            200,
            format!(r#"{{"Id":"sha256:{ID}","Id":"sha256:{ID}"}}"#).into_bytes(),
        ),
    ] {
        let script = Script {
            container: Container::Raw(status, body),
            ..Script::default()
        };
        let r = run_with(script, IMAGE, Duration::from_secs(2), || false);
        if status == 404 {
            assert_eq!(
                r.value["outcome"]["readiness"],
                json!({"image_present":false})
            );
            assert_eq!(r.connections, 5);
            assert!(r.value["observations"].is_object());
        } else {
            unavailable(&r.value);
        }
    }
}
#[test]
fn identity_changes_and_api_range_fail_closed() {
    let mut scripts = Vec::new();
    scripts.push(Script {
        after_info: Some(json!({"ID":"changed"})),
        ..Script::default()
    });
    scripts.push(Script {
        after_version: Some(
            json!({"Version":"changed","ApiVersion":"1.47","MinAPIVersion":"1.24"}),
        ),
        ..Script::default()
    });
    scripts.push(Script {
        version: json!({"Version":"27.0.1","ApiVersion":"1.46","MinAPIVersion":"1.24"}),
        ..Script::default()
    });
    scripts.push(Script {
        info: json!({"ID":"other"}),
        ..Script::default()
    });
    for s in scripts {
        unavailable(&run_with(s, IMAGE, Duration::from_secs(2), || false).value);
    }
}
#[test]
fn full_repo_digest_must_match_and_at_sign_is_encoded() {
    let image = format!("registry:5000/repo@sha256:{ID}");
    for digests in [
        json!([image]),
        json!([format!("other@sha256:{ID}")]),
        json!([]),
        Value::Null,
    ] {
        let matches = digests == json!([image]);
        let s = Script {
            image_path: format!("/v1.47/images/registry%3A5000%2Frepo%40sha256%3A{ID}/json"),
            container: Container::Json(json!({"Id":format!("sha256:{ID}"),"RepoDigests":digests})),
            ..Script::default()
        };
        let r = run_with(s, &image, Duration::from_secs(2), || false);
        if matches {
            assert_eq!(r.value["outcome"]["readiness"]["image_present"], true);
        } else {
            unavailable(&r.value);
        }
    }
}
#[test]
fn invalid_reference_and_initial_cancel_never_connect() {
    for image in [
        "",
        "-x",
        "a?b",
        "a#b",
        "a/../b",
        "a//b",
        "é",
        "a@sha256:bad",
    ] {
        let r = run_with(Script::default(), image, Duration::from_secs(2), || false);
        unavailable(&r.value);
        assert_eq!(r.connections, 0);
    }
    let r = run_with(Script::default(), IMAGE, Duration::from_secs(2), || true);
    unavailable(&r.value);
    assert_eq!(r.connections, 0);
}
#[test]
fn one_deadline_bounds_delayed_observations() {
    let r = run_with(
        Script {
            delay: Duration::from_millis(100),
            ..Script::default()
        },
        IMAGE,
        Duration::from_millis(20),
        || false,
    );
    unavailable(&r.value);
    assert!(r.connections <= 1);
}
#[test]
fn socket_replacement_and_missing_socket_cannot_be_readiness() {
    let root = Root::new();
    let cfg = config(&root);
    let fake = Fake::start(&root, Script::default());
    let socket = SocketIdentity::verify(&cfg).unwrap();
    fs::remove_file(root.socket()).unwrap();
    let _replacement = UnixListener::bind(root.socket()).unwrap();
    unavailable(&readiness::check(
        &cfg,
        &socket,
        IMAGE,
        Duration::from_millis(20),
        &|| false,
    ));
    assert_eq!(fake.connections(), 0);
    fs::remove_file(root.socket()).unwrap();
    assert!(SocketIdentity::verify(&cfg).is_err());
}

#[test]
fn info_and_image_stalls_and_midflight_cancellation_never_succeed() {
    for path in [
        "/v1.47/info",
        "/v1.47/images/registry%3A5000%2Frepo%3Atag/json",
    ] {
        let r = run_with(
            Script {
                delay: Duration::from_millis(100),
                delay_on: Some(path.into()),
                ..Script::default()
            },
            IMAGE,
            Duration::from_millis(30),
            || false,
        );
        unavailable(&r.value);
    }
    let root = Root::new();
    let cfg = config(&root);
    let fake = Fake::start(&root, Script::default());
    let socket = SocketIdentity::verify(&cfg).unwrap();
    let r = readiness::check(&cfg, &socket, IMAGE, Duration::from_secs(2), &|| {
        fake.connections() >= 3
    });
    unavailable(&r);
    assert!(fake.connections() >= 3);
}
#[test]
fn malformed_image_404_does_not_prove_missing_image() {
    for body in [
        b"broken".to_vec(),
        b"{}".to_vec(),
        br#"{"message":false}"#.to_vec(),
    ] {
        let r = run_with(
            Script {
                container: Container::Raw(404, body),
                ..Script::default()
            },
            IMAGE,
            Duration::from_secs(2),
            || false,
        );
        unavailable(&r.value);
    }
}
