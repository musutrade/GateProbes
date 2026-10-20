//! Bounded native Unix HTTP tests. Fake protected-root listeners only; no daemon connect.

use gateprobes_docker_runtime::http::{get, Route};
use gateprobes_docker_runtime::input::Config;
use gateprobes_docker_runtime::socket_identity::SocketIdentity;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

static COUNTER: AtomicU64 = AtomicU64::new(0);
const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let base = std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".cache"))
            .filter(|path| protected(path))
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", euid())));
        let path = base.join(format!(
            "gateprobes-http-{}-{}",
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
fn bind(root: &Root) -> UnixListener {
    let _ = fs::remove_file(root.socket());
    UnixListener::bind(root.socket()).unwrap()
}
fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Error",
    };
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n");
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    out.into_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .collect()
}
fn serve(
    listener: UnixListener,
    reply: Vec<u8>,
    fragment: bool,
    cancel: Option<Arc<AtomicBool>>,
) -> (thread::JoinHandle<Vec<u8>>, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let thread_count = Arc::clone(&count);
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        thread_count.fetch_add(1, Ordering::SeqCst);
        if let Some(flag) = cancel {
            flag.store(true, Ordering::SeqCst);
        }
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).unwrap_or(0) == 0 {
                break;
            }
            request.push(byte[0]);
            if request.len() > 16_384 {
                break;
            }
        }
        if fragment {
            for byte in reply {
                if stream.write_all(&[byte]).is_err() {
                    return request;
                }
                thread::sleep(Duration::from_millis(1));
            }
        } else {
            let _ = stream.write_all(&reply);
        }
        request
    });
    (handle, count)
}
fn identity(_root: &Root, cfg: &Config) -> SocketIdentity {
    SocketIdentity::verify(cfg).unwrap()
}
fn run(
    root: &Root,
    cfg: &Config,
    route: Route<'_>,
    deadline: Instant,
) -> Result<gateprobes_docker_runtime::http::Reply, &'static str> {
    let socket = identity(root, cfg);
    get(cfg, &socket, route, deadline, &|| false)
}
fn assert_zero_connections(listener: &UnixListener) {
    listener.set_nonblocking(true).unwrap();
    let result = listener.accept();
    assert!(matches!(result, Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock));
}

#[test]
fn exact_routes_and_bounded_fragmentation() {
    let root = Root::new();
    let cfg = config(&root);
    let reply = response(200, &[("Content-Length", "2")], b"OK");
    for (route, expected) in [
        (Route::Version, "/version"),
        (Route::Info, "/v1.47/info"),
        (
            Route::Inspect(ID),
            &format!("/v1.47/containers/{ID}/json")[..],
        ),
    ] {
        let listener = bind(&root);
        let (handle, _) = serve(listener, reply.clone(), true, None);
        let result = run(&root, &cfg, route, Instant::now() + Duration::from_secs(2)).unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.body, b"OK");
        let request = handle.join().unwrap();
        assert!(request.starts_with(format!("GET {expected} HTTP/1.1\r\n").as_bytes()));
    }
}

#[test]
fn rejects_duplicate_framing_bounds_and_status() {
    let root = Root::new();
    let cfg = config(&root);
    let cases = vec![
        response(
            200,
            &[("Content-Length", "2"), ("Content-Length", "2")],
            b"OK",
        ),
        response(
            200,
            &[("Transfer-Encoding", "chunked"), ("Content-Length", "2")],
            b"OK",
        ),
        response(
            200,
            &[("Content-Encoding", "gzip"), ("Content-Length", "2")],
            b"OK",
        ),
        response(200, &[("Content-Length", "02")], b"OK"),
        response(200, &[("Content-Length", "1048577")], b""),
        response(700, &[("Content-Length", "0")], b""),
        {
            let mut headers = Vec::new();
            for _ in 0..65 {
                headers.push(("X-Test", "x"));
            }
            response(200, &headers, b"")
        },
    ];
    for (index, reply) in cases.into_iter().enumerate() {
        let listener = bind(&root);
        let (handle, _) = serve(listener, reply, false, None);
        let result = run(
            &root,
            &cfg,
            Route::Version,
            Instant::now() + Duration::from_secs(1),
        );
        assert!(result.is_err(), "case {index}");
        let _ = handle.join();
    }
}

#[test]
fn raw404_is_returned_not_absence() {
    let root = Root::new();
    let cfg = config(&root);
    let listener = bind(&root);
    let (handle, _) = serve(
        listener,
        response(404, &[("Content-Length", "4")], b"nope"),
        false,
        None,
    );
    let result = run(
        &root,
        &cfg,
        Route::Inspect(ID),
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(result.status, 404);
    assert_eq!(result.body, b"nope");
    let _ = handle.join();
}

#[test]
fn truncation_extra_and_header_size_are_rejected() {
    let root = Root::new();
    let cfg = config(&root);
    let cases = vec![
        response(200, &[("Content-Length", "5")], b"ab"),
        response(200, &[("Content-Length", "2")], b"OKextra"),
        {
            let mut out = b"HTTP/1.1 200 OK\r\nX-Large: ".to_vec();
            out.extend(std::iter::repeat_n(b'x', 17_000));
            out.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
            out
        },
    ];
    for reply in cases {
        let listener = bind(&root);
        let (handle, _) = serve(listener, reply, false, None);
        assert!(run(
            &root,
            &cfg,
            Route::Version,
            Instant::now() + Duration::from_secs(1)
        )
        .is_err());
        let _ = handle.join();
    }
}

#[test]
fn timeout_trickle_and_cancel_are_bounded() {
    let root = Root::new();
    let cfg = config(&root);
    let header = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n".to_vec();
    let listener = bind(&root);
    let (handle, _) = serve(listener, header.clone(), false, None);
    assert!(run(
        &root,
        &cfg,
        Route::Version,
        Instant::now() + Duration::from_millis(100)
    )
    .is_err());
    let _ = handle.join();

    let listener = bind(&root);
    let slow = response(200, &[("Content-Length", "1000")], &vec![b'x'; 1000]);
    let (handle, _) = serve(listener, slow, true, None);
    assert!(run(
        &root,
        &cfg,
        Route::Version,
        Instant::now() + Duration::from_millis(50)
    )
    .is_err());
    let _ = handle.join();

    let flag = Arc::new(AtomicBool::new(false));
    let listener = bind(&root);
    let (handle, _) = serve(listener, header, false, Some(Arc::clone(&flag)));
    let socket = identity(&root, &cfg);
    assert!(get(
        &cfg,
        &socket,
        Route::Version,
        Instant::now() + Duration::from_secs(2),
        &|| flag.load(Ordering::SeqCst)
    )
    .is_err());
    let _ = handle.join();
}

#[test]
fn socket_replacement_and_bad_route_input_make_zero_connections() {
    let root = Root::new();
    let cfg = config(&root);
    let first = bind(&root);
    let socket = identity(&root, &cfg);
    fs::remove_file(root.socket()).unwrap();
    drop(first);
    let second = bind(&root);
    assert!(get(
        &cfg,
        &socket,
        Route::Version,
        Instant::now() + Duration::from_secs(1),
        &|| false
    )
    .is_err());
    assert_zero_connections(&second);
    drop(second);

    let mut bad = config(&root);
    bad.api_version = "01.47".into();
    let listener = bind(&root);
    assert!(run(
        &root,
        &bad,
        Route::Version,
        Instant::now() + Duration::from_secs(1)
    )
    .is_err());
    assert_zero_connections(&listener);
    drop(listener);

    let listener = bind(&root);
    assert!(run(
        &root,
        &cfg,
        Route::Inspect("A".repeat(64).as_str()),
        Instant::now() + Duration::from_secs(1)
    )
    .is_err());
    assert_zero_connections(&listener);
}

#[test]
fn deadline_over_thirty_seconds_is_refused_before_connect() {
    let root = Root::new();
    let cfg = config(&root);
    let listener = bind(&root);
    assert!(run(
        &root,
        &cfg,
        Route::Version,
        Instant::now() + Duration::from_secs(31)
    )
    .is_err());
    assert_zero_connections(&listener);
}
