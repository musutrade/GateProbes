//! Disposable Unix-socket Docker API double. It is a test fact source only;
//! it never contacts a real daemon and never claims to be one.

use serde_json::{json, Value};
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Clone)]
pub enum Reply {
    Json(Value),
    Status(u16, Vec<u8>),
}

pub struct Script {
    pub version: Value,
    pub info: Value,
    pub container: Reply,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            version: json!({
                "Version": "27.0.1",
                "ApiVersion": "1.47",
                "MinAPIVersion": "1.24"
            }),
            info: json!({"ID": "daemon-1"}),
            container: Reply::Json(json!({
                "Id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "Config": {"Labels": {"harness-gate.owner": "harness-gate"}}
            })),
        }
    }
}

pub struct FakeDocker {
    socket_path: PathBuf,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeDocker {
    pub fn start(root: &Path, api_version: &str, script: Script) -> io::Result<Self> {
        let socket_path = root.join("docker.sock");
        let listener = UnixListener::bind(&socket_path)?;
        listener.set_nonblocking(true)?;
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_connections = Arc::clone(&connections);
        let thread_stop = Arc::clone(&stop);
        let versioned_info = format!("/v{api_version}/info");
        let container_prefix = format!("/v{api_version}/containers/");
        let script = Arc::new(script);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        thread_connections.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                        let _ = handle(&mut stream, &script, &versioned_info, &container_prefix);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            socket_path,
            connections,
            stop,
            thread: Some(thread),
        })
    }

    pub fn socket_path(&self) -> String {
        self.socket_path.to_string_lossy().into_owned()
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for FakeDocker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

fn handle(
    stream: &mut UnixStream,
    script: &Script,
    versioned_info: &str,
    container_prefix: &str,
) -> io::Result<()> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() > 16384 {
            return Ok(());
        }
    }
    let head = String::from_utf8_lossy(&request);
    let path = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("");
    let reply = if path == "/version" {
        Reply::Json(script.version.clone())
    } else if path == versioned_info {
        Reply::Json(script.info.clone())
    } else if is_inspect(path, container_prefix) {
        script.container.clone()
    } else {
        Reply::Status(404, b"{\"message\":\"not found\"}".to_vec())
    };
    write_reply(stream, &reply)
}

fn is_inspect(path: &str, prefix: &str) -> bool {
    if !path.starts_with(prefix) || !path.ends_with("/json") {
        return false;
    }
    let id = &path[prefix.len()..path.len() - "/json".len()];
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn write_reply(stream: &mut UnixStream, reply: &Reply) -> io::Result<()> {
    let (status, body) = match reply {
        Reply::Json(value) => (200, serde_json::to_vec(value).expect("reply JSON")),
        Reply::Status(status, body) => (*status, body.clone()),
    };
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Status",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}
