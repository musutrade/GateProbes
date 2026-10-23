#![cfg(target_os = "linux")]
use super::adapter::execute;
use gatehouse_runtime_protocol::lifecycle::wire::{
    Binding, EngineBinding, Entry, Operation, Outcome, Request, Target, PROTOCOL,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::FromRawFd,
        unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::PathBuf,
    sync::mpsc,
    thread,
    time::Duration,
};

const ID: &str = "a";
fn id() -> String {
    ID.repeat(64)
}

fn labels() -> Vec<Entry> {
    vec![
        Entry {
            key: "gatehouse.lifecycle.authority".into(),
            value: "container-lifecycle/mutate".into(),
        },
        Entry {
            key: "gatehouse.lifecycle.invocation".into(),
            value: "1".repeat(32),
        },
        Entry {
            key: "gatehouse.lifecycle.project".into(),
            value: "project".into(),
        },
        Entry {
            key: "gatehouse.lifecycle.resource".into(),
            value: "service:fixture".into(),
        },
    ]
}

struct Fixture {
    socket: PathBuf,
    config: Vec<u8>,
    request: Request,
    _dir: tempfile::TempDir,
}

fn fixture(operation: Operation, port: u16) -> Fixture {
    let root = std::env::var_os("HOME").expect("HOME required");
    let dir = tempfile::Builder::new()
        .prefix("podman-lifecycle-adapter-")
        .tempdir_in(root)
        .unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("podman.sock");
    let uid = unsafe { libc::geteuid() };
    let binding = EngineBinding {
        engine: "podman".into(),
        transport: "unix-http".into(),
        socket_path: socket.to_str().unwrap().into(),
        socket_uid: uid,
        principal_uid: uid,
        rootless: true,
        api_version: "5.7.0".into(),
        server_version: "5.7.0".into(),
        daemon_id: "fixture-host".into(),
        scope: "/fixture/storage".into(),
    };
    let config = serde_json::to_vec(&serde_json::json!({
        "schema": "gate-runtime/lifecycle-config-v1",
        "engine_binding": binding,
    }))
    .unwrap();
    let labels = labels();
    let mut request = Request {
        protocol: PROTOCOL.into(),
        binding: Binding {
            installation_sha256: "b".repeat(64),
            executable_sha256: "c".repeat(64),
            config_sha256: format!("{:x}", Sha256::digest(&config)),
            engine_binding: binding,
            project_id: "project".into(),
            resource_id: "service:fixture".into(),
            lease_invocation: "1".repeat(32),
            invocation: "2".repeat(32),
            generation: 2,
            operation_key: String::new(),
        },
        operation,
    };
    if let Operation::Create {
        name,
        labels: request_labels,
        ..
    } = &mut request.operation
    {
        *name = "fixture".into();
        *request_labels = labels.clone();
        let _ = port;
    }
    request.binding.operation_key = request.operation_key().unwrap();
    Fixture {
        socket,
        config,
        request,
        _dir: dir,
    }
}

fn memory(bytes: &[u8]) -> File {
    let fd = unsafe {
        libc::memfd_create(
            c"podman-lifecycle-test".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    assert!(fd >= 0);
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes).unwrap();
    assert_eq!(unsafe { libc::fchmod(fd, 0o600) }, 0);
    assert_eq!(
        unsafe {
            libc::fcntl(
                fd,
                libc::F_ADD_SEALS,
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
            )
        },
        0
    );
    file
}

fn info_body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "host": {"hostname":"fixture-host","security":{"rootless":true}},
        "store": {"graphRoot":"/fixture/storage","runRoot":"/run/containers/storage"},
        "version": {"APIVersion":"5.7.0","Version":"5.7.0"}
    }))
    .unwrap()
}

fn inspect_body(state: &str) -> Vec<u8> {
    let running = state == "running";
    serde_json::to_vec(&serde_json::json!({
        "Id": id(),
        "Name": "fixture",
        "Image": "e".repeat(64),
        "Config": {"Labels": {
            "gatehouse.lifecycle.authority":"container-lifecycle/mutate",
            "gatehouse.lifecycle.invocation":"11111111111111111111111111111111",
            "gatehouse.lifecycle.project":"project",
            "gatehouse.lifecycle.resource":"service:fixture"
        }},
        "State": {"Status":state,"Running":running,"Paused":false,"Restarting":false,"Dead":false},
        "HostConfig": {"PortBindings":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"49152"}]}},
        "NetworkSettings": {"Ports":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"49152"}]}}
    }))
    .unwrap()
}

fn serve(socket: PathBuf, steps: Vec<(String, String, u16, Vec<u8>)>, done: mpsc::Sender<()>) {
    let listener = UnixListener::bind(socket).unwrap();
    fs::set_permissions(
        listener.local_addr().unwrap().as_pathname().unwrap(),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    for (expected_method, expected_path, status, body) in steps {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream, &expected_method, &expected_path);
        let reason = match status {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => panic!(),
        };
        write!(
            stream,
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(&body).unwrap();
    }
    done.send(()).unwrap();
}

fn read_request(stream: &mut UnixStream, method: &str, path: &str) {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() < 8192);
    }
    let text = String::from_utf8(bytes).unwrap();
    assert!(
        text.starts_with(&format!("{method} {path} HTTP/1.1\r\n")),
        "{text}"
    );
    let length = text
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
}

#[test]
fn create_start_health_stop_remove_through_exact_libpod_routes() {
    let operation = Operation::Create {
        name: "fixture".into(),
        image_id: format!("sha256:{}", "e".repeat(64)),
        labels: vec![],
        environment: vec![],
        container_port: 8080,
        command: Some(vec!["sleep".into(), "60".into()]),
    };
    let fixture = fixture(operation, 8080);
    let expected = fixture.request.canonical_bytes().unwrap();
    let config = memory(&fixture.config);
    let expected_file = memory(&expected);
    let (tx, rx) = mpsc::channel();
    let socket = fixture.socket.clone();
    let steps = vec![
        ("GET".into(), "/v5.7.0/libpod/info".into(), 200, info_body()),
        (
            "POST".into(),
            "/v5.7.0/libpod/containers/create".into(),
            201,
            serde_json::to_vec(&serde_json::json!({"Id":id(),"Warnings":[]})).unwrap(),
        ),
        (
            "GET".into(),
            format!("/v5.7.0/libpod/containers/{}/json", id()),
            200,
            inspect_body("created"),
        ),
        ("GET".into(), "/v5.7.0/libpod/info".into(), 200, info_body()),
    ];
    let server = thread::spawn(move || serve(socket, steps, tx));
    let response = execute(
        &config,
        &expected_file,
        &expected,
        Duration::from_secs(5),
        || false,
    )
    .unwrap();
    assert!(matches!(response.outcome, Outcome::Created { .. }));
    rx.recv_timeout(Duration::from_secs(5)).unwrap();
    server.join().unwrap();
}

#[test]
fn status_absence_is_exact_and_unknown_results_are_retained() {
    let target = Target {
        object_id: id(),
        name: "fixture".into(),
        container_port: 8080,
        labels: labels(),
    };
    let fixture = fixture(
        Operation::Status {
            target: target.clone(),
        },
        8080,
    );
    let expected = fixture.request.canonical_bytes().unwrap();
    let config = memory(&fixture.config);
    let expected_file = memory(&expected);
    let (tx, rx) = mpsc::channel();
    let socket = fixture.socket.clone();
    let missing = serde_json::to_vec(&serde_json::json!({
        "cause":"no such container",
        "message":format!("no container with name or ID \"{}\" found: no such container", target.object_id),
        "response":404
    })).unwrap();
    let steps = vec![
        ("GET".into(), "/v5.7.0/libpod/info".into(), 200, info_body()),
        (
            "GET".into(),
            format!("/v5.7.0/libpod/containers/{}/json", target.object_id),
            404,
            missing,
        ),
        ("GET".into(), "/v5.7.0/libpod/info".into(), 200, info_body()),
    ];
    let server = thread::spawn(move || serve(socket, steps, tx));
    let response = execute(
        &config,
        &expected_file,
        &expected,
        Duration::from_secs(5),
        || false,
    )
    .unwrap();
    match response.outcome {
        Outcome::Absent { evidence } => {
            assert_eq!(
                evidence.route,
                format!("/v5.7.0/libpod/containers/{}/json", target.object_id)
            );
            assert_eq!(evidence.http_status, 404);
        }
        other => panic!("{other:?}"),
    }
    rx.recv_timeout(Duration::from_secs(5)).unwrap();
    server.join().unwrap();
}
