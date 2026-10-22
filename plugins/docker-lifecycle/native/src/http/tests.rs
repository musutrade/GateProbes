use super::*;
use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    thread,
};
fn config(path: &std::path::Path) -> Config {
    let r = gatehouse_runtime_protocol::lifecycle::wire::parse_request(include_bytes!(
        "../status-request.json"
    ))
    .unwrap();
    let mut c = r.binding.engine_binding;
    c.socket_path = path.to_str().unwrap().into();
    c.socket_uid = unsafe { libc::geteuid() };
    c.principal_uid = unsafe { libc::geteuid() };
    c
}
fn dir() -> tempfile::TempDir {
    let d = tempfile::Builder::new()
        .prefix("lifecycle-http-")
        .tempdir_in(
            std::env::var_os("GATEHOUSE_JOURNAL_TEST_ROOT")
                .or_else(|| std::env::var_os("HOME"))
                .expect("protected test root required"),
        )
        .unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    d
}
#[test]
fn malformed_headers_and_unsupported_framing_are_rejected() {
    for raw in [
        "garbage\r\nContent-Length: 0",
        "HTTP/2 200 OK\r\nContent-Length: 0",
        "HTTP/1.1 20 OK\r\nContent-Length: 0",
        "HTTP/1.1 101 Upgrade\r\nContent-Length: 0",
        "HTTP/1.1 200 OK",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\ncontent-length: 0",
        "HTTP/1.1 200 OK\r\nContent-Length: 01",
        "HTTP/1.1 200 OK\r\nContent-Length: -1",
        "HTTP/1.1 200 OK\r\nContent-Length: 1048577",
        "HTTP/1.1 204 OK\r\nContent-Length: 1",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Encoding: gzip",
        "HTTP/1.1 200 OK\r\nBad Header: x\r\nContent-Length: 0",
    ] {
        assert!(headers(raw.as_bytes()).is_err(), "{raw}");
    }
    assert_eq!(
        headers(b"HTTP/1.1 204 No Content"),
        Ok((204, Framing::Length(0)))
    );
    assert_eq!(
        headers(b"HTTP/1.1 200 OK\r\nContent-Length: 2"),
        Ok((200, Framing::Length(2)))
    );
}
fn reply(raw: Vec<u8>, delay: Duration, replace: bool, timeout: Duration) -> Result<Reply> {
    let d = dir();
    let path = d.path().join("engine.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let c = config(&path);
    let socket = SocketIdentity::verify(&c).unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut b = [0];
            stream.read_exact(&mut b).unwrap();
            request.push(b[0]);
        }
        if replace {
            fs::rename(&path, path.with_extension("old")).unwrap();
            let _other = UnixListener::bind(&path).unwrap();
        }
        thread::sleep(delay);
        let _ = stream.write_all(&raw);
    });
    let result = exchange(
        &c,
        &socket,
        "GET",
        "/version",
        &[],
        Instant::now() + timeout,
        &|| false,
    );
    handle.join().unwrap();
    result
}
#[test]
fn exchange_rejects_truncation_trailing_bytes_header_overflow_and_replacement() {
    for raw in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}x".to_vec(),
        vec![b'x'; 16_385],
    ] {
        assert!(reply(raw, Duration::ZERO, false, Duration::from_secs(1)).is_err());
    }
    assert!(reply(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        Duration::ZERO,
        true,
        Duration::from_secs(1)
    )
    .is_err());
}
#[test]
fn header_deadline_and_precancel_stop_transport() {
    assert!(reply(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        Duration::from_millis(100),
        false,
        Duration::from_millis(20)
    )
    .is_err());
    let d = dir();
    let path = d.path().join("engine.sock");
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let c = config(&path);
    let socket = SocketIdentity::verify(&c).unwrap();
    assert!(exchange(
        &c,
        &socket,
        "GET",
        "/version",
        &[],
        Instant::now() + Duration::from_secs(1),
        &|| true
    )
    .is_err());
    assert!(listener.accept().is_err());
}
#[test]
fn socket_identity_rejects_replacement_wrong_owner_and_unsafe_parent() {
    let d = dir();
    let path = d.path().join("engine.sock");
    let _listener = UnixListener::bind(&path).unwrap();
    let c = config(&path);
    let socket = SocketIdentity::verify(&c).unwrap();
    let mut wrong = c.clone();
    wrong.socket_uid = wrong.socket_uid.wrapping_add(1);
    assert!(SocketIdentity::verify(&wrong).is_err());
    fs::rename(&path, path.with_extension("old")).unwrap();
    let _replacement = UnixListener::bind(&path).unwrap();
    assert!(socket.revalidate().is_err());
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(SocketIdentity::verify(&c).is_err());
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn chunked_transport_accepts_complete_body_and_rejects_ambiguity() {
    for raw in [
        "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked",
        "HTTP/1.1 204 OK\r\nTransfer-Encoding: chunked",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: digest",
    ] {
        assert!(headers(raw.as_bytes()).is_err());
    }
    let header = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    let raw = [header.as_slice(), b"1\r\n{\r\n1\r\n}\r\n0\r\n\r\n"].concat();
    assert_eq!(
        reply(raw, Duration::ZERO, false, Duration::from_secs(1))
            .unwrap()
            .body,
        b"{}"
    );
    for body in [
        b"1\r\n{\r\n".as_slice(),
        b"0\r\n\r\nx",
        b"0\r\nDigest: forged\r\n\r\n",
    ] {
        assert!(reply(
            [header.as_slice(), body].concat(),
            Duration::ZERO,
            false,
            Duration::from_secs(1)
        )
        .is_err());
    }
}

#[cfg(feature = "real-engine-tests")]
#[test]
fn explicit_real_engine_readonly_version_and_info() {
    let path = std::env::var_os("GATEHOUSE_LIFECYCLE_REAL_BINDING")
        .expect("explicit real engine binding required");
    let config: Config = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    config.validate().unwrap();
    let socket = SocketIdentity::verify(&config).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    for (route, field, expected) in [
        (
            "/version".to_string(),
            "Version",
            config.server_version.as_str(),
        ),
        (
            format!("/v{}/info", config.api_version),
            "ID",
            config.daemon_id.as_str(),
        ),
    ] {
        let reply = exchange(&config, &socket, "GET", &route, &[], deadline, &|| false).unwrap();
        assert_eq!(reply.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body[field].as_str(), Some(expected));
    }
}
