use super::*;
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
struct Fixture {
    dir: tempfile::TempDir,
    listener: UnixListener,
    context: ProtectedContext,
    info: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("p.sock");
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let m = fs::metadata(&path).unwrap();
        let uid = unsafe { libc::geteuid() };
        let cfg = json!({"operator_epoch":"a".repeat(32),"principal_uid":uid,"observation":{"engine":"podman","api_surface":"libpod","selected_api":"6.1.4","server_version":"6.1.4","hostname":"fixture","rootless":uid!=0,"graph_root":"/var/lib/containers/storage","run_root":"/run/containers/storage","remote_socket":null,"socket":{"path":path,"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"mode":m.mode()}}});
        let config = dir.path().join("context.json");
        fs::write(&config, serde_json::to_vec(&cfg).unwrap()).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        let context = ProtectedContext::load(&config).unwrap();
        let info=serde_json::to_vec(&json!({"host":{"hostname":"fixture","security":{"rootless":uid!=0}},"store":{"graphRoot":"/var/lib/containers/storage","runRoot":"/run/containers/storage"},"version":{"APIVersion":"6.1.4","Version":"6.1.4"}})).unwrap();
        Self {
            dir,
            listener,
            context,
            info,
        }
    }
}
fn request(stream: &mut std::os::unix::net::UnixStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bytes = vec![];
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 16384);
        let mut b = [0];
        stream.read_exact(&mut b).unwrap();
        bytes.push(b[0]);
    }
    String::from_utf8(bytes).unwrap()
}
fn reply(body: &[u8]) -> Vec<u8> {
    let mut b = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    b.extend(body);
    b
}
#[test]
fn actual_socket_image_composition_and_exact_gets() {
    let f = Fixture::new();
    let id = "b".repeat(64);
    let route = image_route(&id).unwrap();
    let info = f.info.clone();
    let expected = route.clone();
    let server = thread::spawn(move || {
        for (n, path) in [INFO_ROUTE, expected.as_str(), INFO_ROUTE]
            .iter()
            .enumerate()
        {
            let (mut stream, _) = f.listener.accept().unwrap();
            let text = request(&mut stream);
            assert!(text.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
            assert!(text.contains("Content-Length: 0\r\n"));
            let body = if n == 1 {
                serde_json::to_vec(&json!({"Id":"b".repeat(64),"Labels":null,"Config":{}})).unwrap()
            } else {
                info.clone()
            };
            stream.write_all(&reply(&body)).unwrap();
        }
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    let facts = f
        .context
        .inspect_image_with(&id, |path| get(&f.context, path, deadline, &|| false))
        .unwrap();
    assert_eq!(facts.id(), id);
    server.join().unwrap();
}
#[test]
fn chunked_real_socket_read_is_bounded_and_decoded() {
    let f = Fixture::new();
    let server = thread::spawn(move || {
        let (mut s, _) = f.listener.accept().unwrap();
        request(&mut s);
        s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n")
            .unwrap();
    });
    assert_eq!(
        get(
            &f.context,
            INFO_ROUTE,
            Instant::now() + Duration::from_secs(2),
            &|| false
        )
        .unwrap(),
        (200, b"{}".to_vec())
    );
    server.join().unwrap();
}
#[test]
fn invalid_routes_cancelled_expired_never_connect() {
    let f = Fixture::new();
    f.listener.set_nonblocking(true).unwrap();
    for path in [
        "/v6.1.4/libpod/containers/create",
        "/v6.1.4/libpod/images/tag/json",
        "/v6.1.4/libpod/info?x=1",
        "/v6.1.4/libpod/exec/name/start",
        "/info",
    ] {
        assert!(get(
            &f.context,
            path,
            Instant::now() + Duration::from_secs(1),
            &|| false
        )
        .is_err());
    }
    assert!(get(&f.context, INFO_ROUTE, Instant::now(), &|| false).is_err());
    assert!(get(
        &f.context,
        INFO_ROUTE,
        Instant::now() + Duration::from_secs(1),
        &|| true
    )
    .is_err());
    assert!(f.listener.accept().is_err());
}
#[test]
fn stalled_peer_deadline_and_cancellation_are_bounded() {
    for cancel in [false, true] {
        let f = Fixture::new();
        let flag = Arc::new(AtomicBool::new(false));
        let server_flag = flag.clone();
        let server = thread::spawn(move || {
            let (mut s, _) = f.listener.accept().unwrap();
            request(&mut s);
            if cancel {
                server_flag.store(true, Ordering::SeqCst);
            }
            thread::sleep(Duration::from_millis(150));
        });
        let start = Instant::now();
        assert!(get(
            &f.context,
            INFO_ROUTE,
            start + Duration::from_millis(80),
            &|| flag.load(Ordering::SeqCst)
        )
        .is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }
}
#[test]
fn malformed_ambiguous_oversize_and_truncated_framing_refused() {
    for raw in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}",
    ] {
        let f = Fixture::new();
        let server = thread::spawn(move || {
            let (mut s, _) = f.listener.accept().unwrap();
            request(&mut s);
            let _ = s.write_all(raw);
        });
        assert!(get(
            &f.context,
            INFO_ROUTE,
            Instant::now() + Duration::from_secs(1),
            &|| false
        )
        .is_err());
        server.join().unwrap();
    }
}
#[test]
fn replacement_before_connect_or_after_response_refused() {
    let f = Fixture::new();
    fs::rename(f.dir.path().join("p.sock"), f.dir.path().join("old.sock")).unwrap();
    let replacement = UnixListener::bind(f.dir.path().join("p.sock")).unwrap();
    fs::set_permissions(
        f.dir.path().join("p.sock"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    replacement.set_nonblocking(true).unwrap();
    assert!(get(
        &f.context,
        INFO_ROUTE,
        Instant::now() + Duration::from_secs(1),
        &|| false
    )
    .is_err());
    assert!(replacement.accept().is_err());
    let f = Fixture::new();
    let config = f.dir.path().join("context.json");
    let server = thread::spawn(move || {
        let (mut s, _) = f.listener.accept().unwrap();
        request(&mut s);
        fs::set_permissions(config, fs::Permissions::from_mode(0o644)).unwrap();
        s.write_all(&reply(b"{}")).unwrap();
    });
    assert!(get(
        &f.context,
        INFO_ROUTE,
        Instant::now() + Duration::from_secs(1),
        &|| false
    )
    .is_err());
    server.join().unwrap();
}

#[test]
fn pathname_swap_at_connect_uses_held_inode_and_sends_no_request() {
    use std::cell::RefCell;
    let f = Fixture::new();
    f.listener.set_nonblocking(true).unwrap();
    let replacement = RefCell::new(None);
    let result = get(
        &f.context,
        INFO_ROUTE,
        Instant::now() + Duration::from_secs(1),
        &|| {
            if replacement.borrow().is_none() {
                fs::rename(f.dir.path().join("p.sock"), f.dir.path().join("old.sock")).unwrap();
                let listener = UnixListener::bind(f.dir.path().join("p.sock")).unwrap();
                fs::set_permissions(
                    f.dir.path().join("p.sock"),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
                listener.set_nonblocking(true).unwrap();
                *replacement.borrow_mut() = Some(listener);
            }
            false
        },
    );
    assert!(result.is_err());
    assert!(replacement.borrow().as_ref().unwrap().accept().is_err());
    let (mut old_stream, _) = f.listener.accept().expect("held inode received connection");
    old_stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut byte = [0];
    assert_eq!(
        old_stream.read(&mut byte).unwrap(),
        0,
        "revalidation must reject before sending HTTP"
    );
}
