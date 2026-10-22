#![cfg(target_os = "linux")]
use std::{
    io::Write,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
};
#[test]
fn missing_protected_descriptors_exit_cleanly_without_output() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gateprobes-docker-lifecycle"));
    command
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            libc::close(3);
            libc::close(4);
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"{}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}
#[test]
fn oversized_stdin_is_rejected_without_output() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_gateprobes-docker-lifecycle"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&vec![b' '; 65_537])
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn sealed_native_entry_resolves_image_over_fake_socket() {
    use gatehouse_runtime_protocol::lifecycle::wire::{self, Operation, Outcome};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File},
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{fs::PermissionsExt, net::UnixListener},
        },
        thread,
        time::Duration,
    };
    fn sealed(bytes: &[u8]) -> File {
        unsafe {
            let fd = libc::memfd_create(
                c"native-entry".as_ptr(),
                libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC,
            );
            assert!(fd >= 0);
            let mut f = File::from_raw_fd(fd);
            assert_eq!(libc::fchmod(fd, 0o600), 0);
            f.write_all(bytes).unwrap();
            assert_eq!(libc::fcntl(fd, libc::F_ADD_SEALS, 15), 0);
            let copy = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 5);
            assert!(copy >= 5);
            File::from_raw_fd(copy)
        }
    }
    let d = tempfile::Builder::new()
        .prefix("native-lifecycle-")
        .tempdir_in(
            std::env::var_os("GATEHOUSE_JOURNAL_TEST_ROOT")
                .or_else(|| std::env::var_os("HOME"))
                .expect("protected test root required"),
        )
        .unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = d.path().join("engine.sock");
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let version = json!({"Version":"27","MinAPIVersion":"1.40","ApiVersion":"1.47"});
        let info = json!({"ID":"test-daemon","SecurityOptions":["name=rootless"]});
        let image = json!({"Id":format!("sha256:{}","e".repeat(64)),"RepoDigests":[]});
        for (route, body) in [
            ("/version", version.clone()),
            ("/v1.47/info", info.clone()),
            ("/v1.47/images/example%3Alatest/json", image),
            ("/version", version),
            ("/v1.47/info", info),
        ] {
            let end = std::time::Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < end,
                            "native entry made no expected request"
                        );
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut b = [0];
                stream.read_exact(&mut b).unwrap();
                header.push(b[0]);
            }
            assert!(String::from_utf8(header)
                .unwrap()
                .starts_with(&format!("GET {route} HTTP/1.1\r\n")));
            let body = serde_json::to_vec(&body).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        }
    });
    let mut request = wire::parse_request(include_bytes!("../src/status-request.json")).unwrap();
    request.operation = Operation::ResolveImage {
        image: "example:latest".into(),
    };
    request.binding.engine_binding.socket_path = path.to_str().unwrap().into();
    request.binding.engine_binding.socket_uid = unsafe { libc::geteuid() };
    request.binding.engine_binding.principal_uid = unsafe { libc::geteuid() };
    let config=serde_json::to_vec(&json!({"schema":"gate-runtime/lifecycle-config-v1","engine_binding":request.binding.engine_binding})).unwrap();
    request.binding.config_sha256 = format!("{:x}", Sha256::digest(&config));
    request.binding.operation_key = request.operation_key().unwrap();
    let bytes = request.canonical_bytes().unwrap();
    let config = sealed(&config);
    let expected = sealed(&bytes);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gateprobes-docker-lifecycle"));
    cmd.env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(config.as_raw_fd(), 3) < 0 || libc::dup2(expected.as_raw_fd(), 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    child.stdin.take().unwrap().write_all(&bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    server.join().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let response = wire::parse_response(&output.stdout, &request).unwrap();
    assert!(matches!(response.outcome, Outcome::Image { .. }));
}
