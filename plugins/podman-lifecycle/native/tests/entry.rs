#![cfg(target_os = "linux")]
use gatehouse_runtime_protocol::lifecycle_v2::{
    capture_wire::*, observation::ExpectedContext, plan_record::PlanInputs, profile::*,
    protected_context::ProtectedContext,
};
use serde_json::json;
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixListener,
            process::CommandExt,
        },
    },
    process::{Command, Stdio},
    time::{Duration, Instant},
};
fn run(case: u8) {
    let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("p.sock");
    let listener = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let m = fs::metadata(&path).unwrap();
    let uid = unsafe { libc::geteuid() };
    let value = json!({"operator_epoch":"a".repeat(32),"principal_uid":uid,"observation":{"engine":"podman","api_surface":"libpod","selected_api":"6.1.4","server_version":"6.1.4","hostname":"fixture","rootless":uid!=0,"graph_root":"/var/lib/containers/storage","run_root":"/run/containers/storage","remote_socket":null,"socket":{"path":path,"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"mode":m.mode()}}});
    let context: ExpectedContext = serde_json::from_value(value).unwrap();
    let inner = serde_json::to_string(&context).unwrap();
    let bytes = format!("{{\"schema\":\"gate-runtime/podman-context-v1\",\"context\":{inner}}}");
    let config_path = dir.path().join("context.json");
    fs::write(&config_path, bytes).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    let held = ProtectedContext::load_versioned(&config_path).unwrap();
    let identity = SlotIdentity {
        profile: Profile {
            protocol: PROTOCOL.into(),
            product: PRODUCT.into(),
            version: VERSION.into(),
            engine: "podman".into(),
        },
        installation_sha256: "a".repeat(64),
        config_sha256: held.config_sha256().unwrap(),
        executable_sha256: "c".repeat(64),
    };
    let request = CaptureRequest {
        schema: "gate-runtime/podman-capture-v1".into(),
        profile: identity.profile.clone(),
        invocation: "1".repeat(32),
        image_id: "b".repeat(64),
        inputs: PlanInputs {
            name: "fixture".into(),
            labels: [("owner".into(), "fixture".into())].into(),
            port: None,
        },
        timeout_ms: 1500,
    };
    let expected = CaptureExpected::bind(
        &request,
        &identity,
        "d".repeat(64),
        config_path.to_str().unwrap().into(),
    )
    .unwrap();
    let eb = expected.encode(&request).unwrap();
    let fd = unsafe {
        libc::memfd_create(
            c"expected".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    assert!(fd >= 0);
    let mut expected_file = unsafe { File::from_raw_fd(fd) };
    assert_eq!(unsafe { libc::fchmod(fd, 0o600) }, 0);
    expected_file.write_all(&eb).unwrap();
    if case != 1 {
        assert_eq!(
            unsafe {
                libc::fcntl(
                    fd,
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_WRITE
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_SEAL,
                )
            },
            0
        );
    }
    let config = File::open(&config_path).unwrap();
    let cfd = unsafe { libc::fcntl(config.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    let efd = unsafe { libc::fcntl(expected_file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    assert!(cfd >= 10 && efd >= 10);
    let child_config = unsafe { File::from_raw_fd(cfd) };
    let child_expected = unsafe { File::from_raw_fd(efd) };
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gateprobes-podman-lifecycle"));
    cmd.env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(cfd, 3) < 0 || libc::dup2(efd, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if case == 2 {
                libc::close(4);
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    drop(child_config);
    drop(child_expected);
    let mut raw = request.encode().unwrap();
    if case == 3 {
        raw[0] = b'!';
    }
    child.stdin.take().unwrap().write_all(&raw).unwrap();
    let mut connections = 0;
    let limit = Instant::now() + Duration::from_secs(4);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                connections += 1;
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut header = vec![];
                while !header.ends_with(b"\r\n\r\n") {
                    let mut b = [0];
                    stream.read_exact(&mut b).unwrap();
                    header.push(b[0]);
                    assert!(header.len() < 16384);
                }
                let route = if connections == 2 {
                    format!("/v6.1.4/libpod/images/{}/json", "b".repeat(64))
                } else {
                    "/v6.1.4/libpod/info".into()
                };
                assert!(String::from_utf8(header)
                    .unwrap()
                    .starts_with(&format!("GET {route} HTTP/1.1\r\n")));
                let body=if connections==2{json!({"Id":"b".repeat(64),"Config":{}})}else{json!({"host":{"hostname":"fixture","security":{"rootless":uid!=0}},"store":{"graphRoot":"/var/lib/containers/storage","runRoot":"/run/containers/storage"},"version":{"APIVersion":"6.1.4","Version":"6.1.4"}})}.to_string();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("{e}"),
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() > limit {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("entry exceeded bound");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.stderr.is_empty());
    if case == 0 {
        assert!(output.status.success());
        assert_eq!(connections, 3);
        let record = decode_response(&output.stdout, &request, &expected, &held).unwrap();
        let evidence = dir.path().join("record");
        record.create_new(&evidence, &held).unwrap();
        assert!(!record.installation_verified());
    } else {
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(connections, 0);
    }
}
#[test]
fn native_fd_capture_positive() {
    run(0);
}
#[test]
fn native_fd_refusals_zero_connect() {
    for case in 1..4 {
        run(case);
    }
}
