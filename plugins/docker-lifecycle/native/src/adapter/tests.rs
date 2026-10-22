use super::*;
use gatehouse_runtime_protocol::lifecycle::wire::Entry;
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::FromRawFd,
        unix::{fs::PermissionsExt, net::UnixListener},
    },
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};
struct Step {
    method: &'static str,
    path: String,
    status: u16,
    body: Vec<u8>,
    delay: Duration,
}
fn step(method: &'static str, path: impl Into<String>, status: u16, value: Value) -> Step {
    Step {
        method,
        path: path.into(),
        status,
        delay: Duration::ZERO,
        body: if value.is_null() {
            vec![]
        } else {
            serde_json::to_vec(&value).unwrap()
        },
    }
}
fn version() -> Step {
    step(
        "GET",
        "/version",
        200,
        json!({"Version":"27","MinAPIVersion":"1.40","ApiVersion":"1.47"}),
    )
}
fn info() -> Step {
    step(
        "GET",
        "/v1.47/info",
        200,
        json!({"ID":"test-daemon","SecurityOptions":["name=rootless"]}),
    )
}
fn sealed(bytes: &[u8]) -> File {
    unsafe {
        let fd = libc::memfd_create(
            c"lifecycle-test".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        );
        assert!(fd >= 0);
        let mut file = File::from_raw_fd(fd);
        assert_eq!(libc::fchmod(fd, 0o600), 0);
        file.write_all(bytes).unwrap();
        assert_eq!(libc::fcntl(fd, libc::F_ADD_SEALS, 15), 0);
        file
    }
}
fn target() -> Target {
    let r = wire::parse_request(include_bytes!("../status-request.json")).unwrap();
    let Operation::Status { target } = r.operation else {
        panic!()
    };
    target
}
fn inspect(state: &str) -> Value {
    let t = target();
    let labels: serde_json::Map<String, Value> = t
        .labels
        .iter()
        .map(|e| (e.key.clone(), e.value.clone().into()))
        .collect();
    json!({"Id":t.object_id,"Name":format!("/{}",t.name),"Image":format!("sha256:{}","e".repeat(64)),"Config":{"Labels":labels},"State":{"Status":state},"NetworkSettings":{"Ports":if state=="running"{json!({"1234/tcp":[{"HostIp":"127.0.0.1","HostPort":"49152"}]})}else{json!({"1234/tcp":null})}}})
}
fn inspect_step(state: &str) -> Step {
    step(
        "GET",
        format!("/v1.47/containers/{}/json", "a".repeat(64)),
        200,
        inspect(state),
    )
}
fn create() -> Operation {
    let t = target();
    Operation::Create {
        name: t.name,
        image_id: format!("sha256:{}", "e".repeat(64)),
        labels: t.labels,
        environment: Vec::<Entry>::new(),
        container_port: t.container_port,
    }
}
fn exercise(operation: Operation, steps: Vec<Step>) -> (Response, Vec<(String, Vec<u8>)>) {
    exercise_bounds(operation, steps, Duration::from_secs(3), false)
}
fn exercise_bounds(
    operation: Operation,
    steps: Vec<Step>,
    timeout: Duration,
    cancelled: bool,
) -> (Response, Vec<(String, Vec<u8>)>) {
    exercise_options(operation, steps, timeout, cancelled, usize::MAX)
}
fn exercise_options(
    operation: Operation,
    steps: Vec<Step>,
    timeout: Duration,
    cancelled: bool,
    cancel_after: usize,
) -> (Response, Vec<(String, Vec<u8>)>) {
    let dir = tempfile::Builder::new()
        .prefix("lifecycle-socket-")
        .tempdir_in(
            std::env::var_os("GATEHOUSE_JOURNAL_TEST_ROOT")
                .or_else(|| std::env::var_os("HOME"))
                .expect("protected test root required"),
        )
        .unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("engine.sock");
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let received = seen.clone();
    let handle = thread::spawn(move || {
        let mut steps = steps.into_iter();
        let end = Instant::now() + Duration::from_secs(5);
        while !stopped.load(Ordering::SeqCst) && Instant::now() < end {
            let (mut stream, _) = match listener.accept() {
                Ok(x) => x,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(e) => panic!("{e}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut b = [0];
                stream.read_exact(&mut b).unwrap();
                header.push(b[0]);
                assert!(header.len() < 16384);
            }
            let text = String::from_utf8(header).unwrap();
            let line = text.lines().next().unwrap().to_owned();
            let length: usize = text
                .lines()
                .find_map(|s| s.strip_prefix("Content-Length: "))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            received.lock().unwrap().push((line.clone(), body));
            let expected = steps.next().expect("unexpected extra request");
            assert_eq!(
                line,
                format!("{} {} HTTP/1.1", expected.method, expected.path)
            );
            let header = if expected.status == 204 {
                "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".into()
            } else {
                format!(
                    "HTTP/1.1 {} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    expected.status,
                    expected.body.len()
                )
            };
            thread::sleep(expected.delay);
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&expected.body);
        }
        assert!(steps.next().is_none(), "expected request missing");
    });
    let mut request = wire::parse_request(include_bytes!("../status-request.json")).unwrap();
    request.operation = operation;
    request.binding.engine_binding.socket_path = path.to_str().unwrap().into();
    request.binding.engine_binding.socket_uid = unsafe { libc::geteuid() };
    request.binding.engine_binding.principal_uid = unsafe { libc::geteuid() };
    let config=serde_json::to_vec(&json!({"schema":"gate-runtime/lifecycle-config-v1","engine_binding":request.binding.engine_binding})).unwrap();
    request.binding.config_sha256 = format!("{:x}", Sha256::digest(&config));
    request.binding.operation_key = request.operation_key().unwrap();
    let bytes = request.canonical_bytes().unwrap();
    let result = execute(&sealed(&config), &sealed(&bytes), &bytes, timeout, || {
        cancelled || seen.lock().unwrap().len() >= cancel_after
    });
    stop.store(true, Ordering::SeqCst);
    handle.join().unwrap();
    let seen = Arc::try_unwrap(seen).unwrap().into_inner().unwrap();
    (result.unwrap(), seen)
}
#[test]
fn fake_create_inspects_exact_id_and_matches_both_observations() {
    let mut steps = vec![
        version(),
        info(),
        step(
            "POST",
            "/v1.47/containers/create?name=test-container",
            201,
            json!({"Id":"a".repeat(64),"Warnings":[]}),
        ),
        inspect_step("created"),
    ];
    steps.extend([version(), info()]);
    let (response, seen) = exercise(create(), steps);
    assert!(matches!(response.outcome, Outcome::Created { .. }));
    let body: Value = serde_json::from_slice(&seen[2].1).unwrap();
    assert_eq!(body["HostConfig"]["AutoRemove"], false);
    assert_eq!(body["Image"], format!("sha256:{}", "e".repeat(64)));
}
#[test]
fn fake_start_stop_and_remove_are_exact_id_and_non_force() {
    let t = target();
    let id = &t.object_id;
    for (operation, steps, expected) in [
        (
            Operation::Start { target: t.clone() },
            vec![
                version(),
                info(),
                inspect_step("created"),
                step(
                    "POST",
                    format!("/v1.47/containers/{id}/start"),
                    204,
                    Value::Null,
                ),
                inspect_step("running"),
                version(),
                info(),
            ],
            "started",
        ),
        (
            Operation::Stop {
                target: t.clone(),
                grace_seconds: 10,
            },
            vec![
                version(),
                info(),
                inspect_step("running"),
                step(
                    "POST",
                    format!("/v1.47/containers/{id}/stop?t=10"),
                    204,
                    Value::Null,
                ),
                inspect_step("exited"),
                version(),
                info(),
            ],
            "stopped",
        ),
        (
            Operation::Remove { target: t.clone() },
            vec![
                version(),
                info(),
                inspect_step("exited"),
                step(
                    "DELETE",
                    format!("/v1.47/containers/{id}?force=false&v=false"),
                    204,
                    Value::Null,
                ),
                version(),
                info(),
            ],
            "removed",
        ),
    ] {
        let (r, _) = exercise(operation, steps);
        assert_eq!(serde_json::to_value(&r.outcome).unwrap()["kind"], expected);
    }
}
#[test]
fn exact_status_404_is_absence_but_generic_404_is_unknown() {
    let t = target();
    let path = format!("/v1.47/containers/{}/json", t.object_id);
    let (r, _) = exercise(
        Operation::Status { target: t.clone() },
        vec![
            version(),
            info(),
            step(
                "GET",
                &path,
                404,
                json!({"message":format!("No such container: {}",t.object_id)}),
            ),
            version(),
            info(),
        ],
    );
    assert!(matches!(r.outcome, Outcome::Absent { .. }));
    let (r, _) = exercise(
        Operation::Status { target: t },
        vec![
            version(),
            info(),
            step("GET", path, 404, json!({"message":"not found"})),
        ],
    );
    assert!(matches!(r.outcome, Outcome::Unknown { .. }));
}
#[test]
fn wrong_preinspection_or_daemon_identity_never_mutates() {
    let mut wrong = inspect("created");
    wrong["Config"]["Labels"] = json!({});
    let (r, seen) = exercise(
        Operation::Start { target: target() },
        vec![
            version(),
            info(),
            step(
                "GET",
                format!("/v1.47/containers/{}/json", "a".repeat(64)),
                200,
                wrong,
            ),
        ],
    );
    assert!(matches!(r.outcome, Outcome::Unknown { .. }));
    assert!(seen.iter().all(|(s, _)| s.starts_with("GET ")));
    let (r, seen) = exercise(
        create(),
        vec![
            version(),
            step(
                "GET",
                "/v1.47/info",
                200,
                json!({"ID":"other","SecurityOptions":["name=rootless"]}),
            ),
        ],
    );
    assert!(matches!(r.outcome, Outcome::Unknown { .. }));
    assert_eq!(seen.len(), 2);
}
#[test]
fn post_create_identity_change_and_warning_claim_remain_unknown() {
    let (r, _) = exercise(
        create(),
        vec![
            version(),
            info(),
            step(
                "POST",
                "/v1.47/containers/create?name=test-container",
                201,
                json!({"Id":"a".repeat(64),"Warnings":[]}),
            ),
            inspect_step("created"),
            version(),
            step(
                "GET",
                "/v1.47/info",
                200,
                json!({"ID":"changed","SecurityOptions":["name=rootless"]}),
            ),
        ],
    );
    assert!(matches!(r.outcome, Outcome::Unknown { .. }));
    let (r, seen) = exercise(
        create(),
        vec![
            version(),
            info(),
            step(
                "POST",
                "/v1.47/containers/create?name=test-container",
                201,
                json!({"Id":"a".repeat(64),"Warnings":["bad"]}),
            ),
        ],
    );
    assert!(matches!(r.outcome, Outcome::Unknown { .. }));
    assert_eq!(seen.len(), 3);
}

#[test]
fn image_resolution_uses_exact_encoded_reference_and_digest_pin() {
    let reference = format!("example.test/team/image@sha256:{}", "f".repeat(64));
    let path = format!("/v1.47/images/{}/json", crate::encode(&reference));
    let operation = Operation::ResolveImage {
        image: reference.clone(),
    };
    let body = json!({"Id":format!("sha256:{}","e".repeat(64)),"RepoDigests":[reference]});
    let (r, seen) = exercise(
        operation.clone(),
        vec![
            version(),
            info(),
            step("GET", &path, 200, body),
            version(),
            info(),
        ],
    );
    assert!(matches!(r.outcome, Outcome::Image { .. }));
    assert!(seen.iter().all(|(line, _)| line.starts_with("GET ")));
    let (r, _) = exercise(
        operation.clone(),
        vec![
            version(),
            info(),
            step(
                "GET",
                &path,
                200,
                json!({"Id":format!("sha256:{}","e".repeat(64)),"RepoDigests":[]}),
            ),
        ],
    );
    assert!(matches!(r.outcome, Outcome::Unknown { .. }));
    let (r, _) = exercise(
        operation,
        vec![
            version(),
            info(),
            step("GET", &path, 404, json!({"message":"No such image"})),
        ],
    );
    assert!(matches!(r.outcome, Outcome::Unknown { .. }));
}

#[test]
fn stopped_created_is_noop_and_running_remove_never_deletes() {
    let (r, seen) = exercise(
        Operation::Stop {
            target: target(),
            grace_seconds: 10,
        },
        vec![
            version(),
            info(),
            inspect_step("created"),
            inspect_step("created"),
            version(),
            info(),
        ],
    );
    assert!(matches!(r.outcome, Outcome::Stopped { .. }));
    assert!(seen.iter().all(|(s, _)| s.starts_with("GET ")));
    let (r, seen) = exercise(
        Operation::Remove { target: target() },
        vec![version(), info(), inspect_step("running")],
    );
    assert!(matches!(r.outcome, Outcome::Unknown { .. }));
    assert!(seen.iter().all(|(s, _)| s.starts_with("GET ")));
}
#[test]
fn ambiguous_command_replies_never_retry_or_claim_success() {
    for status in [200, 400, 404, 500] {
        let t = target();
        let path = format!("/v1.47/containers/{}/start", t.object_id);
        let (r, seen) = exercise(
            Operation::Start { target: t },
            vec![
                version(),
                info(),
                inspect_step("created"),
                step("POST", path, status, json!({"message":"ambiguous"})),
            ],
        );
        assert!(matches!(r.outcome, Outcome::Unknown { .. }));
        assert_eq!(
            seen.iter().filter(|(s, _)| s.starts_with("POST ")).count(),
            1
        );
    }
    let t = target();
    let path = format!("/v1.47/containers/{}/stop?t=10", t.object_id);
    let (r, _) = exercise(
        Operation::Stop {
            target: t,
            grace_seconds: 10,
        },
        vec![
            version(),
            info(),
            inspect_step("running"),
            step("POST", path, 200, json!({})),
        ],
    );
    assert!(matches!(r.outcome, Outcome::Unknown { .. }));
    let t = target();
    let path = format!("/v1.47/containers/{}?force=false&v=false", t.object_id);
    let (r, _) = exercise(
        Operation::Remove { target: t },
        vec![
            version(),
            info(),
            inspect_step("created"),
            step("DELETE", path, 404, json!({"message":"already missing"})),
        ],
    );
    assert!(matches!(r.outcome, Outcome::Unknown { .. }));
}
#[test]
fn create_errors_and_identity_redirect_do_not_retry() {
    for status in [400, 404, 409, 500] {
        let (r, seen) = exercise(
            create(),
            vec![
                version(),
                info(),
                step(
                    "POST",
                    "/v1.47/containers/create?name=test-container",
                    status,
                    json!({"message":"failed"}),
                ),
            ],
        );
        assert!(matches!(r.outcome, Outcome::Unknown { .. }));
        assert_eq!(seen.len(), 3);
    }
    let (r, seen) = exercise(
        create(),
        vec![step("GET", "/version", 302, json!({})), info()],
    );
    assert!(matches!(r.outcome, Outcome::Unknown { .. }));
    assert!(seen.iter().all(|(s, _)| s.starts_with("GET ")));
}
#[test]
fn invalid_bounds_never_connect() {
    for (timeout, cancelled) in [
        (Duration::ZERO, false),
        (Duration::from_secs(31), false),
        (Duration::from_secs(1), true),
    ] {
        let (r, seen) = exercise_bounds(create(), vec![], timeout, cancelled);
        assert!(matches!(r.outcome, Outcome::Unknown { .. }));
        assert!(seen.is_empty());
    }
}

fn health() -> Operation {
    Operation::HealthExec {
        target: target(),
        argv: vec!["check".into(), "literal $HOME".into()],
        timeout_ms: 2000,
    }
}
fn exec_create() -> Step {
    step(
        "POST",
        format!("/v1.47/containers/{}/exec", target().object_id),
        201,
        json!({"Id":"b".repeat(64)}),
    )
}
fn exec_start() -> Step {
    step(
        "POST",
        format!("/v1.47/exec/{}/start", "b".repeat(64)),
        200,
        Value::Null,
    )
}
fn exec_poll(running: bool, exit: i32) -> Step {
    step(
        "GET",
        format!("/v1.47/exec/{}/json", "b".repeat(64)),
        200,
        json!({"ID":"b".repeat(64),"ContainerID":target().object_id,"Running":running,"ExitCode":exit}),
    )
}
#[test]
fn detached_health_polls_without_repeating_effects_and_returns_nonzero_exit() {
    for code in [0, 7] {
        let steps = vec![
            version(),
            info(),
            inspect_step("running"),
            exec_create(),
            exec_start(),
            exec_poll(true, 0),
            exec_poll(false, code),
            inspect_step("running"),
            version(),
            info(),
        ];
        let (r, seen) = exercise(health(), steps);
        let Outcome::Health { exit_code, .. } = r.outcome else {
            panic!("health failed: {:?}", r.outcome)
        };
        assert_eq!(exit_code, code);
        assert_eq!(
            seen.iter()
                .filter(|(line, _)| line.starts_with("POST "))
                .count(),
            2
        );
        let create: Value = serde_json::from_slice(&seen[3].1).unwrap();
        assert_eq!(
            create,
            json!({"Cmd":["check","literal $HOME"],"AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"Tty":false,"Privileged":false})
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&seen[4].1).unwrap(),
            json!({"Detach":true,"Tty":false})
        );
    }
}
#[test]
fn health_cancellation_before_create_after_create_start_and_poll_never_replays() {
    for limit in [3, 4, 5, 6] {
        let mut steps = vec![
            version(),
            info(),
            inspect_step("running"),
            exec_create(),
            exec_start(),
            exec_poll(true, 0),
        ];
        steps.truncate(limit);
        let (r, seen) = exercise_options(health(), steps, Duration::from_secs(3), false, limit);
        assert!(matches!(r.outcome, Outcome::Unknown { .. }));
        assert_eq!(seen.len(), limit);
        assert!(
            seen.iter()
                .filter(|(line, _)| line.ends_with("/exec HTTP/1.1"))
                .count()
                <= 1
        );
        assert!(
            seen.iter()
                .filter(|(line, _)| line.ends_with("/start HTTP/1.1"))
                .count()
                <= 1
        );
    }
}
#[test]
fn health_wrong_exec_identity_or_missing_exit_fails_closed() {
    for body in [
        json!({"ID":"c".repeat(64),"ContainerID":target().object_id,"Running":false,"ExitCode":0}),
        json!({"ID":"b".repeat(64),"ContainerID":"c".repeat(64),"Running":false,"ExitCode":0}),
        json!({"ID":"b".repeat(64),"ContainerID":target().object_id,"Running":false}),
    ] {
        let (r, _) = exercise(
            health(),
            vec![
                version(),
                info(),
                inspect_step("running"),
                exec_create(),
                exec_start(),
                step(
                    "GET",
                    format!("/v1.47/exec/{}/json", "b".repeat(64)),
                    200,
                    body,
                ),
            ],
        );
        assert!(matches!(r.outcome, Outcome::Unknown { .. }));
    }
}

#[test]
fn health_deadline_during_exec_poll_remains_unknown_without_reexecution() {
    let mut delayed = exec_poll(false, 0);
    delayed.delay = Duration::from_millis(1100);
    let operation = Operation::HealthExec {
        target: target(),
        argv: vec!["check".into()],
        timeout_ms: 1000,
    };
    let (r, seen) = exercise(
        operation,
        vec![
            version(),
            info(),
            inspect_step("running"),
            exec_create(),
            exec_start(),
            delayed,
        ],
    );
    assert!(matches!(r.outcome, Outcome::Unknown { .. }));
    assert_eq!(seen.len(), 6);
    assert_eq!(
        seen.iter().filter(|(s, _)| s.starts_with("POST ")).count(),
        2
    );
}
#[test]
fn health_ambiguous_create_start_and_terminal_container_do_not_repeat_effects() {
    let (r, seen) = exercise(health(), vec![version(), info(), inspect_step("exited")]);
    assert!(matches!(r.outcome, Outcome::Unknown { .. }));
    assert!(seen.iter().all(|(s, _)| s.starts_with("GET ")));
    let mut wrong = exec_create();
    wrong.body = serde_json::to_vec(&json!({"Id":"b".repeat(64),"extra":true})).unwrap();
    let (r, seen) = exercise(
        health(),
        vec![version(), info(), inspect_step("running"), wrong],
    );
    assert!(matches!(r.outcome, Outcome::Unknown { .. }));
    assert_eq!(seen.len(), 4);
    let mut wrong = exec_start();
    wrong.body = b"{}".to_vec();
    let (r, seen) = exercise(
        health(),
        vec![
            version(),
            info(),
            inspect_step("running"),
            exec_create(),
            wrong,
        ],
    );
    assert!(matches!(r.outcome, Outcome::Unknown { .. }));
    assert_eq!(seen.len(), 5);
}
