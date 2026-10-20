//! Independent Linux acceptance matrix for the fixture-only v2 entry.
//!
//! Run from tests/runtime-v2-wire with GATEPROBES_V2_RUNTIME_SOURCE_DIR
//! pointing at the current checkout's plugins/docker-runtime directory.
//! scripts/run-acceptance.sh supplies it and verifies the checkout is clean.

use gateprobes_runtime_v2_wire_acceptance::fake_docker::{FakeDocker, Reply, Script};
use gateprobes_runtime_v2_wire_acceptance::fixture::{self, Fixture, Pins, API_VERSION, OBJECT_ID};
use gateprobes_runtime_v2_wire_acceptance::host::{self, HostOutput, SpawnSpec};
use gateprobes_runtime_v2_wire_acceptance::memfd;
use gateprobes_runtime_v2_wire_acceptance::{
    v2, Capability, Operation, Outcome, MAX_MESSAGE_BYTES,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

struct TestRoot {
    path: PathBuf,
}

impl TestRoot {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", fixture::euid())));
        let path = base.join(format!(
            "gateprobes-wire-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("private acceptance root");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("private acceptance root mode");
        Self { path }
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(serde::Deserialize)]
struct SourceSet {
    schema: String,
    files: Vec<String>,
    host_version: String,
}

const SOURCE_SET_DOMAIN: &[u8] = b"gateprobes-runtime-v2-source-set/v1\0";
const REQUIRED_SOURCES: [&str; 4] = [
    "config.py",
    "fixture_wire.py",
    "observation.py",
    "unix_http.py",
];

fn source_set_digest(source_dir: &Path, files: &[String]) -> String {
    let mut names = files.to_vec();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), files.len(), "duplicate source-set file");
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_SET_DOMAIN);
    for name in names {
        let path = source_dir.join(&name);
        let bytes =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(bytes.len().to_string().as_bytes());
        hasher.update([0]);
        hasher.update(&bytes);
    }
    let mut output = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut output, "{byte:02x}").expect("writing digest");
    }
    output
}

struct Candidate {
    python: PathBuf,
    script: PathBuf,
    sha256: String,
    version: String,
}

impl Candidate {
    fn from_env() -> Self {
        let source_dir = PathBuf::from(
            std::env::var_os("GATEPROBES_V2_RUNTIME_SOURCE_DIR")
                .expect("GATEPROBES_V2_RUNTIME_SOURCE_DIR must point at the current checkout"),
        );
        let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("source-set.json");
        let manifest: SourceSet =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read source-set.json"))
                .expect("parse source-set.json");
        assert_eq!(manifest.schema, "gateprobes-runtime-v2-source-set/v1");
        let mut declared = manifest.files.clone();
        declared.sort();
        let mut required = REQUIRED_SOURCES.to_vec();
        required.sort();
        assert_eq!(
            declared, required,
            "source set must match the full runtime Python closure"
        );
        let script = source_dir.join("fixture_wire.py");
        let sha256 = source_set_digest(&source_dir, &manifest.files);
        let python = std::env::var_os("GATEPROBES_V2_PYTHON")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/usr/bin/python3"));
        Self {
            python,
            script,
            sha256,
            version: manifest.host_version,
        }
    }

    fn pins(&self) -> Pins {
        Pins {
            adapter_sha256: self.sha256.clone(),
            adapter_version: self.version.clone(),
        }
    }

    fn run(
        &self,
        _fixture: &Fixture,
        actual: &[u8],
        fd3: Option<OwnedFd>,
        fd4: Option<OwnedFd>,
        extras: Vec<(RawFd, OwnedFd)>,
    ) -> HostOutput {
        host::run(SpawnSpec {
            executable: self.python.clone(),
            args: vec![self.script.clone().into_os_string()],
            cwd: PathBuf::from("/"),
            stdin: actual.to_vec(),
            fd3,
            fd4,
            extras,
        })
        .expect("spawn candidate")
    }

    fn run_sealed(&self, fixture: &Fixture, actual: &[u8]) -> HostOutput {
        self.run(
            fixture,
            actual,
            Some(memfd::sealed("config", &fixture.config).expect("config memfd")),
            Some(memfd::sealed("expected", &fixture.expected_bytes()).expect("expected memfd")),
            Vec::new(),
        )
    }
}

fn socket_uid(server: &FakeDocker) -> u32 {
    fs::metadata(server.socket_path())
        .expect("socket metadata")
        .uid()
}

fn default_script() -> Script {
    Script::default()
}

fn wait_for_connections(server: &FakeDocker, minimum: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while server.connections() < minimum && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
        server.connections() >= minimum,
        "expected at least {minimum} connections, got {}",
        server.connections()
    );
}

fn assert_no_connections(server: &FakeDocker) {
    std::thread::sleep(Duration::from_millis(25));
    assert_eq!(server.connections(), 0, "candidate connected unexpectedly");
}

fn duplicate(file: &fs::File) -> OwnedFd {
    let fd = unsafe { libc::dup(file.as_raw_fd()) };
    assert!(fd >= 0, "dup failed: {}", io::Error::last_os_error());
    unsafe { OwnedFd::from_raw_fd(fd) }
}

#[test]
fn sealed_memfd_helper_is_private_and_fully_sealed() {
    let fd = memfd::sealed("helper", b"hello").expect("sealed memfd");
    let info = fs::metadata(format!("/proc/self/fd/{}", fd.as_raw_fd())).expect("fstat");
    assert_eq!(info.mode() & 0o777, 0o600);
    assert_eq!(info.nlink(), 0);
    assert_eq!(info.uid(), fixture::euid());
    assert_eq!(memfd::seals(fd.as_raw_fd()).unwrap(), memfd::REQUIRED_SEALS);
    assert_eq!(memfd::read_sealed(&fd).unwrap(), b"hello");
}

#[test]
fn capabilities_is_inspect_only_without_connection() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Capabilities,
    );
    let output = candidate.run_sealed(&fixture, &fixture.expected_bytes());
    assert!(
        output.succeeded(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout_within_limit());
    let response = v2::parse_response(&output.stdout, &fixture.expected).expect("Core v2 parse");
    assert_eq!(
        response.outcome,
        Outcome::Capabilities {
            supported: vec![Capability::Inspect]
        }
    );
    assert_eq!(response.observations, None);
    assert_eq!(response.binding, fixture.expected.binding);
    assert_eq!(response.operation, fixture.expected.operation);
    assert_no_connections(&server);
}

#[test]
fn remove_is_static_error_with_empty_stdout_and_no_connection() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Remove {
            object_id: OBJECT_ID.into(),
        },
    );
    let output = candidate.run_sealed(&fixture, &fixture.expected_bytes());
    assert!(!output.succeeded(), "Remove must fail statically");
    assert!(output.stdout_empty(), "Remove must not emit partial output");
    assert!(!output.stderr.is_empty());
    assert_no_connections(&server);
}

#[test]
fn inspect_present_is_full_binding_and_core_parsed() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Inspect {
            object_id: OBJECT_ID.into(),
        },
    );
    let output = candidate.run_sealed(&fixture, &fixture.expected_bytes());
    assert!(
        output.succeeded(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout_within_limit());
    let response = v2::parse_response(&output.stdout, &fixture.expected).expect("Core v2 parse");
    let Outcome::Present { object } = &response.outcome else {
        panic!("expected Present, got {:?}", response.outcome);
    };
    assert_eq!(object.object_id, OBJECT_ID);
    assert!(response.observations.is_some());
    assert_eq!(response.binding, fixture.expected.binding);
    wait_for_connections(&server, 5);
    assert_eq!(server.connections(), 5);
}

#[test]
fn inspect_404_is_unavailable_never_absent() {
    let root = TestRoot::new();
    let mut script = default_script();
    script.container = Reply::Status(404, b"{\"message\":\"no such container\"}".to_vec());
    let server = FakeDocker::start(&root.path, API_VERSION, script).unwrap();
    let candidate = Candidate::from_env();
    let fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Inspect {
            object_id: OBJECT_ID.into(),
        },
    );
    let output = candidate.run_sealed(&fixture, &fixture.expected_bytes());
    assert!(
        output.succeeded(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response = v2::parse_response(&output.stdout, &fixture.expected).expect("Core v2 parse");
    assert_eq!(response.outcome, Outcome::Unavailable);
    assert!(!matches!(response.outcome, Outcome::Absent));
    assert_eq!(response.observations, None);
    wait_for_connections(&server, 3);
    assert_eq!(server.connections(), 3);
}

#[test]
fn missing_fd3_or_fd4_is_rejected_before_connect() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Inspect {
            object_id: OBJECT_ID.into(),
        },
    );
    let expected = memfd::sealed("expected", &fixture.expected_bytes()).unwrap();
    let output = candidate.run(
        &fixture,
        &fixture.expected_bytes(),
        None,
        Some(expected),
        Vec::new(),
    );
    assert!(!output.succeeded());
    assert!(output.stdout_empty());
    assert_no_connections(&server);

    let config = memfd::sealed("config", &fixture.config).unwrap();
    let output = candidate.run(
        &fixture,
        &fixture.expected_bytes(),
        Some(config),
        None,
        Vec::new(),
    );
    assert!(!output.succeeded());
    assert!(output.stdout_empty());
    assert_no_connections(&server);
}

#[test]
fn unsealed_memfd_is_rejected_before_connect() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Inspect {
            object_id: OBJECT_ID.into(),
        },
    );
    let output = candidate.run(
        &fixture,
        &fixture.expected_bytes(),
        Some(memfd::unsealed("config", &fixture.config).unwrap()),
        Some(memfd::sealed("expected", &fixture.expected_bytes()).unwrap()),
        Vec::new(),
    );
    assert!(!output.succeeded());
    assert!(output.stdout_empty());
    assert_no_connections(&server);
}

#[test]
fn regular_file_descriptor_is_rejected_before_connect() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Inspect {
            object_id: OBJECT_ID.into(),
        },
    );
    let config_path = root.path.join("config.json");
    let file = memfd::regular_file(&config_path, &fixture.config).unwrap();
    let output = candidate.run(
        &fixture,
        &fixture.expected_bytes(),
        Some(duplicate(&file)),
        Some(memfd::sealed("expected", &fixture.expected_bytes()).unwrap()),
        Vec::new(),
    );
    assert!(!output.succeeded());
    assert!(output.stdout_empty());
    assert_no_connections(&server);
}

#[test]
fn extra_live_descriptor_is_rejected_before_connect() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Inspect {
            object_id: OBJECT_ID.into(),
        },
    );
    let output = candidate.run(
        &fixture,
        &fixture.expected_bytes(),
        Some(memfd::sealed("config", &fixture.config).unwrap()),
        Some(memfd::sealed("expected", &fixture.expected_bytes()).unwrap()),
        vec![(5, memfd::sealed("extra", b"extra").unwrap())],
    );
    assert!(!output.succeeded());
    assert!(output.stdout_empty());
    assert_no_connections(&server);
}

#[test]
fn config_digest_mismatch_is_rejected_before_connect() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let mut fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Inspect {
            object_id: OBJECT_ID.into(),
        },
    );
    let mut config: serde_json::Value = serde_json::from_slice(&fixture.config).unwrap();
    config["scope"] = json!("different-scope");
    fixture.config = serde_json::to_vec(&config).unwrap();
    let output = candidate.run_sealed(&fixture, &fixture.expected_bytes());
    assert!(!output.succeeded());
    assert!(output.stdout_empty());
    assert_no_connections(&server);
}

#[test]
fn binding_pin_mismatch_is_rejected_before_connect() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let mut fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Inspect {
            object_id: OBJECT_ID.into(),
        },
    );
    fixture.expected.binding.server_version = "27.9.9".into();
    let output = candidate.run_sealed(&fixture, &fixture.expected_bytes());
    assert!(!output.succeeded());
    assert!(output.stdout_empty());
    assert_no_connections(&server);
}

#[test]
fn typed_actual_mismatch_is_rejected_before_connect() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Inspect {
            object_id: OBJECT_ID.into(),
        },
    );
    let mut actual = fixture.expected.clone();
    actual.binding.generation = "different-generation".into();
    let output = candidate.run_sealed(
        &fixture,
        &serde_json::to_vec(&actual).expect("actual request"),
    );
    assert!(!output.succeeded());
    assert!(output.stdout_empty());
    assert_no_connections(&server);
}

#[test]
fn typed_equivalent_actual_is_accepted_despite_different_bytes() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Capabilities,
    );
    let actual = serde_json::to_vec_pretty(&fixture.expected).expect("pretty request");
    assert_ne!(actual, fixture.expected_bytes());
    let output = candidate.run_sealed(&fixture, &actual);
    assert!(
        output.succeeded(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response = v2::parse_response(&output.stdout, &fixture.expected).expect("Core v2 parse");
    assert_eq!(
        response.outcome,
        Outcome::Capabilities {
            supported: vec![Capability::Inspect]
        }
    );
    assert_no_connections(&server);
}

#[test]
fn unsealed_expected_fd4_is_rejected_before_connect() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Inspect {
            object_id: OBJECT_ID.into(),
        },
    );
    let output = candidate.run(
        &fixture,
        &fixture.expected_bytes(),
        Some(memfd::sealed("config", &fixture.config).unwrap()),
        Some(memfd::unsealed("expected", &fixture.expected_bytes()).unwrap()),
        Vec::new(),
    );
    assert!(!output.succeeded());
    assert!(output.stdout_empty());
    assert_no_connections(&server);
}

#[test]
fn non_private_memfd_mode_is_rejected_before_connect() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Inspect {
            object_id: OBJECT_ID.into(),
        },
    );
    let config = memfd::sealed("config", &fixture.config).unwrap();
    assert_eq!(unsafe { libc::fchmod(config.as_raw_fd(), 0o644) }, 0);
    let output = candidate.run(
        &fixture,
        &fixture.expected_bytes(),
        Some(config),
        Some(memfd::sealed("expected", &fixture.expected_bytes()).unwrap()),
        Vec::new(),
    );
    assert!(!output.succeeded());
    assert!(output.stdout_empty());
    assert_no_connections(&server);
}

#[test]
fn pread_ignores_descriptor_offsets() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Capabilities,
    );
    let config = memfd::sealed("config", &fixture.config).unwrap();
    let expected = memfd::sealed("expected", &fixture.expected_bytes()).unwrap();
    for fd in [&config, &expected] {
        let offset = unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_END) };
        assert!(offset >= 0);
    }
    let output = candidate.run(
        &fixture,
        &fixture.expected_bytes(),
        Some(config),
        Some(expected),
        Vec::new(),
    );
    assert!(
        output.succeeded(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response = v2::parse_response(&output.stdout, &fixture.expected).expect("Core v2 parse");
    assert_eq!(
        response.outcome,
        Outcome::Capabilities {
            supported: vec![Capability::Inspect]
        }
    );
    assert_no_connections(&server);
}

#[test]
fn every_config_derived_pin_mismatch_is_rejected_before_connect() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let base = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Inspect {
            object_id: OBJECT_ID.into(),
        },
    );
    type Mutation = (&'static str, Box<dyn Fn(&mut v2::Request)>);
    let mutations: Vec<Mutation> = vec![
        (
            "socket_path",
            Box::new(|request| request.binding.socket_path = "/run/other.sock".into()),
        ),
        (
            "socket_uid",
            Box::new(|request| request.binding.socket_uid = 4321),
        ),
        (
            "principal_uid",
            Box::new(|request| request.binding.principal_uid = 4321),
        ),
        (
            "rootless",
            Box::new(|request| request.binding.rootless = true),
        ),
        (
            "api_version",
            Box::new(|request| request.binding.api_version = "1.48".into()),
        ),
        (
            "server_version",
            Box::new(|request| request.binding.server_version = "27.9.9".into()),
        ),
        (
            "daemon_id",
            Box::new(|request| request.binding.daemon_id = "other-daemon".into()),
        ),
        (
            "scope",
            Box::new(|request| request.binding.scope = "other-scope".into()),
        ),
    ];
    for (name, mutate) in mutations {
        let mut fixture = base.clone();
        mutate(&mut fixture.expected);
        let output = candidate.run_sealed(&fixture, &fixture.expected_bytes());
        assert!(!output.succeeded(), "pin {name} was not rejected");
        assert!(output.stdout_empty(), "pin {name} emitted output");
        assert_no_connections(&server);
    }
}

#[test]
fn oversized_actual_stdin_is_rejected_before_connect() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Inspect {
            object_id: OBJECT_ID.into(),
        },
    );
    let actual = vec![b' '; MAX_MESSAGE_BYTES + 1];
    let output = candidate.run_sealed(&fixture, &actual);
    assert!(!output.succeeded());
    assert!(output.stdout_empty());
    assert_no_connections(&server);
}

#[test]
fn unknown_actual_field_is_rejected_before_connect() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Inspect {
            object_id: OBJECT_ID.into(),
        },
    );
    let mut actual: serde_json::Value = serde_json::from_slice(&fixture.expected_bytes()).unwrap();
    actual["extra"] = json!(true);
    let output = candidate.run_sealed(&fixture, &serde_json::to_vec(&actual).unwrap());
    assert!(!output.succeeded());
    assert!(output.stdout_empty());
    assert_no_connections(&server);
}

#[test]
fn oversized_present_fails_without_partial_stdout() {
    let root = TestRoot::new();
    let mut script = default_script();
    script.container = Reply::Json(json!({
        "Id": OBJECT_ID,
        "Config": {"Labels": {"harness-gate.owner": "x".repeat(70_000)}}
    }));
    let server = FakeDocker::start(&root.path, API_VERSION, script).unwrap();
    let candidate = Candidate::from_env();
    let fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Inspect {
            object_id: OBJECT_ID.into(),
        },
    );
    let output = candidate.run_sealed(&fixture, &fixture.expected_bytes());
    assert!(!output.succeeded());
    assert!(
        output.stdout_empty(),
        "oversized output must not be partial"
    );
    assert!(output.stdout_within_limit());
}

#[test]
fn oversized_config_memfd_is_rejected_before_connect() {
    let root = TestRoot::new();
    let server = FakeDocker::start(&root.path, API_VERSION, default_script()).unwrap();
    let candidate = Candidate::from_env();
    let mut fixture = Fixture::new(
        &server.socket_path(),
        socket_uid(&server),
        &candidate.pins(),
        Operation::Inspect {
            object_id: OBJECT_ID.into(),
        },
    );
    let mut config: serde_json::Value = serde_json::from_slice(&fixture.config).unwrap();
    config["scope"] = json!("x".repeat(MAX_MESSAGE_BYTES));
    fixture.config = serde_json::to_vec(&config).unwrap();
    assert!(fixture.config.len() > MAX_MESSAGE_BYTES);
    let output = candidate.run_sealed(&fixture, &fixture.expected_bytes());
    assert!(!output.succeeded());
    assert!(output.stdout_empty());
    assert_no_connections(&server);
}
