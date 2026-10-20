//! Protected local Unix-socket identity tests. Fake listeners only; no connect.

use gateprobes_docker_runtime::input::Config;
use gateprobes_docker_runtime::socket_identity::SocketIdentity;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Root(PathBuf);

impl Root {
    fn new() -> Self {
        let base = std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".cache"))
            .filter(|path| path.is_dir() && protected(path))
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", euid())));
        let path = base.join(format!(
            "gateprobes-socket-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
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

fn config(root: &Root, socket_uid: u32, principal_uid: u32) -> Config {
    Config {
        schema: "gate-runtime-engine-config/v2".into(),
        engine: "docker".into(),
        transport: "unix-http".into(),
        socket_path: root.socket().to_string_lossy().into_owned(),
        socket_uid,
        principal_uid,
        rootless: false,
        api_version: "1.47".into(),
        server_version: "27.0.1".into(),
        daemon_id: "daemon-1".into(),
        scope: "scope-1".into(),
    }
}

fn bind(root: &Root) -> UnixListener {
    UnixListener::bind(root.socket()).unwrap()
}

#[test]
fn accepts_protected_current_user_socket_without_connecting() {
    let root = Root::new();
    let _listener = bind(&root);
    let identity = SocketIdentity::verify(&config(&root, euid(), euid())).unwrap();
    assert_eq!(identity.path(), root.socket());
    identity.revalidate().unwrap();
}

#[test]
fn rejects_nonabsolute_missing_nonsocket_and_symlinked_paths() {
    let root = Root::new();
    let _listener = bind(&root);
    let mut cfg = config(&root, euid(), euid());
    cfg.socket_path = "relative.sock".into();
    assert!(SocketIdentity::verify(&cfg).is_err());

    cfg.socket_path = root
        .path()
        .join("missing.sock")
        .to_string_lossy()
        .into_owned();
    assert!(SocketIdentity::verify(&cfg).is_err());

    let regular = root.path().join("regular");
    fs::write(&regular, b"not a socket").unwrap();
    cfg.socket_path = regular.to_string_lossy().into_owned();
    assert!(SocketIdentity::verify(&cfg).is_err());

    let link = root.path().join("socket-link");
    symlink(root.socket(), &link).unwrap();
    cfg.socket_path = link.to_string_lossy().into_owned();
    assert!(SocketIdentity::verify(&cfg).is_err());
}

#[test]
fn rejects_symlink_parent_and_writable_ancestor() {
    let root = Root::new();
    let _listener = bind(&root);

    let linked_parent = root.path().join("linked");
    symlink(root.path(), &linked_parent).unwrap();
    let mut cfg = config(&root, euid(), euid());
    cfg.socket_path = linked_parent
        .join("docker.sock")
        .to_string_lossy()
        .into_owned();
    assert!(SocketIdentity::verify(&cfg).is_err());

    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
    let err = match SocketIdentity::verify(&config(&root, euid(), euid())) {
        Ok(_) => panic!("writable ancestor accepted"),
        Err(error) => error,
    };
    assert_eq!(err, "runtime local identity rejected");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn rejects_owner_or_principal_mismatch() {
    let root = Root::new();
    let _listener = bind(&root);
    assert!(SocketIdentity::verify(&config(&root, euid().wrapping_add(1), euid())).is_err());
    assert!(SocketIdentity::verify(&config(&root, euid(), euid().wrapping_add(1))).is_err());
}

#[test]
fn revalidation_detects_replacement_and_mode_changes() {
    let root = Root::new();
    let first = bind(&root);
    let identity = SocketIdentity::verify(&config(&root, euid(), euid())).unwrap();
    identity.revalidate().unwrap();

    fs::remove_file(root.socket()).unwrap();
    drop(first);
    let _second = bind(&root);
    assert_eq!(
        identity.revalidate().unwrap_err(),
        "runtime local identity changed"
    );

    let root = Root::new();
    let _listener = bind(&root);
    let identity = SocketIdentity::verify(&config(&root, euid(), euid())).unwrap();
    fs::set_permissions(root.socket(), fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(
        identity.revalidate().unwrap_err(),
        "runtime local identity changed"
    );
}
