//! Host-pinned config and expected request construction.

use crate::memfd::sha256_hex;
use crate::{v2, Operation};
use serde_json::json;

pub const API_VERSION: &str = "1.47";
pub const SERVER_VERSION: &str = "27.0.1";
pub const DAEMON_ID: &str = "daemon-1";
pub const SCOPE: &str = "harness-gate.acceptance";
pub const OBJECT_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

pub fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

pub struct Pins {
    pub adapter_sha256: String,
    pub adapter_version: String,
}

#[derive(Clone)]
pub struct Fixture {
    pub config: Vec<u8>,
    pub expected: v2::Request,
}

impl Fixture {
    pub fn new(socket_path: &str, socket_uid: u32, pins: &Pins, operation: Operation) -> Self {
        let principal_uid = euid();
        let config = serde_json::to_vec(&json!({
            "schema": "gate-runtime-engine-config/v2",
            "engine": "docker",
            "transport": "unix-http",
            "socket_path": socket_path,
            "socket_uid": socket_uid,
            "principal_uid": principal_uid,
            "rootless": false,
            "api_version": API_VERSION,
            "server_version": SERVER_VERSION,
            "daemon_id": DAEMON_ID,
            "scope": SCOPE,
        }))
        .expect("config serialization");
        let binding = v2::Binding {
            protocol: v2::Protocol::V2,
            adapter_sha256: pins.adapter_sha256.clone(),
            adapter_version: pins.adapter_version.clone(),
            invocation: "inv-acceptance-1".into(),
            operation_key: "op-acceptance-1".into(),
            generation: "gen-acceptance-1".into(),
            adapter_config_sha256: sha256_hex(&config),
            engine: v2::Engine::Docker,
            transport: v2::Transport::UnixHttp,
            socket_path: socket_path.into(),
            socket_uid,
            principal_uid,
            rootless: false,
            api_version: API_VERSION.into(),
            server_version: SERVER_VERSION.into(),
            daemon_id: DAEMON_ID.into(),
            scope: SCOPE.into(),
        };
        Self {
            config,
            expected: v2::Request { binding, operation },
        }
    }

    pub fn expected_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.expected).expect("request serialization")
    }
}
