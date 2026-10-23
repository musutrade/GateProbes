//! Protected native Podman 5.7 lifecycle adapter. Core owns durable intent,
//! lease/fencing, timeout, recovery and every retry decision.
use super::{http, json, podman, socket_identity::SocketIdentity};
use crate::Result;
use gatehouse_runtime_protocol::lifecycle::{
    installation::parse_protected_inputs,
    wire::{
        exact_absence, ContainerState, EngineBinding, Observation, Observations, Operation,
        Outcome, Reason, Request, Response, Target,
    },
};
use std::{
    fs::File,
    thread,
    time::{Duration, Instant},
};

const MAX_DEADLINE: Duration = Duration::from_secs(30);
const EXEC_START_BODY: &[u8] = br#"{"Detach":true,"Tty":false,"h":0,"w":0}"#;

/// Only protected installation descriptors and exact stdin reach Libpod I/O.
/// A lost or malformed response becomes Unknown, never an implicit retry.
pub fn execute(
    config: &File,
    expected: &File,
    stdin: &[u8],
    timeout: Duration,
    cancelled: impl Fn() -> bool,
) -> Result<Response> {
    let request = parse_protected_inputs(config, expected, stdin)
        .map_err(|_| "protected lifecycle input rejected")?;
    let unknown = || Response {
        protocol: request.protocol.clone(),
        binding: request.binding.clone(),
        operation: request.operation.clone(),
        outcome: Outcome::Unknown {
            reason: Reason::Transport,
        },
        observations: None,
    };
    if timeout.is_zero() || timeout > MAX_DEADLINE || cancelled() {
        return Ok(unknown());
    }
    let mut deadline = Instant::now() + timeout;
    if let Operation::HealthExec { timeout_ms, .. } = &request.operation {
        deadline = deadline.min(Instant::now() + Duration::from_millis(u64::from(*timeout_ms)));
    }
    let response = operate(&request, deadline, &cancelled).unwrap_or_else(|_| unknown());
    response
        .validate(&request)
        .map_err(|_| "lifecycle response rejected")?;
    Ok(response)
}

struct Engine<'a, F: Fn() -> bool> {
    config: &'a EngineBinding,
    socket: SocketIdentity,
    deadline: Instant,
    cancelled: &'a F,
}

impl<F: Fn() -> bool> Engine<'_, F> {
    fn exchange(&self, method: &str, path: &str, body: &[u8]) -> Result<http::Reply> {
        http::exchange(
            self.config,
            &self.socket,
            method,
            path,
            body,
            self.deadline,
            self.cancelled,
        )
    }

    fn path(&self, id: &str, suffix: &str) -> String {
        format!(
            "/v{}/libpod/containers/{id}/{suffix}",
            self.config.api_version
        )
    }

    /// Podman has no Docker daemon UUID. Bind the observed host name, API
    /// version, rootless flag and graph root. This is an observation, not
    /// authentication or proof that the daemon did not restart.
    fn identity(&self) -> Result<Observation> {
        let info = self.exchange(
            "GET",
            &format!("/v{}/libpod/info", self.config.api_version),
            &[],
        )?;
        if info.status != 200 {
            return Err("Podman identity unavailable");
        }
        let value = json::document(&info.body)?;
        let api = value["version"]["APIVersion"].as_str();
        let version = value["version"]["Version"].as_str();
        let hostname = value["host"]["hostname"].as_str();
        let rootless = value["host"]["security"]["rootless"].as_bool();
        let graph_root = value["store"]["graphRoot"].as_str();
        if api != Some(self.config.api_version.as_str())
            || version != Some(self.config.server_version.as_str())
            || hostname != Some(self.config.daemon_id.as_str())
            || rootless != Some(self.config.rootless)
            || graph_root != Some(self.config.scope.as_str())
        {
            return Err("Podman identity changed");
        }
        Ok(Observation {
            api_version: self.config.api_version.clone(),
            server_version: self.config.server_version.clone(),
            daemon_id: self.config.daemon_id.clone(),
        })
    }

    fn inspect(
        &self,
        target: &Target,
        image: Option<&str>,
    ) -> Result<gatehouse_runtime_protocol::lifecycle::wire::Object> {
        let reply = self.exchange("GET", &self.path(&target.object_id, "json"), &[])?;
        if reply.status != 200 {
            return Err("container inspection unavailable");
        }
        podman::inspect(&reply.body, target, image)
    }

    fn command(&self, target: &Target, suffix: &str) -> Result<http::Reply> {
        self.exchange("POST", &self.path(&target.object_id, suffix), &[])
    }

    fn outcome(&self, request: &Request) -> Result<Outcome> {
        match &request.operation {
            Operation::ResolveImage { image } => {
                let encoded = encode(image);
                let reply = self.exchange(
                    "GET",
                    &format!("/v{}/libpod/images/{encoded}/json", self.config.api_version),
                    &[],
                )?;
                if reply.status != 200 {
                    return Err("image resolution unavailable");
                }
                podman::image(&reply.body, image)
            }
            Operation::Create {
                name,
                labels,
                container_port,
                ..
            } => {
                let body = podman::create_body(request)?;
                let body = serde_json::to_vec(&body).map_err(|_| "create encoding failed")?;
                let reply = self.exchange(
                    "POST",
                    &format!("/v{}/libpod/containers/create", self.config.api_version),
                    &body,
                )?;
                if reply.status != 201 {
                    return Err("create uncertain");
                }
                let object_id = podman::created(&reply.body)?;
                let target = Target {
                    object_id,
                    name: name.clone(),
                    labels: labels.clone(),
                    container_port: *container_port,
                };
                let object = self.inspect(&target, None)?;
                if object.state != ContainerState::Created {
                    return Err("create state unexpected");
                }
                Ok(Outcome::Created { object })
            }
            Operation::Status { target } => {
                let route = self.path(&target.object_id, "json");
                let reply = self.exchange("GET", &route, &[])?;
                if reply.status == 200 {
                    return Ok(Outcome::Status {
                        object: podman::inspect(&reply.body, target, None)?,
                    });
                }
                if reply.status != 404 {
                    return Err("status unavailable");
                }
                podman::exact_absence(&reply.body, target)?;
                Ok(Outcome::Absent {
                    evidence: exact_absence(self.config, target)
                        .map_err(|_| "absence evidence rejected")?,
                })
            }
            Operation::Start { target } => {
                let before = self.inspect(target, None)?;
                if before.state != ContainerState::Created {
                    return Err("start state rejected");
                }
                let reply = self.command(target, "start")?;
                if !matches!(reply.status, 204 | 304) || !reply.body.is_empty() {
                    return Err("start uncertain");
                }
                let object = self.inspect(target, None)?;
                if object.state != ContainerState::Running {
                    return Err("start state uncertain");
                }
                Ok(Outcome::Started { object })
            }
            Operation::Stop {
                target,
                grace_seconds,
            } => {
                let before = self.inspect(target, None)?;
                if before.state == ContainerState::Running {
                    let reply = self.command(target, &format!("stop?t={grace_seconds}"))?;
                    // Podman 5.7 can report a rootless-netns cleanup error after
                    // the container is terminal. A fresh exact-ID observation is
                    // required before accepting that transition; a still-running
                    // or unreadable object remains Unknown.
                    if !matches!(reply.status, 204 | 304) || !reply.body.is_empty() {
                        let observed = self.inspect(target, None)?;
                        if !matches!(
                            observed.state,
                            ContainerState::Created | ContainerState::Exited
                        ) {
                            return Err("stop uncertain");
                        }
                    }
                } else if !matches!(
                    before.state,
                    ContainerState::Created | ContainerState::Exited
                ) {
                    return Err("stop state rejected");
                }
                let object = self.inspect(target, None)?;
                if !matches!(
                    object.state,
                    ContainerState::Created | ContainerState::Exited
                ) {
                    return Err("stop state uncertain");
                }
                Ok(Outcome::Stopped { object })
            }
            Operation::Remove { target } => {
                let before = self.inspect(target, None)?;
                if !matches!(
                    before.state,
                    ContainerState::Created | ContainerState::Exited
                ) {
                    return Err("remove state rejected");
                }
                let path = format!(
                    "/v{}/libpod/containers/{}?force=false&volumes=false",
                    self.config.api_version, target.object_id
                );
                let reply = self.exchange("DELETE", &path, &[])?;
                if reply.status == 204 && reply.body.is_empty() {
                    return Ok(Outcome::Removed);
                }
                if reply.status != 200 {
                    return Err("remove uncertain");
                }
                podman::remove_claim(&reply.body, &target.object_id)?;
                Ok(Outcome::Removed)
            }
            Operation::HealthExec { target, argv, .. } => self.health(target, argv),
        }
    }

    fn health(&self, target: &Target, argv: &[String]) -> Result<Outcome> {
        let before = self.inspect(target, None)?;
        if before.state != ContainerState::Running {
            return Err("health container not running");
        }
        let body =
            serde_json::to_vec(&podman::exec_body(argv)?).map_err(|_| "exec encoding failed")?;
        let reply = self.exchange(
            "POST",
            &format!(
                "/v{}/libpod/containers/{}/exec",
                self.config.api_version, target.object_id
            ),
            &body,
        )?;
        if reply.status != 201 {
            return Err("exec create uncertain");
        }
        let exec = podman::exec_created(&reply.body)?;
        let started = self.exchange(
            "POST",
            &format!("/v{}/libpod/exec/{exec}/start", self.config.api_version),
            EXEC_START_BODY,
        )?;
        if started.status != 200 || !matches!(started.body.as_slice(), b"" | b"\n") {
            return Err("exec start uncertain");
        }
        loop {
            if (self.cancelled)() || Instant::now() >= self.deadline {
                return Err("health deadline or cancellation");
            }
            let reply = self.exchange(
                "GET",
                &format!("/v{}/libpod/exec/{exec}/json", self.config.api_version),
                &[],
            )?;
            if reply.status != 200 {
                return Err("exec inspection unavailable");
            }
            match podman::health(&reply.body, &exec, &target.object_id, argv)? {
                podman::HealthObservation::Pending => thread::sleep(Duration::from_millis(100)),
                podman::HealthObservation::Completed(code) => {
                    let object = self.inspect(target, None)?;
                    if object.state != ContainerState::Running {
                        return Err("health container changed");
                    }
                    return Ok(Outcome::Health {
                        exec_id: exec,
                        exit_code: i32::from(code),
                        object,
                    });
                }
            }
        }
    }
}

fn operate(
    request: &Request,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<Response> {
    let socket = SocketIdentity::verify(&request.binding.engine_binding)?;
    let engine = Engine {
        config: &request.binding.engine_binding,
        socket,
        deadline,
        cancelled,
    };
    let before = engine.identity()?;
    let outcome = engine.outcome(request)?;
    let after = engine.identity()?;
    Ok(Response {
        protocol: request.protocol.clone(),
        binding: request.binding.clone(),
        operation: request.operation.clone(),
        outcome,
        observations: Some(Observations {
            observed_before: before,
            observed_after: after,
        }),
    })
}

fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}
