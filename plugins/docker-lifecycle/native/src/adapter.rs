//! Only sealed config/expected plus exact stdin can reach lifecycle HTTP calls.
//! Filesystem and daemon observations are assertions, not OS containment.
use crate::{
    create_request, docker, http, json::document, socket_identity::SocketIdentity, Result,
};
use gatehouse_runtime_protocol::lifecycle::{
    installation::parse_protected_inputs,
    wire::{
        self, Absence, ContainerState, EngineBinding, Observation, Observations, Operation,
        Outcome, Reason, Request, Response, Target,
    },
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    time::{Duration, Instant},
};

/// No free Request/executable/endpoint entry. The caller supplies only protected
/// descriptor handles and bounded stdin. Core owns durable intent and timeout.
pub fn execute(
    config: &File,
    expected: &File,
    stdin: &[u8],
    timeout: Duration,
    cancelled: impl Fn() -> bool,
) -> Result<Response> {
    let request = parse_protected_inputs(config, expected, stdin)
        .map_err(|_| "lifecycle protected input rejected")?;
    let unknown = || Response {
        protocol: request.protocol.clone(),
        binding: request.binding.clone(),
        operation: request.operation.clone(),
        outcome: Outcome::Unknown {
            reason: Reason::Transport,
        },
        observations: None,
    };
    if timeout.is_zero() || timeout > Duration::from_secs(30) || cancelled() {
        return Ok(unknown());
    }
    if matches!(request.operation, Operation::HealthExec { .. }) {
        return Ok(Response {
            outcome: Outcome::RejectedBeforeEffect {
                reason: Reason::UnsupportedState,
            },
            ..unknown()
        });
    }
    let deadline = Instant::now() + timeout;
    let result = operate(&request, deadline, &cancelled);
    let response = result.unwrap_or_else(|_| unknown());
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
        format!("/v{}/containers/{id}/{suffix}", self.config.api_version)
    }
    fn identity(&self) -> Result<Observation> {
        let version = self.exchange("GET", "/version", &[])?;
        let info = self.exchange("GET", &format!("/v{}/info", self.config.api_version), &[])?;
        if version.status != 200 || info.status != 200 {
            return Err("identity HTTP rejected");
        }
        let v = document(&version.body)?;
        let i = document(&info.body)?;
        let parse = |s: &str| -> Result<(u16, u16)> {
            let (a, b) = s.split_once('.').ok_or("API version rejected")?;
            let x: u16 = a.parse().map_err(|_| "API version rejected")?;
            let y: u16 = b.parse().map_err(|_| "API version rejected")?;
            if x.to_string() != a || y.to_string() != b {
                return Err("API version rejected");
            }
            Ok((x, y))
        };
        let min = parse(v["MinAPIVersion"].as_str().ok_or("API minimum missing")?)?;
        let max = parse(v["ApiVersion"].as_str().ok_or("API maximum missing")?)?;
        let selected = parse(&self.config.api_version)?;
        let options = i["SecurityOptions"]
            .as_array()
            .ok_or("security options missing")?;
        let mut rootless = false;
        for option in options {
            let value = option.as_str().ok_or("security option rejected")?;
            rootless |= value == "name=rootless";
        }
        if !(min..=max).contains(&selected)
            || v["Version"].as_str() != Some(&self.config.server_version)
            || i["ID"].as_str() != Some(&self.config.daemon_id)
            || rootless != self.config.rootless
        {
            return Err("daemon identity changed");
        }
        Ok(Observation {
            api_version: self.config.api_version.clone(),
            server_version: self.config.server_version.clone(),
            daemon_id: self.config.daemon_id.clone(),
        })
    }
    fn inspect(&self, target: &Target, image: Option<&str>) -> Result<wire::Object> {
        let reply = self.exchange("GET", &self.path(&target.object_id, "json"), &[])?;
        if reply.status != 200 {
            return Err("container inspection unavailable");
        }
        docker::inspect(&reply.body, target, image)
    }
    fn command(&self, target: &Target, suffix: &str) -> Result<()> {
        let reply = self.exchange("POST", &self.path(&target.object_id, suffix), &[])?;
        if !matches!(reply.status, 204 | 304) || !reply.body.is_empty() {
            return Err("container command uncertain");
        }
        Ok(())
    }
    fn outcome(&self, request: &Request) -> Result<Outcome> {
        match &request.operation {
            Operation::ResolveImage { image } => {
                let path = format!(
                    "/v{}/images/{}/json",
                    self.config.api_version,
                    crate::encode(image)
                );
                let reply = self.exchange("GET", &path, &[])?;
                if reply.status != 200 {
                    return Err("image resolution unavailable");
                }
                docker::image(&reply.body, image)
            }
            Operation::Create {
                name,
                image_id,
                labels,
                container_port,
                ..
            } => {
                let call = create_request(request)?;
                let body = serde_json::to_vec(&call.body).map_err(|_| "create encoding failed")?;
                let reply = self.exchange("POST", &call.route, &body)?;
                if reply.status != 201 {
                    return Err("create uncertain");
                }
                let object_id = docker::created(&reply.body)?;
                let target = Target {
                    object_id,
                    name: name.clone(),
                    labels: labels.clone(),
                    container_port: *container_port,
                };
                let object = self.inspect(&target, Some(image_id))?;
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
                        object: docker::inspect(&reply.body, target, None)?,
                    });
                }
                if reply.status != 404 {
                    return Err("status unavailable");
                }
                docker::exact_absence(&reply.body, target)?;
                Ok(Outcome::Absent {
                    evidence: Absence {
                        route,
                        object_id: target.object_id.clone(),
                        http_status: 404,
                        error_message_sha256: format!(
                            "{:x}",
                            Sha256::digest(
                                format!("No such container: {}", target.object_id).as_bytes()
                            )
                        ),
                    },
                })
            }
            Operation::Start { target } => {
                let before = self.inspect(target, None)?;
                if before.state != ContainerState::Created {
                    return Err("start state rejected");
                }
                self.command(target, "start")?;
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
                    self.command(target, &format!("stop?t={grace_seconds}"))?;
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
                    "/v{}/containers/{}?force=false&v=false",
                    self.config.api_version, target.object_id
                );
                let reply = self.exchange("DELETE", &path, &[])?;
                if reply.status != 204 || !reply.body.is_empty() {
                    return Err("remove uncertain");
                }
                Ok(Outcome::Removed)
            }
            _ => Err("operation not implemented"),
        }
    }
}
fn operate(
    request: &Request,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<Response> {
    let engine = Engine {
        config: &request.binding.engine_binding,
        socket: SocketIdentity::verify(&request.binding.engine_binding)?,
        deadline,
        cancelled,
    };
    let before = engine.identity()?;
    let outcome = engine.outcome(request)?;
    let after = engine.identity()?;
    if before != after || cancelled() || Instant::now() >= deadline {
        return Err("lifecycle final boundary rejected");
    }
    let response = Response {
        protocol: request.protocol.clone(),
        binding: request.binding.clone(),
        operation: request.operation.clone(),
        outcome,
        observations: Some(Observations {
            observed_before: before,
            observed_after: after,
        }),
    };
    response
        .validate(request)
        .map_err(|_| "lifecycle final response invalid")?;
    Ok(response)
}

#[cfg(test)]
mod tests;
