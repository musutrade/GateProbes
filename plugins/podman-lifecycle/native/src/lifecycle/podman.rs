//! Libpod 5.7 document checks and the exact create request. Facts only; the
//! durable Core journal and protected installation remain the authority.
use super::json::{any, document};
use crate::Result;
use gatehouse_runtime_protocol::lifecycle::wire::{
    ContainerState, Entry, Object, Operation, Outcome, Port, Request, Target,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

const ERROR: &str = "lifecycle Podman document rejected";

fn id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn native_image(value: &str) -> Option<String> {
    if id(value) {
        Some(format!("sha256:{value}"))
    } else {
        value
            .strip_prefix("sha256:")
            .filter(|v| id(v))
            .map(|v| format!("sha256:{v}"))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Created {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Warnings")]
    warnings: Vec<String>,
}

pub(crate) fn created(bytes: &[u8]) -> Result<String> {
    let created: Created = serde_json::from_value(document(bytes)?).map_err(|_| ERROR)?;
    if !created.warnings.is_empty() || !id(&created.id) {
        return Err(ERROR);
    }
    Ok(created.id)
}

pub(crate) fn image(bytes: &[u8], reference: &str) -> Result<Outcome> {
    let value = document(bytes)?;
    let raw = value["Id"].as_str().ok_or(ERROR)?;
    let image_id = native_image(raw).ok_or(ERROR)?;
    let digests = match value.get("RepoDigests") {
        Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned).ok_or(ERROR))
            .collect::<Result<Vec<_>>>()?,
        _ => return Err(ERROR),
    };
    if digests.len() > 128 {
        return Err(ERROR);
    }
    for (index, digest) in digests.iter().enumerate() {
        gatehouse_runtime_protocol::v3::validate_image(digest).map_err(|_| ERROR)?;
        if !digest.contains('@') || digests[..index].contains(digest) {
            return Err(ERROR);
        }
    }
    if reference.contains('@') && !digests.iter().any(|digest| digest == reference) {
        return Err(ERROR);
    }
    Ok(Outcome::Image {
        image_id,
        repo_digests: digests,
    })
}

fn state(value: &Value) -> Result<ContainerState> {
    let status = value["Status"].as_str().ok_or(ERROR)?;
    let running = value["Running"].as_bool().ok_or(ERROR)?;
    let paused = value["Paused"].as_bool().ok_or(ERROR)?;
    let restarting = value["Restarting"].as_bool().ok_or(ERROR)?;
    let dead = value["Dead"].as_bool().ok_or(ERROR)?;
    let state = match status {
        "initialized" | "created" => ContainerState::Created,
        "running" => ContainerState::Running,
        "paused" => ContainerState::Paused,
        "stopped" | "exited" => ContainerState::Exited,
        "removing" => ContainerState::Removing,
        "dead" => ContainerState::Dead,
        _ => return Err(ERROR),
    };
    if running != (state == ContainerState::Running)
        || paused != (state == ContainerState::Paused)
        || restarting != (state == ContainerState::Restarting)
        || dead != (state == ContainerState::Dead)
    {
        return Err(ERROR);
    }
    Ok(state)
}

pub(crate) fn inspect(bytes: &[u8], target: &Target, image: Option<&str>) -> Result<Object> {
    let value = document(bytes)?;
    if value["Id"].as_str() != Some(&target.object_id)
        || value["Name"].as_str() != Some(target.name.as_str())
    {
        return Err(ERROR);
    }
    let image_id = value["Image"]
        .as_str()
        .and_then(native_image)
        .ok_or(ERROR)?;
    if image.is_some_and(|expected| expected != image_id) {
        return Err(ERROR);
    }
    let labels = value["Config"]["Labels"]
        .as_object()
        .ok_or(ERROR)?
        .iter()
        .map(|(key, value)| {
            Ok(Entry {
                key: key.clone(),
                value: value.as_str().ok_or(ERROR)?.into(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    for expected in &target.labels {
        if !labels
            .iter()
            .any(|entry| entry.key == expected.key && entry.value == expected.value)
        {
            return Err(ERROR);
        }
    }
    Ok(Object {
        object_id: target.object_id.clone(),
        name: target.name.clone(),
        image_id,
        labels,
        state: state(&value["State"])?,
        ports: ports(&value, target.container_port)?,
    })
}

fn ports(value: &Value, container_port: u16) -> Result<Vec<Port>> {
    let mut bindings = None;
    for path in [
        &value["HostConfig"]["PortBindings"],
        &value["NetworkSettings"]["Ports"],
    ] {
        if let Some(map) = path.as_object() {
            if !map.is_empty() {
                bindings = Some(map);
            }
        }
    }
    let Some(bindings) = bindings else {
        return Ok(vec![]);
    };
    let key = format!("{container_port}/tcp");
    if bindings.len() != 1 || !bindings.contains_key(&key) {
        return Err(ERROR);
    }
    let Some(values) = bindings[&key].as_array() else {
        if bindings[&key].is_null() {
            return Ok(vec![]);
        }
        return Err(ERROR);
    };
    if values.len() != 1 {
        return Err(ERROR);
    }
    let binding = values[0].as_object().ok_or(ERROR)?;
    if binding.get("HostIp").and_then(Value::as_str) != Some("127.0.0.1") {
        return Err(ERROR);
    }
    let raw = binding
        .get("HostPort")
        .and_then(Value::as_str)
        .ok_or(ERROR)?;
    let host_port: u16 = raw.parse().map_err(|_| ERROR)?;
    if host_port == 0 || host_port.to_string() != raw {
        return Err(ERROR);
    }
    Ok(vec![Port {
        container_port,
        protocol: "tcp".into(),
        host_ip: "127.0.0.1".into(),
        host_port,
    }])
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    cause: String,
    message: String,
    response: u16,
}

pub(crate) fn exact_absence(bytes: &[u8], target: &Target) -> Result<()> {
    let failure: Failure = serde_json::from_value(document(bytes)?).map_err(|_| ERROR)?;
    if failure.response != 404
        || failure.cause != "no such container"
        || failure.message
            != format!(
                "no container with name or ID \"{}\" found: no such container",
                target.object_id
            )
    {
        return Err(ERROR);
    }
    Ok(())
}

pub(crate) fn remove_claim(bytes: &[u8], object_id: &str) -> Result<()> {
    if bytes.is_empty() {
        return Err(ERROR);
    }
    let value = any(bytes)?;
    let values = value.as_array().ok_or(ERROR)?;
    if values.len() != 1 {
        return Err(ERROR);
    }
    let item = values[0].as_object().ok_or(ERROR)?;
    if item.len() != 1 || item.get("Id").and_then(Value::as_str) != Some(object_id) {
        return Err(ERROR);
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecCreated {
    #[serde(rename = "Id")]
    id: String,
}

pub(crate) fn exec_created(bytes: &[u8]) -> Result<String> {
    let created: ExecCreated = serde_json::from_value(document(bytes)?).map_err(|_| ERROR)?;
    if !id(&created.id) {
        return Err(ERROR);
    }
    Ok(created.id)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ExecInspect {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "ContainerID")]
    container_id: String,
    can_remove: bool,
    running: bool,
    exit_code: i32,
    open_stdin: bool,
    open_stdout: bool,
    open_stderr: bool,
    process_config: Process,
}

#[derive(Deserialize)]
struct Process {
    entrypoint: String,
    #[serde(deserialize_with = "required_arguments")]
    arguments: Option<Vec<String>>,
    privileged: bool,
    tty: bool,
    user: String,
}

fn required_arguments<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Vec<String>>, D::Error> {
    Option::<Vec<String>>::deserialize(d)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HealthObservation {
    Pending,
    Completed(u8),
}

pub(crate) fn health(
    bytes: &[u8],
    exec: &str,
    container: &str,
    argv: &[String],
) -> Result<HealthObservation> {
    let inspected: ExecInspect = serde_json::from_value(document(bytes)?).map_err(|_| ERROR)?;
    let process = inspected.process_config;
    if inspected.id != exec
        || inspected.container_id != container
        || inspected.open_stdin
        || inspected.open_stdout
        || inspected.open_stderr
        || process.privileged
        || process.tty
        || !process.user.is_empty()
        || process.entrypoint != argv[0]
        || process.arguments.unwrap_or_default() != argv[1..]
    {
        return Err(ERROR);
    }
    if inspected.running {
        if inspected.can_remove {
            return Err(ERROR);
        }
        return Ok(HealthObservation::Pending);
    }
    if !inspected.can_remove {
        return Ok(HealthObservation::Pending);
    }
    if !(0..=255).contains(&inspected.exit_code) {
        return Err(ERROR);
    }
    Ok(HealthObservation::Completed(inspected.exit_code as u8))
}

pub(crate) fn exec_body(argv: &[String]) -> Result<Value> {
    if argv.is_empty() || argv.len() > 128 {
        return Err(ERROR);
    }
    serde_json::to_value(json!({
        "User": "",
        "Privileged": false,
        "Tty": false,
        "AttachStdin": false,
        "AttachStderr": false,
        "AttachStdout": false,
        "DetachKeys": "",
        "Env": [],
        "WorkingDir": "",
        "Cmd": argv,
    }))
    .map_err(|_| ERROR)
}

pub(crate) fn create_body(request: &Request) -> Result<Value> {
    request.validate().map_err(|_| ERROR)?;
    let Operation::Create {
        name,
        image_id,
        labels,
        environment,
        container_port,
        command,
    } = &request.operation
    else {
        return Err(ERROR);
    };
    let labels: Map<String, Value> = labels
        .iter()
        .map(|entry| (entry.key.clone(), Value::String(entry.value.clone())))
        .collect();
    let environment: BTreeMap<String, String> = environment
        .iter()
        .map(|entry| (entry.key.clone(), entry.value.clone()))
        .collect();
    let mut body = json!({
        "name": name,
        "image": image_id.strip_prefix("sha256:").ok_or(ERROR)?,
        "labels": labels,
        "env": environment,
        "env_host": false,
        "httpproxy": false,
        "netns": {"nsmode": "bridge"},
        "portmappings": [{
            "host_ip": "127.0.0.1",
            "container_port": container_port,
            "host_port": 0,
            "range": 1,
            "protocol": "tcp"
        }],
        "publish_image_ports": false,
        "privileged": false,
        "remove": false,
        "removeImage": false,
        "restart_policy": "no"
    });
    if let Some(command) = command {
        body["command"] = json!(command);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gatehouse_runtime_protocol::lifecycle::wire::{Binding, EngineBinding, PROTOCOL};

    fn target() -> Target {
        Target {
            object_id: "a".repeat(64),
            name: "fixture".into(),
            container_port: 8080,
            labels: vec![
                Entry {
                    key: "gatehouse.lifecycle.authority".into(),
                    value: "container-lifecycle/mutate".into(),
                },
                Entry {
                    key: "gatehouse.lifecycle.invocation".into(),
                    value: "1".repeat(32),
                },
                Entry {
                    key: "gatehouse.lifecycle.project".into(),
                    value: "project".into(),
                },
                Entry {
                    key: "gatehouse.lifecycle.resource".into(),
                    value: "service:fixture".into(),
                },
            ],
        }
    }

    fn request() -> Request {
        Request {
            protocol: PROTOCOL.into(),
            binding: Binding {
                installation_sha256: "b".repeat(64),
                executable_sha256: "c".repeat(64),
                config_sha256: "d".repeat(64),
                engine_binding: EngineBinding {
                    engine: "podman".into(),
                    transport: "unix-http".into(),
                    socket_path: "/run/user/1000/podman/podman.sock".into(),
                    socket_uid: 1000,
                    principal_uid: 1000,
                    rootless: true,
                    api_version: "5.7.0".into(),
                    server_version: "5.7.0".into(),
                    daemon_id: "fixture".into(),
                    scope: "/storage".into(),
                },
                project_id: "project".into(),
                resource_id: "service:fixture".into(),
                lease_invocation: "1".repeat(32),
                invocation: "2".repeat(32),
                generation: 2,
                operation_key: String::new(),
            },
            operation: Operation::Create {
                name: "fixture".into(),
                image_id: format!("sha256:{}", "e".repeat(64)),
                labels: target().labels,
                environment: vec![Entry {
                    key: "ALPHA".into(),
                    value: "first".into(),
                }],
                container_port: 8080,
                command: Some(vec!["sleep".into(), "60".into()]),
            },
        }
    }

    #[test]
    fn exact_create_body_and_image_normalization() {
        let mut request = request();
        request.binding.operation_key = request.operation_key().unwrap();
        let body = create_body(&request).unwrap();
        assert_eq!(body["name"], "fixture");
        assert_eq!(body["image"], "e".repeat(64));
        assert_eq!(body["portmappings"][0]["host_port"], 0);
        assert_eq!(body["command"], json!(["sleep", "60"]));
        assert_eq!(
            image(
                &serde_json::to_vec(&json!({
                    "Id": "e".repeat(64),
                    "RepoDigests": [format!("repo@sha256:{}", "f".repeat(64))]
                }))
                .unwrap(),
                "repo:tag"
            )
            .unwrap(),
            Outcome::Image {
                image_id: format!("sha256:{}", "e".repeat(64)),
                repo_digests: vec![format!("repo@sha256:{}", "f".repeat(64))]
            }
        );
    }

    #[test]
    fn inspect_requires_exact_identity_labels_state_and_ports() {
        let target = target();
        let body = serde_json::to_vec(&json!({
            "Id": target.object_id,
            "Name": target.name,
            "Image": "e".repeat(64),
            "Config": {"Labels": {
                "gatehouse.lifecycle.authority":"container-lifecycle/mutate",
                "gatehouse.lifecycle.invocation":"11111111111111111111111111111111",
                "gatehouse.lifecycle.project":"project",
                "gatehouse.lifecycle.resource":"service:fixture"
            }},
            "State": {"Status":"running","Running":true,"Paused":false,"Restarting":false,"Dead":false},
            "HostConfig": {"PortBindings":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"49152"}]}},
            "NetworkSettings": {"Ports":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"49152"}]}}
        }))
        .unwrap();
        let object = inspect(&body, &target, None).unwrap();
        assert_eq!(object.state, ContainerState::Running);
        assert_eq!(object.ports[0].host_port, 49152);
        for (field, replacement) in [
            ("Name", json!("other")),
            ("Image", json!("not-an-image")),
            (
                "State",
                json!({"Status":"running","Running":false,"Paused":false,"Restarting":false,"Dead":false}),
            ),
        ] {
            let mut changed = serde_json::from_slice::<Value>(&body).unwrap();
            changed[field] = replacement;
            assert!(inspect(&serde_json::to_vec(&changed).unwrap(), &target, None).is_err());
        }
    }

    #[test]
    fn absence_remove_exec_and_health_are_exact() {
        let target = target();
        let absent = serde_json::to_vec(&json!({
            "cause":"no such container",
            "message":format!("no container with name or ID \"{}\" found: no such container", target.object_id),
            "response":404
        }))
        .unwrap();
        exact_absence(&absent, &target).unwrap();
        assert!(exact_absence(b"{\"cause\":\"x\"}", &target).is_err());
        remove_claim(
            serde_json::to_vec(&json!([{"Id": target.object_id}]))
                .unwrap()
                .as_slice(),
            &target.object_id,
        )
        .unwrap();
        assert!(remove_claim(b"[]", &target.object_id).is_err());
        let exec = "b".repeat(64);
        assert_eq!(
            exec_created(&serde_json::to_vec(&json!({"Id": exec})).unwrap()).unwrap(),
            exec
        );
        let argv = vec!["/bin/true".to_string()];
        let body = serde_json::to_vec(&json!({
            "ID": exec,
            "ContainerID": target.object_id,
            "CanRemove": true,
            "Running": false,
            "ExitCode": 0,
            "OpenStdin": false,
            "OpenStdout": false,
            "OpenStderr": false,
            "ProcessConfig": {"entrypoint":"/bin/true","arguments":null,"privileged":false,"tty":false,"user":""}
        }))
        .unwrap();
        assert_eq!(
            health(&body, &exec, &target.object_id, &argv).unwrap(),
            HealthObservation::Completed(0)
        );
    }
}
