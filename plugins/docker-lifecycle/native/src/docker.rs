//! Docker document validation. Documents are facts only, never mutation authority.
use crate::{json::document, Result};
use gatehouse_runtime_protocol::lifecycle::wire::{ContainerState, Entry, Object, Port, Target};
use serde_json::Value;
const ERROR: &str = "lifecycle Docker document rejected";
fn id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn created(bytes: &[u8]) -> Result<String> {
    let v = document(bytes)?;
    if !matches!(v.get("Warnings"), Some(Value::Null))
        && !v
            .get("Warnings")
            .is_some_and(|v| v.as_array().is_some_and(Vec::is_empty))
    {
        return Err(ERROR);
    }
    let object_id = v["Id"].as_str().ok_or(ERROR)?;
    if !id(object_id) {
        return Err(ERROR);
    }
    Ok(object_id.into())
}
pub(crate) fn inspect(bytes: &[u8], target: &Target, image: Option<&str>) -> Result<Object> {
    let v = document(bytes)?;
    if v["Id"].as_str() != Some(&target.object_id)
        || v["Name"].as_str() != Some(&format!("/{}", target.name))
    {
        return Err(ERROR);
    }
    let image_id = v["Image"].as_str().ok_or(ERROR)?;
    if !image_id.strip_prefix("sha256:").is_some_and(id) || image.is_some_and(|p| p != image_id) {
        return Err(ERROR);
    }
    let labels = v["Config"]["Labels"]
        .as_object()
        .ok_or(ERROR)?
        .iter()
        .map(|(k, v)| {
            Ok(Entry {
                key: k.clone(),
                value: v.as_str().ok_or(ERROR)?.into(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if labels != target.labels {
        return Err(ERROR);
    }
    let state = match v["State"]["Status"].as_str().ok_or(ERROR)? {
        "created" => ContainerState::Created,
        "running" => ContainerState::Running,
        "paused" => ContainerState::Paused,
        "restarting" => ContainerState::Restarting,
        "removing" => ContainerState::Removing,
        "exited" => ContainerState::Exited,
        "dead" => ContainerState::Dead,
        _ => return Err(ERROR),
    };
    let ports = ports(&v["NetworkSettings"]["Ports"], target.container_port)?;
    Ok(Object {
        object_id: target.object_id.clone(),
        name: target.name.clone(),
        image_id: image_id.into(),
        labels,
        state,
        ports,
    })
}
fn ports(value: &Value, port: u16) -> Result<Vec<Port>> {
    let entries = value.as_object().ok_or(ERROR)?;
    if entries.is_empty() {
        return Ok(vec![]);
    }
    if entries.len() != 1 {
        return Err(ERROR);
    }
    let bindings = entries.get(&format!("{port}/tcp")).ok_or(ERROR)?;
    if bindings.is_null() {
        return Ok(vec![]);
    }
    let bindings = bindings.as_array().ok_or(ERROR)?;
    if bindings.len() != 1 {
        return Err(ERROR);
    }
    let binding = bindings[0].as_object().ok_or(ERROR)?;
    if binding.len() != 2 || binding.get("HostIp").and_then(Value::as_str) != Some("127.0.0.1") {
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
        container_port: port,
        protocol: "tcp".into(),
        host_ip: "127.0.0.1".into(),
        host_port,
    }])
}
pub(crate) fn exact_absence(bytes: &[u8], target: &Target) -> Result<()> {
    let v = document(bytes)?;
    if v.as_object().ok_or(ERROR)?.len() != 1
        || v["message"].as_str() != Some(&format!("No such container: {}", target.object_id))
    {
        return Err(ERROR);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

pub(crate) fn image(
    bytes: &[u8],
    reference: &str,
) -> Result<gatehouse_runtime_protocol::lifecycle::wire::Outcome> {
    let v = document(bytes)?;
    let image_id = v["Id"].as_str().ok_or(ERROR)?;
    if !image_id.strip_prefix("sha256:").is_some_and(id) {
        return Err(ERROR);
    }
    let values = v["RepoDigests"].as_array().ok_or(ERROR)?;
    if values.len() > 128 {
        return Err(ERROR);
    }
    let mut repo_digests = Vec::new();
    for value in values {
        let digest = value.as_str().ok_or(ERROR)?;
        gatehouse_runtime_protocol::v3::validate_image(digest).map_err(|_| ERROR)?;
        if !digest.contains('@') || repo_digests.iter().any(|d| d == digest) {
            return Err(ERROR);
        }
        repo_digests.push(digest.to_owned());
    }
    if reference.contains('@') && !repo_digests.iter().any(|d| d == reference) {
        return Err(ERROR);
    }
    Ok(
        gatehouse_runtime_protocol::lifecycle::wire::Outcome::Image {
            image_id: image_id.into(),
            repo_digests,
        },
    )
}

pub(crate) fn exec_created(bytes: &[u8]) -> Result<String> {
    let value = document(bytes)?;
    let exec_id = value["Id"].as_str().ok_or(ERROR)?;
    if value.as_object().ok_or(ERROR)?.len() != 1 || !id(exec_id) {
        return Err(ERROR);
    }
    Ok(exec_id.into())
}
pub(crate) fn exec_exit(bytes: &[u8], exec_id: &str, container_id: &str) -> Result<Option<i32>> {
    let value = document(bytes)?;
    if value["ID"].as_str() != Some(exec_id) || value["ContainerID"].as_str() != Some(container_id)
    {
        return Err(ERROR);
    }
    if value["Running"].as_bool().ok_or(ERROR)? {
        return Ok(None);
    }
    let code = value["ExitCode"].as_i64().ok_or(ERROR)?;
    Ok(Some(i32::try_from(code).map_err(|_| ERROR)?))
}
