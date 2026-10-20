//! Pinned before/after observations are adapter assertions, never attestation.
//! No absence inference, mutation, rootless or restart proof.
use crate::{
    http::{self, Route},
    input::{Config, Result},
    json::document,
    socket_identity::SocketIdentity,
};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
const ERROR: &str = "runtime observation unavailable";
fn version(s: &str) -> Result<(u16, u16)> {
    let (a, b) = s.split_once('.').ok_or(ERROR)?;
    let a_num: u16 = a.parse().map_err(|_| ERROR)?;
    let b_num: u16 = b.parse().map_err(|_| ERROR)?;
    if a_num.to_string() != a || b_num.to_string() != b {
        return Err(ERROR);
    }
    Ok((a_num, b_num))
}
fn fetch(
    config: &Config,
    socket: &SocketIdentity,
    route: Route<'_>,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<Value> {
    let reply = http::get(config, socket, route, deadline, cancelled)?;
    if reply.status != 200 {
        return Err(ERROR);
    }
    document(&reply.body)
}
fn identity(
    config: &Config,
    socket: &SocketIdentity,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<Value> {
    let server = fetch(config, socket, Route::Version, deadline, cancelled)?;
    if server["Version"].as_str() != Some(&config.server_version) {
        return Err(ERROR);
    }
    let minimum = version(server["MinAPIVersion"].as_str().ok_or(ERROR)?)?;
    let maximum = version(server["ApiVersion"].as_str().ok_or(ERROR)?)?;
    let selected = version(&config.api_version)?;
    if !(minimum..=maximum).contains(&selected) {
        return Err(ERROR);
    }
    let info = fetch(config, socket, Route::Info, deadline, cancelled)?;
    if info["ID"].as_str() != Some(&config.daemon_id) {
        return Err(ERROR);
    }
    Ok(
        json!({"api_version":config.api_version,"server_version":config.server_version,"daemon_id":config.daemon_id}),
    )
}
fn present(value: Value, id: &str) -> Result<Value> {
    if value["Id"].as_str() != Some(id) {
        return Err(ERROR);
    }
    let labels = value["Config"]["Labels"].as_object().ok_or(ERROR)?;
    if labels.is_empty() {
        return Err(ERROR);
    }
    let mut sorted: Vec<_> = labels.iter().collect();
    sorted.sort_by_key(|(key, _)| *key);
    let mut result = Vec::new();
    for (key, value) in sorted {
        let value = value.as_str().ok_or(ERROR)?;
        if [key.as_str(), value]
            .iter()
            .any(|s| s.trim().is_empty() || s.chars().any(char::is_control))
        {
            return Err(ERROR);
        }
        result.push(json!({"key":key,"value":value}));
    }
    Ok(json!({"object_id":id,"labels":result}))
}
fn observe(
    config: &Config,
    socket: &SocketIdentity,
    id: &str,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<Value> {
    // Reject invalid IDs before identity requests can connect.
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ERROR);
    }
    let before = identity(config, socket, deadline, cancelled)?;
    let object = present(
        fetch(config, socket, Route::Inspect(id), deadline, cancelled)?,
        id,
    )?;
    let after = identity(config, socket, deadline, cancelled)?;
    if before != after || cancelled() || Instant::now() >= deadline {
        return Err(ERROR);
    }
    Ok(
        json!({"outcome":{"present":{"object":object}},"observations":{"observed_before":before,"observed_after":after}}),
    )
}
pub fn inspect(
    config: &Config,
    socket: &SocketIdentity,
    id: &str,
    timeout: Duration,
    cancelled: &impl Fn() -> bool,
) -> Value {
    let unavailable = || json!({"outcome":"unavailable","observations":null});
    if timeout.is_zero() || timeout > Duration::from_secs(30) {
        return unavailable();
    }
    observe(config, socket, id, Instant::now() + timeout, cancelled)
        .unwrap_or_else(|_| unavailable())
}
