//! Read-only image lookup; absence here is not container-removal reconciliation.
use crate::{
    bootstrap,
    http::{self, Route},
    input::{Config, Result, LIMIT},
    input_v3,
    json::document,
    observation::identity,
    socket_identity::SocketIdentity,
};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
const ERROR: &str = "runtime readiness unavailable";
fn image_id(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn observe(
    c: &Config,
    socket: &SocketIdentity,
    image: &str,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<Value> {
    input_v3::validate_image(image)?;
    let before = identity(c, socket, deadline, cancelled)?;
    let reply = http::get(c, socket, Route::Image(image), deadline, cancelled)?;
    let readiness = match reply.status {
        404 => {
            let value = document(&reply.body)?;
            if !value["message"]
                .as_str()
                .is_some_and(|s| !s.trim().is_empty() && !s.chars().any(char::is_control))
            {
                return Err(ERROR);
            }
            json!({"image_present":false})
        }
        200 => {
            let value = document(&reply.body)?;
            let id = value["Id"].as_str().filter(|s| image_id(s)).ok_or(ERROR)?;
            if image.contains('@')
                && !value["RepoDigests"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(image)))
            {
                return Err(ERROR);
            }
            json!({"image_present":true,"image_id":id})
        }
        _ => return Err(ERROR),
    };
    let after = identity(c, socket, deadline, cancelled)?;
    socket.revalidate()?;
    if before != after || cancelled() || Instant::now() >= deadline {
        return Err(ERROR);
    }
    Ok(
        json!({"outcome":{"readiness":readiness},"observations":{"observed_before":before,"observed_after":after}}),
    )
}
pub fn check(
    c: &Config,
    socket: &SocketIdentity,
    image: &str,
    timeout: Duration,
    cancelled: &impl Fn() -> bool,
) -> Value {
    if timeout.is_zero() || timeout > Duration::from_secs(30) {
        return json!({"outcome":"unavailable","observations":null});
    }
    observe(c, socket, image, Instant::now() + timeout, cancelled)
        .unwrap_or_else(|_| json!({"outcome":"unavailable","observations":null}))
}
pub fn execute() -> Result<Vec<u8>> {
    let (expected, actual, config) = bootstrap::read_bytes()?;
    let (request, config) = input_v3::validate_inputs(&expected, &actual, &config)?;
    let socket = SocketIdentity::verify(&config)?;
    let result = check(
        &config,
        &socket,
        &request.operation.readiness.image,
        Duration::from_secs(30),
        &|| false,
    );
    socket.revalidate()?;
    let bytes = serde_json::to_vec(&json!({"binding":request.binding,"operation":request.operation,"outcome":result["outcome"],"observations":result["observations"]})).map_err(|_| ERROR)?;
    if bytes.len() > LIMIT {
        return Err(ERROR);
    }
    Ok(bytes)
}
