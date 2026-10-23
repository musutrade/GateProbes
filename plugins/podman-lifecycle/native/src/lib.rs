//! Unreleased Linux-only read-only transport checkpoint, no plugin entrypoint.
#![cfg(target_os = "linux")]
mod http;
mod socket_identity;
#[cfg(test)]
use gatehouse_runtime_protocol::lifecycle_v2::{
    native_image::image_route, observation::INFO_ROUTE,
};
use gatehouse_runtime_protocol::lifecycle_v2::{
    native_image::image_route_for,
    native_status::inspect_route,
    observation::{info_route, API},
    protected_context::ProtectedContext,
};
use std::time::{Duration, Instant};
pub type Result<T> = std::result::Result<T, &'static str>;
/// Only native info and exact full-ID image/container GET. No CLI, environment,
/// redirects, mutation, retry or implicit endpoint. One deadline spans all calls.
pub fn get(
    context: &ProtectedContext,
    path: &str,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<(u16, Vec<u8>)> {
    let api = context.read_only_api()?;
    let info = info_route(&api)?;
    let mut valid = path == info.as_str();
    if !valid && api == API {
        valid = path
            .strip_prefix("/v6.1.4/libpod/containers/")
            .and_then(|s| s.strip_suffix("/json"))
            .is_some_and(|id| inspect_route(id).is_ok_and(|expected| expected == path));
    }
    if !valid {
        valid = path
            .strip_prefix(&format!("/v{api}/libpod/images/"))
            .and_then(|s| s.strip_suffix("/json"))
            .is_some_and(|id| image_route_for(&api, id).is_ok_and(|expected| expected == path));
    }
    if !valid {
        return Err("native read-only route rejected");
    }
    let socket = socket_identity::SocketIdentity::verify(context)?;
    let reply = http::exchange(&socket, path, deadline, cancelled)?;
    Ok((reply.status, reply.body))
}
/// Fixed transport composition. Returns read-only evidence, never installation,
/// freshness, lease or mutation authority. One deadline covers all three GETs.
pub fn capture_plan(
    context: &ProtectedContext,
    image_id: &str,
    identity: &gatehouse_runtime_protocol::lifecycle_v2::profile::SlotIdentity,
    inputs: gatehouse_runtime_protocol::lifecycle_v2::plan_record::PlanInputs,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<gatehouse_runtime_protocol::lifecycle_v2::plan_record::PlanRecord> {
    use gatehouse_runtime_protocol::lifecycle_v2::plan_record::PlanRecord;
    let api = context.read_only_api()?;
    image_route_for(&api, image_id)?;
    if deadline.saturating_duration_since(Instant::now()) > Duration::from_secs(30) {
        return Err("capture deadline exceeds maximum");
    }
    inputs.validate()?;
    identity.validate()?;
    if identity.config_sha256 != context.config_sha256()? {
        return Err("capture slot config mismatch");
    }
    if cancelled() || Instant::now() >= deadline {
        return Err("capture cancelled or expired");
    }
    let captured =
        context.capture_image_for_plan(image_id, |path| get(context, path, deadline, cancelled))?;
    let record = PlanRecord::capture(context, &captured, identity, inputs)?;
    finish_capture(record, context, deadline, cancelled)
}
fn finish_capture(
    record: gatehouse_runtime_protocol::lifecycle_v2::plan_record::PlanRecord,
    context: &ProtectedContext,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<gatehouse_runtime_protocol::lifecycle_v2::plan_record::PlanRecord> {
    context.revalidate()?;
    if cancelled() || Instant::now() >= deadline {
        return Err("capture cancelled or expired");
    }
    Ok(record)
}
#[cfg(test)]
mod tests;
