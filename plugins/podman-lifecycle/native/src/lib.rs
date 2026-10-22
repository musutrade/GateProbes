//! Unreleased Linux-only read-only transport checkpoint, no plugin entrypoint.
#![cfg(target_os = "linux")]
mod http;
mod socket_identity;
use gatehouse_runtime_protocol::lifecycle_v2::{
    native_image::image_route, native_status::inspect_route, observation::INFO_ROUTE,
    protected_context::ProtectedContext,
};
use std::time::Instant;
pub type Result<T> = std::result::Result<T, &'static str>;
/// Only native info and exact full-ID image/container GET. No CLI, environment,
/// redirects, mutation, retry or implicit endpoint. One deadline spans all calls.
pub fn get(
    context: &ProtectedContext,
    path: &str,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<(u16, Vec<u8>)> {
    if path != INFO_ROUTE {
        let valid = [
            ("/v6.1.4/libpod/images/", true),
            ("/v6.1.4/libpod/containers/", false),
        ]
        .iter()
        .any(|(prefix, image)| {
            path.strip_prefix(prefix)
                .and_then(|s| s.strip_suffix("/json"))
                .is_some_and(|id| {
                    if *image {
                        image_route(id)
                    } else {
                        inspect_route(id)
                    }
                    .is_ok_and(|expected| expected == path)
                })
        });
        if !valid {
            return Err("native read-only route rejected");
        }
    }
    let socket = socket_identity::SocketIdentity::verify(context)?;
    let reply = http::exchange(&socket, path, deadline, cancelled)?;
    Ok((reply.status, reply.body))
}
#[cfg(test)]
mod tests;
