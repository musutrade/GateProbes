//! Native Podman 5.7 lifecycle profile. The read-only capture route remains a
//! separate installation and dispatch path.
mod adapter;
mod http;
mod json;
mod podman;
mod socket_identity;

pub use adapter::execute;

#[cfg(test)]
mod tests;
