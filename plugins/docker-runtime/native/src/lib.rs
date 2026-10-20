//! Unreleased native adapter building blocks; not a Core authority/parser copy.
//! Fake-socket acceptance is required before any release or engine integration.
pub mod input;

pub mod bootstrap;

#[cfg(unix)]
pub mod socket_identity;

#[cfg(target_os = "linux")]
pub mod http;

#[cfg(target_os = "linux")]
mod json;
#[cfg(target_os = "linux")]
pub mod observation;
