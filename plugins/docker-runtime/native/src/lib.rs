//! Unreleased native adapter building blocks; not a Core authority/parser copy.
//! No bootstrap or engine implementation is exposed by this initial module.
pub mod input;

pub mod bootstrap;

#[cfg(unix)]
pub mod socket_identity;

#[cfg(target_os = "linux")]
pub mod http;
