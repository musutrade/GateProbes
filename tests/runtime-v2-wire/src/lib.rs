//! Independent acceptance harness for the fixture-only GateProbes v2 entry.
//!
//! This crate is deliberately outside the GateProbes production tree. It links
//! the Rust contract from Core commit 1d066cc directly; it does not copy or
//! reimplement the parser.

pub use gatehouse_runtime_protocol::v2;
pub use gatehouse_runtime_protocol::{Capability, Label, Object, Operation, Outcome};

pub mod fake_docker;
pub mod fixture;
pub mod host;
pub mod memfd;

pub const MAX_MESSAGE_BYTES: usize = gatehouse_runtime_protocol::MAX_MESSAGE_BYTES;
