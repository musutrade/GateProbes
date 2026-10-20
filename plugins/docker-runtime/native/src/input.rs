//! Adapter-side strict wire inputs. Core independently verifies its own contract.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const LIMIT: usize = 65_536;
pub type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub protocol: String,
    pub adapter_sha256: String,
    pub adapter_version: String,
    pub invocation: String,
    pub operation_key: String,
    pub generation: String,
    pub adapter_config_sha256: String,
    pub engine: String,
    pub transport: String,
    pub socket_path: String,
    pub socket_uid: u32,
    pub principal_uid: u32,
    pub rootless: bool,
    pub api_version: String,
    pub server_version: String,
    pub daemon_id: String,
    pub scope: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectId {
    pub object_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Inspection {
    pub inspect: ObjectId,
}

// Unit capability accepts a string only. Remove has no accepted representation.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Operation {
    Capabilities(String),
    Inspect(Inspection),
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub binding: Binding,
    pub operation: Operation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: String,
    pub engine: String,
    pub transport: String,
    pub socket_path: String,
    pub socket_uid: u32,
    pub principal_uid: u32,
    pub rootless: bool,
    pub api_version: String,
    pub server_version: String,
    pub daemon_id: String,
    pub scope: String,
}

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err("runtime input rejected")
    }
}
fn text(s: &str) -> bool {
    !s.trim().is_empty() && !s.chars().any(char::is_control)
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn api(s: &str) -> bool {
    let parts: Vec<_> = s.split('.').collect();
    parts.len() == 2
        && parts
            .iter()
            .all(|p| p.parse::<u16>().is_ok_and(|n| n.to_string() == *p))
}
fn path(s: &str) -> bool {
    text(s) && s.starts_with('/') && s[1..].split('/').all(|p| !matches!(p, "" | "." | ".."))
}

impl Binding {
    fn validate(&self) -> Result<()> {
        require(
            self.protocol == "gate-runtime/v2"
                && self.engine == "docker"
                && self.transport == "unix-http",
        )?;
        require(digest(&self.adapter_sha256) && digest(&self.adapter_config_sha256))?;
        require(
            [
                &self.adapter_version,
                &self.invocation,
                &self.operation_key,
                &self.generation,
                &self.server_version,
                &self.daemon_id,
                &self.scope,
            ]
            .into_iter()
            .all(|s| text(s)),
        )?;
        require(path(&self.socket_path) && api(&self.api_version))
    }
}

pub fn parse_request(bytes: &[u8]) -> Result<Request> {
    require(bytes.len() <= LIMIT)?;
    let request: Request = serde_json::from_slice(bytes).map_err(|_| "runtime input rejected")?;
    request.binding.validate()?;
    match &request.operation {
        Operation::Capabilities(s) => require(s == "capabilities")?,
        Operation::Inspect(i) => require(digest(&i.inspect.object_id))?,
    }
    Ok(request)
}

/// Exact raw bytes are bound; no filesystem or identity observation occurs here.
pub fn parse_config(bytes: &[u8], expected: &Request) -> Result<Config> {
    require(bytes.len() <= LIMIT)?;
    expected.binding.validate()?;
    require(format!("{:x}", Sha256::digest(bytes)) == expected.binding.adapter_config_sha256)?;
    let config: Config = serde_json::from_slice(bytes).map_err(|_| "runtime input rejected")?;
    require(config.schema == "gate-runtime-engine-config/v2")?;
    let b = &expected.binding;
    require(
        config.engine == b.engine
            && config.transport == b.transport
            && config.socket_path == b.socket_path
            && config.socket_uid == b.socket_uid
            && config.principal_uid == b.principal_uid
            && config.rootless == b.rootless
            && config.api_version == b.api_version
            && config.server_version == b.server_version
            && config.daemon_id == b.daemon_id
            && config.scope == b.scope,
    )?;
    Ok(config)
}

pub fn validate_inputs(expected: &[u8], actual: &[u8], config: &[u8]) -> Result<(Request, Config)> {
    let expected = parse_request(expected)?;
    require(parse_request(actual)? == expected)?;
    let config = parse_config(config, &expected)?;
    Ok((expected, config))
}
