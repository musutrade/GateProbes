//! Strict v3 inputs, independently checked by Core. No v2 parsing fallback.
use crate::input::{Binding, Config, Result, LIMIT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub image: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub readiness: Target,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub binding: Binding,
    pub operation: Operation,
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

pub fn validate_image(s: &str) -> Result<()> {
    require(
        !s.is_empty()
            && s.len() <= 512
            && s.is_ascii()
            && !s.starts_with(['-', '+'])
            && !s.bytes().any(|b| {
                b.is_ascii_whitespace() || b.is_ascii_control() || matches!(b, b'?' | b'#')
            })
            && s.split('/').all(|p| !matches!(p, "" | "." | "..")),
    )?;
    if let Some((repo, hash)) = s.split_once('@') {
        require(text(repo) && hash.strip_prefix("sha256:").is_some_and(digest))?;
    }
    Ok(())
}
pub fn parse_request(bytes: &[u8]) -> Result<Request> {
    require(bytes.len() <= LIMIT)?;
    let r: Request = serde_json::from_slice(bytes).map_err(|_| "runtime v3 input rejected")?;
    let b = &r.binding;
    require(
        b.protocol == "gate-runtime/v3"
            && b.adapter_version == "0.2.0"
            && b.engine == "docker"
            && b.transport == "unix-http",
    )?;
    require(
        [
            &b.adapter_sha256,
            &b.adapter_config_sha256,
            &b.operation_key,
            &b.generation,
        ]
        .into_iter()
        .all(|s| digest(s)),
    )?;
    require(
        b.invocation.len() == 32
            && b.invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )?;
    require(
        [&b.server_version, &b.daemon_id, &b.scope]
            .into_iter()
            .all(|s| text(s))
            && path(&b.socket_path)
            && api(&b.api_version),
    )?;
    validate_image(&r.operation.readiness.image)?;
    Ok(r)
}
pub fn validate_inputs(expected: &[u8], actual: &[u8], bytes: &[u8]) -> Result<(Request, Config)> {
    let r = parse_request(expected)?;
    require(parse_request(actual)? == r && bytes.len() <= LIMIT)?;
    let c: Config = serde_json::from_slice(bytes).map_err(|_| "runtime v3 config rejected")?;
    let b = &r.binding;
    require(
        c.schema == "gate-runtime-engine-config/v3"
            && format!("{:x}", Sha256::digest(bytes)) == b.adapter_config_sha256
            && c.engine == b.engine
            && c.transport == b.transport
            && c.socket_path == b.socket_path
            && c.socket_uid == b.socket_uid
            && c.principal_uid == b.principal_uid
            && c.rootless == b.rootless
            && c.api_version == b.api_version
            && c.server_version == b.server_version
            && c.daemon_id == b.daemon_id
            && c.scope == b.scope,
    )?;
    Ok((r, c))
}
