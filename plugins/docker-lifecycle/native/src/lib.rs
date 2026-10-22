//! Staged lifecycle adapter construction only. No socket, dispatch or authority.
//! The development protocol must be supplied by an explicit local Cargo patch.
use gatehouse_runtime_protocol::lifecycle::wire::{Operation, Request};
use serde_json::{json, Map, Value};

#[derive(Debug, PartialEq)]
pub struct CreateRequest {
    pub route: String,
    pub body: Value,
}

/// Build the exact reviewed create policy; this does not authorize execution.
/// A future dispatcher must validate protected inputs, daemon observations and
/// durable Core intent before sending it, then inspect the returned exact ID.
pub fn create_request(request: &Request) -> Result<CreateRequest, &'static str> {
    request
        .validate()
        .map_err(|_| "invalid lifecycle request")?;
    let Operation::Create {
        name,
        image_id,
        labels,
        environment,
        container_port,
    } = &request.operation
    else {
        return Err("create operation required");
    };
    let labels: Map<String, Value> = labels
        .iter()
        .map(|entry| (entry.key.clone(), Value::String(entry.value.clone())))
        .collect();
    let env: Vec<String> = environment
        .iter()
        .map(|entry| format!("{}={}", entry.key, entry.value))
        .collect();
    let port = format!("{container_port}/tcp");
    Ok(CreateRequest {
        route: format!(
            "/v{}/containers/create?name={}",
            request.binding.engine_binding.api_version,
            encode(name)
        ),
        body: json!({
            "Image":image_id,"Labels":labels,"Env":env,
            "ExposedPorts":{port.clone():{}},
            "AttachStdin":false,"AttachStdout":false,"AttachStderr":false,
            "OpenStdin":false,"StdinOnce":false,"Tty":false,
            "HostConfig":{
                "AutoRemove":false,"Privileged":false,"PublishAllPorts":false,
                "NetworkMode":"bridge","RestartPolicy":{"Name":"no","MaximumRetryCount":0},
                "PortBindings":{port:[{"HostIp":"127.0.0.1","HostPort":""}]}
            }
        }),
    })
}
fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests;
