//! Unreleased Linux native entry; launching host supplies trust and supervision.
#[cfg(target_os = "linux")]
fn execute() -> Result<Vec<u8>, &'static str> {
    use gateprobes_docker_runtime::{
        bootstrap,
        input::{Operation, LIMIT},
        observation,
        socket_identity::SocketIdentity,
    };
    use serde_json::json;
    let (expected, config) = bootstrap::read()?;
    // Even capability discovery checks the same configured local identity,
    // but never connects. No ambient socket, context or PATH fallback.
    let socket = SocketIdentity::verify(&config)?;
    let result = match &expected.operation {
        Operation::Capabilities(_) => {
            json!({"outcome":{"capabilities":{"supported":["inspect"]}},"observations":null})
        }
        Operation::Inspect(i) => observation::inspect(
            &config,
            &socket,
            &i.inspect.object_id,
            std::time::Duration::from_secs(5),
            &|| false,
        ),
    };
    socket.revalidate()?;
    let response = json!({"binding":expected.binding,"operation":expected.operation,
        "outcome":result["outcome"],"observations":result["observations"]});
    let bytes = serde_json::to_vec(&response).map_err(|_| "runtime output rejected")?;
    if bytes.len() > LIMIT {
        return Err("runtime output rejected");
    }
    Ok(bytes)
}
#[cfg(not(target_os = "linux"))]
fn execute() -> Result<Vec<u8>, &'static str> {
    Err("runtime requires Linux")
}
fn main() {
    use std::io::Write;
    match execute() {
        Ok(bytes) => {
            if std::io::stdout()
                .write_all(&bytes)
                .and_then(|_| std::io::stdout().flush())
                .is_err()
            {
                std::process::exit(1);
            }
        }
        Err(_) => {
            eprintln!("runtime input or execution rejected");
            std::process::exit(1);
        }
    }
}
