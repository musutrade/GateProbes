use super::*;
use gatehouse_runtime_protocol::lifecycle::wire::{self, Entry};
fn request() -> Request {
    let mut request = wire::parse_request(include_bytes!("status-request.json")).unwrap();
    let Operation::Status { target } = request.operation else {
        panic!()
    };
    request.operation = Operation::Create {
        name: target.name,
        image_id: format!("sha256:{}", "e".repeat(64)),
        labels: target.labels,
        environment: vec![Entry {
            key: "A".into(),
            value: "literal=$HOME;=value".into(),
        }],
        container_port: target.container_port,
    };
    request.binding.operation_key = request.operation_key().unwrap();
    request
}
#[test]
fn exact_create_policy_preserves_only_requested_inputs() {
    let r = request();
    let built = create_request(&r).unwrap();
    assert_eq!(built.route, "/v1.47/containers/create?name=test-container");
    assert_eq!(
        built.body,
        json!({"Image":format!("sha256:{}","e".repeat(64)),"Labels":{
        "gatehouse.lifecycle.authority":"container-lifecycle/mutate","gatehouse.lifecycle.invocation":"11111111111111111111111111111111","gatehouse.lifecycle.project":"project","gatehouse.lifecycle.resource":"resource"
    },"Env":["A=literal=$HOME;=value"],"ExposedPorts":{"1234/tcp":{}},
    "AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"OpenStdin":false,"StdinOnce":false,"Tty":false,
    "HostConfig":{"AutoRemove":false,"Privileged":false,"PublishAllPorts":false,"NetworkMode":"bridge","RestartPolicy":{"Name":"no","MaximumRetryCount":0},"PortBindings":{"1234/tcp":[{"HostIp":"127.0.0.1","HostPort":""}]}}})
    );
}
#[test]
fn wrong_operation_and_stale_binding_fail() {
    let status = wire::parse_request(include_bytes!("status-request.json")).unwrap();
    assert!(create_request(&status).is_err());
    let mut r = request();
    if let Operation::Create { container_port, .. } = &mut r.operation {
        *container_port = 80;
    }
    assert!(create_request(&r).is_err());
}
#[test]
fn zero_port_and_duplicate_labels_fail_before_build() {
    let mut r = request();
    if let Operation::Create { container_port, .. } = &mut r.operation {
        *container_port = 0;
    }
    assert!(create_request(&r).is_err());
    let mut r = request();
    if let Operation::Create { labels, .. } = &mut r.operation {
        labels.push(labels[0].clone());
    }
    assert!(create_request(&r).is_err());
}
#[test]
fn percent_encoding_has_no_query_or_path_escape() {
    assert_eq!(
        encode("name/a?x=1&b=% #"),
        "name%2Fa%3Fx%3D1%26b%3D%25%20%23"
    );
}
