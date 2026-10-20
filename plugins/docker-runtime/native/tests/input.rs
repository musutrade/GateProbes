//! Independent strictness tests for the native adapter input boundary.

use gateprobes_docker_runtime::input::{
    parse_config, parse_request, validate_inputs, Request, LIMIT,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn binding() -> Value {
    json!({
        "protocol": "gate-runtime/v2",
        "adapter_sha256": "a".repeat(64),
        "adapter_version": "1.0.0",
        "invocation": "inv-1",
        "operation_key": "op-1",
        "generation": "gen-1",
        "adapter_config_sha256": "b".repeat(64),
        "engine": "docker",
        "transport": "unix-http",
        "socket_path": "/run/docker.sock",
        "socket_uid": 1000,
        "principal_uid": 1000,
        "rootless": false,
        "api_version": "1.47",
        "server_version": "27.0.1",
        "daemon_id": "daemon-1",
        "scope": "scope-1"
    })
}

fn config_value() -> Value {
    json!({
        "schema": "gate-runtime-engine-config/v2",
        "engine": "docker",
        "transport": "unix-http",
        "socket_path": "/run/docker.sock",
        "socket_uid": 1000,
        "principal_uid": 1000,
        "rootless": false,
        "api_version": "1.47",
        "server_version": "27.0.1",
        "daemon_id": "daemon-1",
        "scope": "scope-1"
    })
}

fn request_value(operation: Value, config_bytes: &[u8]) -> Value {
    let mut binding = binding();
    binding["adapter_config_sha256"] = json!(digest(config_bytes));
    json!({"binding": binding, "operation": operation})
}

fn request_bytes(operation: Value, config_bytes: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&request_value(operation, config_bytes)).unwrap()
}

fn config_bytes() -> Vec<u8> {
    serde_json::to_vec(&config_value()).unwrap()
}

fn expected_request(operation: Value) -> Request {
    let config = config_bytes();
    parse_request(&request_bytes(operation, &config)).expect("valid expected request")
}

fn rejects_request(value: &Value) {
    let bytes = serde_json::to_vec(value).unwrap();
    assert!(parse_request(&bytes).is_err());
}

#[test]
fn accepts_valid_request_config_and_typed_actual() {
    let config = config_bytes();
    let expected = expected_request(json!("capabilities"));
    assert_eq!(parse_config(&config, &expected).unwrap().scope, "scope-1");

    let actual = serde_json::to_vec_pretty(&expected).unwrap();
    let (_, parsed_config) = validate_inputs(
        &request_bytes(json!("capabilities"), &config),
        &actual,
        &config,
    )
    .unwrap();
    assert_eq!(parsed_config.daemon_id, "daemon-1");
}

#[test]
fn operation_shape_is_strict() {
    let config = config_bytes();
    let object = "c".repeat(64);
    for operation in [
        json!(null),
        json!([]),
        json!(true),
        json!(1),
        json!("remove"),
        json!("inspect"),
        json!({"capabilities": null}),
        json!({"remove": {"object_id": object}}),
        json!({"inspect": {"object_id": object}, "extra": true}),
        json!({"inspect": {"object_id": object, "extra": true}}),
        json!({"inspect": {"object_id": "A".repeat(64)}}),
        json!({"inspect": {"object_id": "c".repeat(63)}}),
    ] {
        let value = request_value(operation, &config);
        rejects_request(&value);
    }

    let valid = request_value(json!({"inspect": {"object_id": object}}), &config);
    assert!(parse_request(&serde_json::to_vec(&valid).unwrap()).is_ok());
    let valid = request_value(json!("capabilities"), &config);
    assert!(parse_request(&serde_json::to_vec(&valid).unwrap()).is_ok());
}

#[test]
fn duplicate_and_unknown_operation_objects_are_rejected() {
    let config = config_bytes();
    let object = "c".repeat(64);
    let binding = serde_json::to_string(&binding()).unwrap();
    let duplicate_map = format!(
        "{{\"binding\":{binding},\"operation\":{{\"inspect\":{{\"object_id\":\"{object}\"}},\"inspect\":{{\"object_id\":\"{object}\"}}}}}}"
    );
    assert!(parse_request(duplicate_map.as_bytes()).is_err());

    let duplicate_object = format!(
        "{{\"binding\":{binding},\"operation\":{{\"inspect\":{{\"object_id\":\"{object}\",\"object_id\":\"{object}\"}}}}}}"
    );
    assert!(parse_request(duplicate_object.as_bytes()).is_err());

    let base = String::from_utf8(
        serde_json::to_vec(&request_value(json!("capabilities"), &config)).unwrap(),
    )
    .unwrap();
    let duplicate_field = format!("{{\"operation\":\"capabilities\",{}", &base[1..]);
    assert!(parse_request(duplicate_field.as_bytes()).is_err());
}

#[test]
fn binding_fields_are_strict() {
    let config = config_bytes();
    let cases = [
        ("protocol", json!("gate-runtime/v1")),
        ("engine", json!("podman")),
        ("transport", json!("tcp")),
        ("adapter_sha256", json!("A".repeat(64))),
        ("adapter_sha256", json!("a".repeat(63))),
        ("adapter_sha256", json!("g".repeat(64))),
        ("adapter_version", json!("")),
        ("invocation", json!("")),
        ("operation_key", json!("")),
        ("generation", json!("")),
        ("server_version", json!("")),
        ("daemon_id", json!("")),
        ("scope", json!("")),
        ("socket_path", json!("relative.sock")),
        ("socket_path", json!("/run/../docker.sock")),
        ("socket_path", json!("/run//docker.sock")),
        ("socket_path", json!("/run/docker.sock/")),
        ("api_version", json!("01.47")),
        ("api_version", json!("1.047")),
        ("api_version", json!("1")),
        ("api_version", json!("1.2.3")),
        ("api_version", json!("65536.0")),
        ("socket_uid", json!(-1)),
        ("socket_uid", json!(4_294_967_296u64)),
        ("socket_uid", json!(1.0)),
        ("socket_uid", json!(true)),
        ("rootless", json!("false")),
        ("extra", json!(true)),
    ];
    for (field, replacement) in cases {
        let mut value = request_value(json!("capabilities"), &config);
        value["binding"][field] = replacement;
        rejects_request(&value);
    }
}

#[test]
fn binding_whitespace_only_is_rejected_like_core() {
    let config = config_bytes();
    let mut value = request_value(json!("capabilities"), &config);
    value["binding"]["scope"] = json!(" ");
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(
        parse_request(&bytes).is_err(),
        "adapter accepted whitespace-only scope; Core v2 rejects nonempty(trim)"
    );
}

#[test]
fn config_fields_digest_and_pins_are_strict() {
    let baseline = config_bytes();
    let expected = expected_request(json!("capabilities"));
    assert!(parse_config(&baseline, &expected).is_ok());

    let mutations = [
        ("schema", json!("other")),
        ("engine", json!("podman")),
        ("transport", json!("tcp")),
        ("socket_path", json!("/run/other.sock")),
        ("socket_uid", json!(1001)),
        ("principal_uid", json!(1001)),
        ("rootless", json!(true)),
        ("api_version", json!("1.48")),
        ("server_version", json!("27.9.9")),
        ("daemon_id", json!("daemon-2")),
        ("scope", json!("scope-2")),
    ];
    for (field, replacement) in mutations {
        let mut value = config_value();
        value[field] = replacement;
        let changed = serde_json::to_vec(&value).unwrap();
        let expected = expected_request(json!("capabilities"));
        let _ = expected;
        let request = request_value(json!("capabilities"), &changed);
        let expected: Request = parse_request(&serde_json::to_vec(&request).unwrap()).unwrap();
        assert!(parse_config(&changed, &expected).is_err(), "{field}");
    }

    let pretty = serde_json::to_vec_pretty(&config_value()).unwrap();
    let expected = expected_request(json!("capabilities"));
    assert!(parse_config(&pretty, &expected).is_err());

    let mut unknown = config_value();
    unknown["extra"] = json!(true);
    let changed = serde_json::to_vec(&unknown).unwrap();
    let request = request_value(json!("capabilities"), &changed);
    let expected: Request = parse_request(&serde_json::to_vec(&request).unwrap()).unwrap();
    assert!(parse_config(&changed, &expected).is_err());
}

#[test]
fn duplicate_config_and_invalid_expected_are_rejected() {
    let config = config_bytes();
    let raw = String::from_utf8(config.clone()).unwrap();
    let duplicate = format!(
        "{{\"schema\":\"gate-runtime-engine-config/v2\",{}",
        &raw[1..]
    );
    let request = request_value(json!("capabilities"), duplicate.as_bytes());
    let expected: Request = parse_request(&serde_json::to_vec(&request).unwrap()).unwrap();
    assert!(parse_config(duplicate.as_bytes(), &expected).is_err());

    let mut invalid = expected_request(json!("capabilities"));
    invalid.binding.adapter_sha256 = "short".into();
    assert!(parse_config(&config, &invalid).is_err());
}

#[test]
fn raw_size_boundary_and_static_errors_hold() {
    let config = config_bytes();
    let mut request = request_bytes(json!("capabilities"), &config);
    request.resize(LIMIT, b' ');
    assert!(parse_request(&request).is_ok());
    request.push(b' ');
    assert!(parse_request(&request).is_err());

    let mut config_padded = config.clone();
    config_padded.resize(LIMIT, b' ');
    let request = request_value(json!("capabilities"), &config_padded);
    let expected: Request = parse_request(&serde_json::to_vec(&request).unwrap()).unwrap();
    assert!(parse_config(&config_padded, &expected).is_ok());
    config_padded.push(b' ');
    assert!(parse_config(&config_padded, &expected).is_err());

    let mut sentinel = config_value();
    sentinel["sentinel"] = json!("SENTINEL-NATIVE-INPUT-DO-NOT-ECHO");
    let changed = serde_json::to_vec(&sentinel).unwrap();
    let request = request_value(json!("capabilities"), &changed);
    let expected: Request = parse_request(&serde_json::to_vec(&request).unwrap()).unwrap();
    let error = parse_config(&changed, &expected).unwrap_err();
    assert!(!error.contains("SENTINEL"));
    assert!(!error.contains("/run/docker.sock"));
}

#[test]
fn actual_mismatch_is_rejected_but_typed_equal_pretty_is_accepted() {
    let config = config_bytes();
    let expected_bytes = request_bytes(json!("capabilities"), &config);
    let expected: Request = parse_request(&expected_bytes).unwrap();
    let pretty = serde_json::to_vec_pretty(&expected).unwrap();
    assert!(validate_inputs(&expected_bytes, &pretty, &config).is_ok());

    let mut changed = expected.clone();
    changed.binding.operation_key = "different".into();
    let actual = serde_json::to_vec(&changed).unwrap();
    assert!(validate_inputs(&expected_bytes, &actual, &config).is_err());
}
