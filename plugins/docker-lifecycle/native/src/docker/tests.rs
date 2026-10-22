use super::*;
use serde_json::json;
fn fixture() -> (Target, Value) {
    let r = gatehouse_runtime_protocol::lifecycle::wire::parse_request(include_bytes!(
        "../status-request.json"
    ))
    .unwrap();
    let gatehouse_runtime_protocol::lifecycle::wire::Operation::Status { target } = r.operation
    else {
        panic!()
    };
    let labels: serde_json::Map<String, Value> = target
        .labels
        .iter()
        .map(|e| (e.key.clone(), e.value.clone().into()))
        .collect();
    let value = json!({"Id":target.object_id,"Name":format!("/{}",target.name),"Image":format!("sha256:{}","e".repeat(64)),"Config":{"Labels":labels},"State":{"Status":"created"},"NetworkSettings":{"Ports":{"1234/tcp":null}}});
    (target, value)
}
#[test]
fn create_claim_requires_full_id_and_no_warnings() {
    for warnings in [Value::Null, json!([])] {
        assert_eq!(
            created(
                &serde_json::to_vec(&json!({"Id":"a".repeat(64),"Warnings":warnings})).unwrap()
            )
            .unwrap(),
            "a".repeat(64)
        );
    }
    for value in [
        json!({"Id":"a","Warnings":null}),
        json!({"Id":"a".repeat(64)}),
        json!({"Id":"a".repeat(64),"Warnings":["warning"]}),
    ] {
        assert!(created(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}
#[test]
fn exact_inspection_and_single_loopback_port() {
    let (target, mut value) = fixture();
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(
        inspect(&bytes, &target, Some(&format!("sha256:{}", "e".repeat(64))))
            .unwrap()
            .ports
            .is_empty()
    );
    value["NetworkSettings"]["Ports"] =
        json!({"1234/tcp":[{"HostIp":"127.0.0.1","HostPort":"49152"}]});
    let object = inspect(&serde_json::to_vec(&value).unwrap(), &target, None).unwrap();
    assert_eq!(object.ports[0].host_port, 49152);
}
#[test]
fn mismatched_identity_labels_image_and_ports_are_rejected() {
    let (target, value) = fixture();
    for (pointer, replacement) in [
        ("/Id", json!("b".repeat(64))),
        ("/Name", json!("other")),
        ("/Image", json!("latest")),
        ("/Config/Labels", json!({})),
        ("/State/Status", json!("unknown")),
        ("/NetworkSettings/Ports", json!({"5678/tcp":null})),
        ("/NetworkSettings/Ports", json!({"1234/udp":null})),
        (
            "/NetworkSettings/Ports",
            json!({"1234/tcp":[{"HostIp":"0.0.0.0","HostPort":"1234"}]}),
        ),
        (
            "/NetworkSettings/Ports",
            json!({"1234/tcp":[{"HostIp":"127.0.0.1","HostPort":"0"}]}),
        ),
        (
            "/NetworkSettings/Ports",
            json!({"1234/tcp":[],"5678/tcp":null}),
        ),
    ] {
        let mut bad = value.clone();
        *bad.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            inspect(&serde_json::to_vec(&bad).unwrap(), &target, None).is_err(),
            "{pointer}"
        );
    }
    assert!(inspect(
        &serde_json::to_vec(&value).unwrap(),
        &target,
        Some(&format!("sha256:{}", "f".repeat(64)))
    )
    .is_err());
}
#[test]
fn duplicate_json_and_broad_404_are_not_absence() {
    let (target, _) = fixture();
    assert!(created(br#"{"Id":"x","Id":"y","Warnings":null}"#).is_err());
    for value in [
        json!({"message":"not found"}),
        json!({"message":format!("No such container: {}",target.object_id),"extra":true}),
        json!({"message":"No such image: missing"}),
    ] {
        assert!(exact_absence(&serde_json::to_vec(&value).unwrap(), &target).is_err());
    }
    exact_absence(
        &serde_json::to_vec(&json!({"message":format!("No such container: {}",target.object_id)}))
            .unwrap(),
        &target,
    )
    .unwrap();
}
