#[test]
fn project_owned_contract() {
    assert_eq!(native_cargo_fixture::production(true), 1);
    assert_eq!(native_cargo_fixture::Generated(1).clone().0, 1);
}
