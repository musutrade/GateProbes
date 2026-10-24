use audit_fixture::{classify, Config};

#[test]
fn covers_both_paths() {
    assert_eq!(classify(0), 0);
    assert_eq!(classify(1), 1);
    let _ = Config { value: 1 };
}
