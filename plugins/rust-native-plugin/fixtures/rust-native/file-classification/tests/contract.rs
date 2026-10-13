use native_file_classification::{forward, generated, local};
#[test]
fn contract() {
    assert_eq!(forward::called(), 3);
    assert_eq!(generated::called(), 4);
    local::KEY.sync_scope(5, || assert_eq!(local::KEY.get(), 5));
    #[cfg(feature = "extra")]
    assert_eq!(native_file_classification::conditional::selected(), 6);
}
