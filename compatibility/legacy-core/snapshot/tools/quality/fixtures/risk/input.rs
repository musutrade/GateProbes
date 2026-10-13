pub fn generic<T: PartialEq>(x: T, y: T) -> bool {
    let compare = || {
        if x == y { true } else { false }
    };
    compare()
}
fn unhit() -> i32 { 0 }
fn main() {
    assert!(generic(1, 1));
    assert!(!generic(1u8, 2u8));
}
