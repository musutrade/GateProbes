fn main() {
    let project = |value: &i32| *value;
    std::hint::black_box(project(&std::hint::black_box(1)));
}
