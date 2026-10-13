#[derive(Clone)]
struct Generated(u8);

fn main() {
    let value = Generated(1).clone();
    std::hint::black_box(value.0);
}
