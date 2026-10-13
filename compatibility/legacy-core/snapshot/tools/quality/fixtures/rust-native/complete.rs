#![allow(dead_code)]

macro_rules! generated {
    ($name:ident) => {
        fn $name(value: bool) -> u8 {
            if value { 1 } else { 2 }
        }
    };
}
generated!(first);
generated!(second);

async fn future(value: bool) -> u8 {
    if value { 1 } else { 2 }
}

fn closure(value: bool) -> u8 {
    let callback = || if value { 1 } else { 2 };
    callback()
}

fn generic<T>(value: T) -> T { value }

#[cfg(feature = "extra")]
fn conditional() -> u8 { 1 }

#[cfg(test)]
mod tests {
    #[test]
    fn not_production() { panic!("must not be sampled"); }
}

fn main() {
    let _unpolled = future(true);
    closure(true);
    first(true);
    second(false);
    generic(1u8);
    generic(2u16);
    #[cfg(feature = "extra")]
    conditional();
}
