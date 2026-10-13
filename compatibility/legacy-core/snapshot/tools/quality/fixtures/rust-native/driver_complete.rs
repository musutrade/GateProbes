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

macro_rules! constant_marker {
    ($name:ident) => { struct $name; impl $name { const CODE: u8 = 7; } };
}
constant_marker!(Marker);

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

#[derive(Clone, Debug, Eq, PartialEq)]
struct Derived(u8);

fn legacy_debt(n: u8) -> u8 {
    if n == 1 { 1 }
    else if n == 2 { 2 }
    else if n == 3 { 3 }
    else if n == 4 { 4 }
    else if n == 5 { 5 }
    else if n == 6 { 6 }
    else { 0 }
}
