#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Generated(pub u8);

pub fn production(value: bool) -> u8 {
    if value { 1 } else { 2 }
}

#[cfg(feature = "extra")]
mod inactive;

#[cfg(test)]
mod tests {
    #[test]
    fn not_a_production_function() { panic!("unit-test target is not selected"); }
}
