#[cfg_attr(test, derive(Debug))]
pub struct Config {
    pub value: u8,
}

pub fn classify(value: u8) -> u8 {
    if value == 0 { 0 } else { 1 }
}
