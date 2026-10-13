macro_rules! runtime {
    ($name:ident) => {
        pub fn $name() -> u8 {
            4
        }
    };
}
runtime!(called);
runtime!(never);
