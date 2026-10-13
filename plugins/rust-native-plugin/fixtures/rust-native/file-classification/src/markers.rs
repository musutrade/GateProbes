macro_rules! marker {
    ($name:ident) => {
        pub struct $name;
        impl crate::declarations::Requirement for $name {
            const CODE: u8 = 7;
        }
    };
}
marker!(Read);
