use thiserror_subset::*;
use std::error::Error;
#[test]
fn all_metadata_and_authored_branches() {
    assert_eq!(Literal::Unit.to_string(), "{unit}");
    assert_eq!(Literal::Named { code: 2 }.to_string(), "named 2 2");
    assert_eq!(Literal::Tuple(1, 2).to_string(), "tuple 1 2");
    assert!(Implicit { source: std::io::Error::other("io") }.source().is_some());
    assert!(Explicit { inner: std::io::Error::other("io"), code: 3 }.source().is_some());
    let converted: Converted = std::io::Error::other("io").into();
    assert!(converted.source().is_some());
    let named: NamedConversion = std::io::Error::other("io").into();
    assert!(named.source().is_some());
    let transparent: Transparent = std::io::Error::other("io").into();
    assert_eq!(transparent.to_string(), "io");
    assert_eq!(TransparentOnly(std::io::Error::other("io")).to_string(), "io");
    let io: Wrapped = std::io::Error::other("io").into();
    assert_eq!(io.to_string(), "io");
    let fmt: Wrapped = std::fmt::Error.into();
    assert!(fmt.source().is_some());
    assert!(Wrapped::Implicit { source: std::fmt::Error }.source().is_some());
    assert!(Wrapped::Explicit { inner: std::fmt::Error }.source().is_some());
    assert!(ExplicitImplicit { source: std::fmt::Error }.source().is_some());
    assert_eq!(NamedLiteral { code: 2 }.to_string(), "named 2 2");
    assert_eq!(TupleLiteral(1, 2).to_string(), "tuple 1 2");
    for (flag, expected, enclosed) in [(true,1,3),(false,2,4)] {
        assert_eq!(Literal::Unit.classify(flag), expected);
        assert_eq!(branch(flag), expected);
        assert_eq!(closure(flag), enclosed);
    }
}
