#[derive(Debug, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum Literal {
    #[error("{{unit}}")] Unit,
    #[error("named {code} {code:?}")] Named { code: u32 },
    #[error("tuple {0} {1:?}")] Tuple(u32, u32),
}
#[derive(Debug, thiserror::Error)]
#[error("implicit")]
pub struct Implicit { pub source: std::io::Error }
#[derive(Debug, thiserror::Error)]
#[error("explicit")]
pub struct Explicit { #[source] pub inner: std::io::Error, pub code: u32 }
#[derive(Debug, thiserror::Error)]
#[error("converted")]
pub struct Converted(#[from] pub std::io::Error);
#[derive(Debug, thiserror::Error)]
#[error("named conversion")]
pub struct NamedConversion { #[from] pub source: std::io::Error }
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Transparent(#[from] pub std::io::Error);
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct TransparentOnly(pub std::io::Error);
impl Literal {
    pub fn classify(&self, flag: bool) -> usize {
        if flag { 1 } else { 2 }
    }
}
pub fn branch(flag: bool) -> usize {
    if flag { 1 } else { 2 }
}
pub fn closure(flag: bool) -> usize {
    let decide = |x| if x { 3 } else { 4 };
    decide(flag)
}
#[derive(Debug, thiserror::Error)]
pub enum Wrapped {
    #[error(transparent)] Io(#[from] std::io::Error),
    #[error("implicit variant")] Implicit { source: std::fmt::Error },
    #[error("explicit variant")] Explicit { #[source] inner: std::fmt::Error },
    #[error("from variant")] Fmt(#[from] std::fmt::Error),
}
#[derive(Debug, thiserror::Error)]
#[error("named {code} {code:?}")]
pub struct NamedLiteral { pub code: u32 }
#[derive(Debug, thiserror::Error)]
#[error("tuple {0} {1:?}")]
pub struct TupleLiteral(pub u32, pub u32);
#[derive(Debug, thiserror::Error)]
#[error("explicit implicit")]
pub struct ExplicitImplicit { #[source] pub source: std::fmt::Error }
