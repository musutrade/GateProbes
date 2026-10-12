//! Source branch grammar adapted from rust-measure/native.rs; macro-generated
//! polling control flow is intentionally excluded from source complexity.
use syn::{Expr, Token, parse::ParseStream};

#[derive(Default)]
pub struct Parsed {
    pub expressions: Vec<Expr>,
    pub decisions: usize,
    pub guards: usize,
}

pub fn parse(input: ParseStream) -> syn::Result<Parsed> {
    let mut parsed = Parsed::default();
    let mut branches = 0usize;
    let fork = input.fork();
    if fork.parse::<syn::Ident>().is_ok_and(|id| id == "biased") && fork.peek(Token![;]) {
        input.parse::<syn::Ident>()?;
        input.parse::<Token![;]>()?;
    }
    while !input.is_empty() {
        if input.peek(Token![else]) {
            input.parse::<Token![else]>()?;
            input.parse::<Token![=>]>()?;
            parsed.expressions.push(input.parse()?);
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
            if !input.is_empty() || branches == 0 {
                return Err(input.error("else must follow futures and be last"));
            }
            branches += 1;
            break;
        }
        let pattern = syn::Pat::parse_multi_with_leading_vert(input)?;
        // Refutable patterns may disable a branch. Only syntactically proven
        // irrefutable forms avoid this extra source decision.
        let irrefutable = match &pattern {
            syn::Pat::Wild(_) => true,
            syn::Pat::Ident(p) => p.subpat.is_none(),
            syn::Pat::Tuple(p) => p.elems.is_empty(),
            _ => false,
        };
        parsed.decisions += usize::from(!irrefutable);
        input.parse::<Token![=]>()?;
        parsed.expressions.push(input.parse()?);
        if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            input.parse::<Token![if]>()?;
            parsed.expressions.push(input.parse()?);
            parsed.guards += 1;
        }
        input.parse::<Token![=>]>()?;
        let handler: Expr = if input.peek(syn::token::Brace) {
            Expr::Block(syn::ExprBlock {
                attrs: Vec::new(),
                label: None,
                block: input.parse()?,
            })
        } else {
            input.parse()?
        };
        let block = matches!(handler, Expr::Block(_));
        parsed.expressions.push(handler);
        branches += 1;
        if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
        } else if !input.is_empty() && !block {
            return Err(input.error("expected comma after handler"));
        }
    }
    if branches == 0 {
        return Err(input.error("expected future branch"));
    }
    parsed.decisions += branches.saturating_sub(1);
    Ok(parsed)
}
