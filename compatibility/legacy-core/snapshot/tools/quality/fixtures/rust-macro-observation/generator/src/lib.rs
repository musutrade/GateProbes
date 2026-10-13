//! Bounded experiment: one generator shared by a proc macro and its observer.
use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse2, visit::Visit, Ident, ItemFn};

pub struct Observation {
    pub owner: String,
    pub cyclomatic: usize,
    pub generated: TokenStream,
}

/// Only these two known templates are supported. This is not a general expander.
pub fn generate(name: Ident, branching: bool) -> Observation {
    let generated = if branching {
        quote! { pub fn #name(x: i32) -> i32 { if x > 0 { 1 } else { 0 } } }
    } else {
        quote! { pub fn #name(x: i32) -> i32 { x } }
    };
    let function: ItemFn = parse2(generated.clone()).expect("known template must parse");
    struct Decisions(usize);
    impl<'ast> Visit<'ast> for Decisions {
        fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
            self.0 += 1;
            syn::visit::visit_expr_if(self, node);
        }
    }
    let mut decisions = Decisions(0);
    decisions.visit_item_fn(&function);
    Observation {
        owner: name.to_string(),
        cyclomatic: 1 + decisions.0,
        generated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invocation_changes_generated_control_flow() {
        let plain = generate(syn::parse_str("plain").unwrap(), false);
        let branch = generate(syn::parse_str("branch").unwrap(), true);
        assert_eq!((plain.owner.as_str(), plain.cyclomatic), ("plain", 1));
        assert_eq!((branch.owner.as_str(), branch.cyclomatic), ("branch", 2));
        assert_ne!(plain.generated.to_string(), branch.generated.to_string());
    }
}
