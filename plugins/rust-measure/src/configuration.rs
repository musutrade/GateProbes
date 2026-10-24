//! Production-only filtering for the explicitly supported target predicates.
//! Source spans survive filtering; excluded ranges also leave line denominators.
use proc_macro2::Span;
use serde_json::{json, Value};
use syn::{
    spanned::Spanned,
    visit_mut::{self, VisitMut},
    Attribute, Expr, Item, Meta, Stmt,
};

pub struct Configuration {
    pub values: Vec<String>,
    pub excluded: Vec<Value>,
    pub errors: Vec<String>,
}

fn item_attributes(item: &mut Item) -> Option<&mut Vec<Attribute>> {
    match item {
        Item::Const(n) => Some(&mut n.attrs),
        Item::Enum(n) => Some(&mut n.attrs),
        Item::ExternCrate(n) => Some(&mut n.attrs),
        Item::Fn(n) => Some(&mut n.attrs),
        Item::ForeignMod(n) => Some(&mut n.attrs),
        Item::Impl(n) => Some(&mut n.attrs),
        Item::Macro(n) => Some(&mut n.attrs),
        Item::Mod(n) => Some(&mut n.attrs),
        Item::Static(n) => Some(&mut n.attrs),
        Item::Struct(n) => Some(&mut n.attrs),
        Item::Trait(n) => Some(&mut n.attrs),
        Item::TraitAlias(n) => Some(&mut n.attrs),
        Item::Type(n) => Some(&mut n.attrs),
        Item::Union(n) => Some(&mut n.attrs),
        Item::Use(n) => Some(&mut n.attrs),
        _ => None,
    }
}

fn expression_attributes(expression: &mut Expr) -> Option<&mut Vec<Attribute>> {
    // Other attributed expression positions fail explicitly in visit_attribute_mut.
    match expression {
        Expr::Block(n) => Some(&mut n.attrs),
        Expr::If(n) => Some(&mut n.attrs),
        Expr::Closure(n) => Some(&mut n.attrs),
        Expr::Async(n) => Some(&mut n.attrs),
        Expr::Try(n) => Some(&mut n.attrs),
        Expr::Unsafe(n) => Some(&mut n.attrs),
        _ => None,
    }
}

impl Configuration {
    fn atom(&self, meta: &Meta) -> syn::Result<bool> {
        match meta {
            Meta::Path(path) if path.is_ident("test") => Ok(false),
            Meta::Path(path) if path.is_ident("unix") || path.is_ident("windows") => {
                Ok(self.values.contains(&path.get_ident().unwrap().to_string()))
            }
            Meta::NameValue(value) if value.path.is_ident("target_os") => {
                if let Expr::Lit(expression) = &value.value {
                    if let syn::Lit::Str(name) = &expression.lit {
                        let name = name.value();
                        if matches!(name.as_str(), "linux" | "macos" | "windows") {
                            return Ok(self.values.contains(&format!("target_os={name:?}")));
                        }
                    }
                }
                Err(syn::Error::new_spanned(meta, "unsupported cfg predicate"))
            }
            _ => Err(syn::Error::new_spanned(meta, "unsupported cfg predicate")),
        }
    }

    fn predicate(&self, meta: &Meta) -> syn::Result<bool> {
        match meta {
            Meta::List(list) if list.path.is_ident("not") => {
                let inner: Meta = syn::parse2(list.tokens.clone())?;
                Ok(!self.predicate(&inner)?)
            }
            Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => {
                let predicates = list.parse_args_with(
                    syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
                )?;
                let all = list.path.is_ident("all");
                // Evaluate every operand before reducing: an unsupported
                // operand is an error even when all(false, ...) or
                // any(true, ...) would short-circuit.
                let mut values = Vec::with_capacity(predicates.len());
                for predicate in &predicates {
                    values.push(self.predicate(predicate)?);
                }
                Ok(if all {
                    values.into_iter().all(|value| value)
                } else {
                    values.into_iter().any(|value| value)
                })
            }
            _ => self.atom(meta),
        }
    }

    fn test_derive(attribute: &Attribute) -> bool {
        let Ok(arguments) = attribute
            .parse_args_with(syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated)
        else {
            return false;
        };
        let mut arguments = arguments.iter();
        if !matches!(arguments.next(), Some(Meta::Path(path)) if path.is_ident("test")) {
            return false;
        }
        let mut derive = false;
        for argument in arguments {
            match argument {
                Meta::List(list) if list.path.is_ident("derive") => derive = true,
                _ => return false,
            }
        }
        derive
    }

    fn active(&mut self, attributes: &mut Vec<Attribute>, location: Span) -> bool {
        self.active_with_cfg_attr(attributes, location, false)
    }

    fn active_with_cfg_attr(
        &mut self,
        attributes: &mut Vec<Attribute>,
        location: Span,
        allow_test_derive: bool,
    ) -> bool {
        // Test code is outside this production series, regardless of test build cfg.
        let mut active = !attributes.iter().any(|a| a.path().is_ident("test"));
        for attr in attributes.iter() {
            if attr.path().is_ident("cfg_attr") {
                if !allow_test_derive || !Self::test_derive(attr) {
                    self.errors
                        .push(format!("unsupported cfg_attr at {:?}", attr.span().start()));
                }
            } else if attr.path().is_ident("cfg") {
                match attr
                    .parse_args::<Meta>()
                    .and_then(|meta| self.predicate(&meta))
                {
                    Ok(value) => active &= value,
                    Err(error) => self
                        .errors
                        .push(format!("{error} at {:?}", attr.span().start())),
                }
            }
        }
        if !active {
            self.excluded.push(json!([
                location.start().line,
                location.start().column + 1,
                location.end().line,
                location.end().column + 1
            ]));
        }
        attributes.retain(|attr| {
            !attr.path().is_ident("cfg")
                && !(allow_test_derive
                    && attr.path().is_ident("cfg_attr")
                    && Self::test_derive(attr))
        });
        active
    }

    #[cfg(test)]
    pub fn apply(&mut self, file: &mut syn::File) {
        self.items(&mut file.items);
        syn::visit_mut::visit_file_mut(self, file);
    }

    fn items(&mut self, items: &mut Vec<Item>) {
        items.retain_mut(|item| {
            let location = item.span();
            let allow_test_derive =
                matches!(item, Item::Struct(_) | Item::Enum(_) | Item::Union(_));
            match item_attributes(item) {
                Some(attrs) => self.active_with_cfg_attr(attrs, location, allow_test_derive),
                None => {
                    self.errors
                        .push("unsupported conditional item position".into());
                    false
                }
            }
        });
    }
}

impl VisitMut for Configuration {
    fn visit_file_mut(&mut self, node: &mut syn::File) {
        let location = node.span();
        if !self.active(&mut node.attrs, location) {
            node.items.clear();
            return;
        }
        self.items(&mut node.items);
        visit_mut::visit_file_mut(self, node);
    }
    fn visit_item_mod_mut(&mut self, node: &mut syn::ItemMod) {
        if let Some((_, items)) = &mut node.content {
            self.items(items);
        }
        visit_mut::visit_item_mod_mut(self, node);
    }
    fn visit_item_impl_mut(&mut self, node: &mut syn::ItemImpl) {
        node.items.retain_mut(|item| {
            let location = item.span();
            let attrs = match item {
                syn::ImplItem::Const(n) => &mut n.attrs,
                syn::ImplItem::Fn(n) => &mut n.attrs,
                syn::ImplItem::Type(n) => &mut n.attrs,
                syn::ImplItem::Macro(n) => &mut n.attrs,
                _ => {
                    self.errors.push("unsupported impl item".into());
                    return false;
                }
            };
            self.active(attrs, location)
        });
        visit_mut::visit_item_impl_mut(self, node);
    }
    fn visit_item_trait_mut(&mut self, node: &mut syn::ItemTrait) {
        node.items.retain_mut(|item| {
            let location = item.span();
            let attrs = match item {
                syn::TraitItem::Const(n) => &mut n.attrs,
                syn::TraitItem::Fn(n) => &mut n.attrs,
                syn::TraitItem::Type(n) => &mut n.attrs,
                syn::TraitItem::Macro(n) => &mut n.attrs,
                _ => {
                    self.errors.push("unsupported trait item".into());
                    return false;
                }
            };
            self.active(attrs, location)
        });
        visit_mut::visit_item_trait_mut(self, node);
    }
    fn visit_block_mut(&mut self, node: &mut syn::Block) {
        node.stmts.retain_mut(|stmt| {
            let location = stmt.span();
            let attrs = match stmt {
                Stmt::Local(n) => Some(&mut n.attrs),
                Stmt::Item(n) => item_attributes(n),
                Stmt::Expr(n, _) => expression_attributes(n),
                Stmt::Macro(n) => Some(&mut n.attrs),
            };
            attrs.is_none_or(|attrs| self.active(attrs, location))
        });
        visit_mut::visit_block_mut(self, node);
    }
    fn visit_expr_mut(&mut self, node: &mut Expr) {
        // A complete statement's attributes were already consumed by
        // visit_block_mut. Residual Try attributes belong to a nested position
        // that cannot be removed as a statement. Reject before active() can
        // strip even a true predicate and accidentally admit that position.
        if let Expr::Try(expression) = node {
            if expression
                .attrs
                .iter()
                .any(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
            {
                self.errors.push(
                    "unsupported cfg try expression position; only removable statements are supported"
                        .into(),
                );
                return;
            }
        }
        let location = node.span();
        if let Some(attrs) = expression_attributes(node) {
            if !self.active(attrs, location) {
                self.errors.push(
                    "unsupported cfg expression position; only removable statements are supported"
                        .into(),
                );
                return;
            }
        }
        visit_mut::visit_expr_mut(self, node);
    }
    fn visit_expr_match_mut(&mut self, node: &mut syn::ExprMatch) {
        node.arms.retain_mut(|arm| {
            // The original whole-arm span includes attributes, guard, body and
            // comma. Filtering before Inventory removes its CC and all owners;
            // byte intervals preserve any active neighbor on the same line.
            let location = arm.span();
            self.active(&mut arm.attrs, location)
        });
        visit_mut::visit_expr_match_mut(self, node);
    }
    fn visit_fields_named_mut(&mut self, node: &mut syn::FieldsNamed) {
        node.named = std::mem::take(&mut node.named)
            .into_iter()
            .filter_map(|mut field| {
                let location = field.span();
                self.active(&mut field.attrs, location).then_some(field)
            })
            .collect();
        visit_mut::visit_fields_named_mut(self, node);
    }
    fn visit_fields_unnamed_mut(&mut self, node: &mut syn::FieldsUnnamed) {
        node.unnamed = std::mem::take(&mut node.unnamed)
            .into_iter()
            .filter_map(|mut field| {
                let location = field.span();
                self.active(&mut field.attrs, location).then_some(field)
            })
            .collect();
        visit_mut::visit_fields_unnamed_mut(self, node);
    }
    fn visit_expr_struct_mut(&mut self, node: &mut syn::ExprStruct) {
        node.fields = std::mem::take(&mut node.fields)
            .into_iter()
            .filter_map(|mut field| {
                let location = field.span();
                self.active(&mut field.attrs, location).then_some(field)
            })
            .collect();
        visit_mut::visit_expr_struct_mut(self, node);
    }
    fn visit_attribute_mut(&mut self, attr: &mut Attribute) {
        if attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr") {
            self.errors.push(format!(
                "unsupported conditional attribute position at {:?}",
                attr.span().start()
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    fn configuration() -> Configuration {
        Configuration {
            values: vec!["unix".into(), "target_os=\"linux\"".into()],
            excluded: vec![],
            errors: vec![],
        }
    }

    fn predicate(meta: Meta) -> syn::Result<bool> {
        configuration().predicate(&meta)
    }

    #[test]
    fn recursive_predicates_use_recorded_target_configuration() {
        assert!(predicate(parse_quote!(any(test, unix))).unwrap());
        assert!(!predicate(parse_quote!(any(test, windows))).unwrap());
        assert!(predicate(parse_quote!(all(unix, not(test)))).unwrap());
        assert!(!predicate(parse_quote!(all(test, target_os = "linux"))).unwrap());
        assert!(!predicate(parse_quote!(not(any(unix, windows)))).unwrap());
        assert!(predicate(parse_quote!(not(windows))).unwrap());
        assert!(predicate(parse_quote!(all())).unwrap());
        assert!(!predicate(parse_quote!(any())).unwrap());
        assert!(predicate(parse_quote!(all(unix,))).unwrap());
    }

    #[test]
    fn every_operand_is_validated_before_reduction() {
        assert!(predicate(parse_quote!(all(unix, feature = "x"))).is_err());
        assert!(predicate(parse_quote!(any(unix, feature = "x"))).is_err());
        assert!(predicate(parse_quote!(all(windows, feature = "x"))).is_err());
        assert!(predicate(parse_quote!(any(unix, feature = "x",))).is_err());
    }

    #[test]
    fn cfg_attr_test_derive_is_removed_from_production_view() {
        let mut configuration = configuration();
        let mut attributes: Vec<Attribute> = vec![parse_quote!(
            #[cfg_attr(test, derive(schemars::JsonSchema), derive(Debug))]
        )];
        assert!(configuration.active_with_cfg_attr(&mut attributes, Span::call_site(), true));
        assert!(attributes.is_empty());
        assert!(configuration.errors.is_empty());
    }

    #[test]
    fn multiple_cfg_attributes_are_all_validated() {
        let mut configuration = configuration();
        let mut attributes: Vec<Attribute> = vec![
            parse_quote!(#[cfg(unix)]),
            parse_quote!(#[cfg(feature = "x")]),
        ];
        configuration.active_with_cfg_attr(&mut attributes, Span::call_site(), false);
        assert!(!configuration.errors.is_empty());
    }

    #[test]
    fn existing_field_and_impl_conditional_support_is_preserved() {
        let mut configuration = configuration();
        let mut file = syn::parse_file(
            "struct A { #[cfg(test)] hidden: u8, visible: u8 } impl A { #[cfg(test)] fn hidden(&self) {} #[cfg(not(test))] fn visible(&self) {} }",
        )
        .unwrap();
        configuration.apply(&mut file);
        assert!(
            configuration.errors.is_empty(),
            "{:?}",
            configuration.errors
        );
        let fields = match &file.items[0] {
            Item::Struct(item) => &item.fields,
            _ => panic!("expected struct"),
        };
        assert_eq!(fields.len(), 1);
        let methods = match &file.items[1] {
            Item::Impl(item) => &item.items,
            _ => panic!("expected impl"),
        };
        assert_eq!(methods.len(), 1);
    }

    #[test]
    fn multiple_cfg_attr_attributes_are_all_validated() {
        let mut configuration = configuration();
        let mut attributes: Vec<Attribute> = vec![
            parse_quote!(#[cfg_attr(test, derive(Debug))]),
            parse_quote!(#[cfg_attr(feature = "x", derive(Clone))]),
        ];
        configuration.active_with_cfg_attr(&mut attributes, Span::call_site(), true);
        assert!(!configuration.errors.is_empty());
    }

    #[test]
    fn cfg_attr_rejects_other_predicates_attributes_and_positions() {
        for attribute in [
            parse_quote!(#[cfg_attr(not(test), derive(Debug))]),
            parse_quote!(#[cfg_attr(test, cfg(feature = "x"))]),
            parse_quote!(#[cfg_attr(test, derive(Debug), doc = "x")]),
        ] {
            let mut configuration = configuration();
            let mut attributes = vec![attribute];
            configuration.active_with_cfg_attr(&mut attributes, Span::call_site(), false);
            assert!(!configuration.errors.is_empty());
        }
    }
}
