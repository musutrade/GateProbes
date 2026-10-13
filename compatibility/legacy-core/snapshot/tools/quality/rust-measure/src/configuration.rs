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
                match &inner {
                    // Preserve the old not(atom) boundary; only a bounded any
                    // is additionally removable. Other nesting stays rejected.
                    Meta::Path(_) => Ok(!self.atom(&inner)?),
                    Meta::List(list) if list.path.is_ident("any") => Ok(!self.predicate(&inner)?),
                    _ => Err(syn::Error::new_spanned(meta, "unsupported cfg predicate")),
                }
            }
            Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => {
                let predicates = list.parse_args_with(
                    syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
                )?;
                let all = list.path.is_ident("all");
                // Validate every operand before reducing, even when test=false
                // or an earlier operand decides the result. all retains its
                // existing path-only grammar; any accepts only known atoms.
                let values = predicates
                    .iter()
                    .map(|meta| {
                        if all && !matches!(meta, Meta::Path(_)) {
                            return Err(syn::Error::new_spanned(
                                meta,
                                "unsupported cfg all operand",
                            ));
                        }
                        self.atom(meta)
                    })
                    .collect::<syn::Result<Vec<_>>>()?;
                Ok(if all {
                    values.into_iter().all(|value| value)
                } else {
                    values.into_iter().any(|value| value)
                })
            }
            _ => self.atom(meta),
        }
    }

    fn active(&mut self, attributes: &mut Vec<Attribute>, location: Span) -> bool {
        // Test code is outside this production series, regardless of test build cfg.
        let mut active = !attributes.iter().any(|a| a.path().is_ident("test"));
        for attr in attributes.iter() {
            if attr.path().is_ident("cfg_attr") {
                self.errors
                    .push(format!("unsupported cfg_attr at {:?}", attr.span().start()));
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
        attributes.retain(|attr| !attr.path().is_ident("cfg"));
        active
    }

    fn items(&mut self, items: &mut Vec<Item>) {
        items.retain_mut(|item| {
            let location = item.span();
            match item_attributes(item) {
                Some(attrs) => self.active(attrs, location),
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
