//! Production item filtering for the recorded target configuration.
use proc_macro2::Span;
use serde::Deserialize;
use syn::{
    Attribute, Expr, Item, Meta,
    spanned::Spanned,
    visit_mut::{self, VisitMut},
};

#[derive(Clone, Deserialize)]
pub struct TargetConfiguration {
    pub target: String,
    pub cfg: Vec<String>,
}

impl TargetConfiguration {
    pub fn canonical(self) -> Result<Self, String> {
        if self.target.is_empty() || self.target.chars().any(char::is_whitespace) {
            return Err("invalid target triple".into());
        }
        if self.cfg.is_empty() || self.cfg.iter().any(String::is_empty) {
            return Err("empty target configuration".into());
        }
        let mut sorted = self.cfg.clone();
        sorted.sort();
        sorted.dedup();
        if sorted != self.cfg {
            return Err("target configuration must be sorted and unique".into());
        }
        let operating_systems = ["linux", "macos", "windows"]
            .into_iter()
            .filter(|os| {
                self.cfg
                    .iter()
                    .any(|value| value == &format!("target_os={os:?}"))
            })
            .collect::<Vec<_>>();
        if operating_systems.len() != 1 {
            return Err("target configuration must contain exactly one supported target_os".into());
        }
        let os = operating_systems[0];
        let triple_matches = match os {
            "linux" => self.target.contains("linux"),
            "macos" => self.target.contains("darwin") || self.target.contains("apple"),
            "windows" => self.target.contains("windows"),
            _ => false,
        };
        if !triple_matches {
            return Err("target triple and target_os disagree".into());
        }
        let unix = self.cfg.iter().any(|value| value == "unix");
        let windows = self.cfg.iter().any(|value| value == "windows");
        if (os == "windows") != windows || (os != "windows") != unix {
            return Err("target configuration has contradictory family values".into());
        }
        Ok(self)
    }
}

pub struct Configuration {
    values: Vec<String>,
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

impl Configuration {
    pub fn new(values: Vec<String>) -> Self {
        Self {
            values,
            errors: vec![],
        }
    }

    fn atom(&self, meta: &Meta) -> syn::Result<bool> {
        match meta {
            Meta::Path(path) if path.is_ident("test") => Ok(false),
            Meta::Path(path) if path.is_ident("unix") || path.is_ident("windows") => {
                Ok(self.values.contains(&path.get_ident().unwrap().to_string()))
            }
            Meta::NameValue(value) if value.path.is_ident("target_os") => {
                if let Expr::Lit(expression) = &value.value
                    && let syn::Lit::Str(name) = &expression.lit
                {
                    let name = name.value();
                    if matches!(name.as_str(), "linux" | "macos" | "windows") {
                        return Ok(self.values.contains(&format!("target_os={name:?}")));
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
            let Meta::List(list) = argument else {
                return false;
            };
            if !list.path.is_ident("derive") {
                return false;
            }
            let Ok(paths) = syn::parse::Parser::parse2(
                syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
                list.tokens.clone(),
            ) else {
                return false;
            };
            if paths.is_empty() {
                return false;
            }
            derive = true;
        }
        derive
    }

    fn active(
        &mut self,
        attributes: &mut Vec<Attribute>,
        location: Span,
        allow_test_derive: bool,
    ) -> bool {
        let mut active = !attributes
            .iter()
            .any(|attribute| attribute.path().is_ident("test"));
        for attribute in attributes.iter() {
            if attribute.path().is_ident("cfg_attr") {
                if !allow_test_derive || !Self::test_derive(attribute) {
                    self.errors.push(format!(
                        "unsupported cfg_attr at {:?}",
                        attribute.span().start()
                    ));
                }
            } else if attribute.path().is_ident("cfg") {
                match attribute
                    .parse_args::<Meta>()
                    .and_then(|meta| self.predicate(&meta))
                {
                    Ok(value) => active &= value,
                    Err(error) => self
                        .errors
                        .push(format!("{error} at {:?}", attribute.span().start())),
                }
            }
        }
        let _ = location;
        attributes.retain(|attribute| {
            !attribute.path().is_ident("cfg") && !attribute.path().is_ident("cfg_attr")
        });
        active
    }

    fn items(&mut self, items: &mut Vec<Item>) {
        items.retain_mut(|item| {
            let location = item.span();
            let allow_test_derive =
                matches!(item, Item::Struct(_) | Item::Enum(_) | Item::Union(_));
            match item_attributes(item) {
                Some(attributes) => self.active(attributes, location, allow_test_derive),
                None => {
                    self.errors
                        .push("unsupported conditional item position".into());
                    false
                }
            }
        });
    }

    pub fn apply(&mut self, file: &mut syn::File) {
        self.items(&mut file.items);
        visit_mut::visit_file_mut(self, file);
    }
}

impl VisitMut for Configuration {
    fn visit_file_mut(&mut self, node: &mut syn::File) {
        self.items(&mut node.items);
        visit_mut::visit_file_mut(self, node);
    }

    fn visit_item_mod_mut(&mut self, node: &mut syn::ItemMod) {
        if let Some((_, items)) = &mut node.content {
            self.items(items);
        }
        visit_mut::visit_item_mod_mut(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    fn configuration() -> Configuration {
        Configuration::new(vec!["unix".into(), "target_os=\"linux\"".into()])
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
        let mut attributes: Vec<Attribute> =
            vec![parse_quote!(#[cfg_attr(test, derive(schemars::JsonSchema))])];
        assert!(configuration.active(&mut attributes, Span::call_site(), true));
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
        configuration.active(&mut attributes, Span::call_site(), false);
        assert!(!configuration.errors.is_empty());
    }

    #[test]
    fn multiple_cfg_attr_attributes_are_all_validated() {
        let mut configuration = configuration();
        let mut attributes: Vec<Attribute> = vec![
            parse_quote!(#[cfg_attr(test, derive(Debug))]),
            parse_quote!(#[cfg_attr(feature = "x", derive(Clone))]),
        ];
        configuration.active(&mut attributes, Span::call_site(), true);
        assert!(!configuration.errors.is_empty());
    }

    #[test]
    fn cfg_attr_rejects_other_predicates_attributes_and_positions() {
        for attribute in [
            parse_quote!(#[cfg_attr(not(test), derive(Debug))]),
            parse_quote!(#[cfg_attr(test, cfg(feature = "x"))]),
            parse_quote!(#[cfg_attr(test, derive(Debug), doc = "x")]),
            parse_quote!(#[cfg_attr(test, derive(Debug = "bad"))]),
            parse_quote!(#[cfg_attr(test, derive())]),
            parse_quote!(#[cfg_attr(test, derive("Debug"))]),
            parse_quote!(#[cfg_attr(test, derive(derive(Debug))) ]),
        ] {
            let mut configuration = configuration();
            let mut attributes = vec![attribute];
            configuration.active(&mut attributes, Span::call_site(), false);
            assert!(!configuration.errors.is_empty());
        }
    }

    #[test]
    fn target_configuration_requires_canonical_matching_values() {
        let valid = TargetConfiguration {
            target: "x86_64-unknown-linux-gnu".into(),
            cfg: vec!["target_os=\"linux\"".into(), "unix".into()],
        };
        assert!(valid.canonical().is_ok());
        assert!(
            TargetConfiguration {
                target: "aarch64-apple-darwin".into(),
                cfg: vec!["target_os=\"macos\"".into(), "unix".into()],
            }
            .canonical()
            .is_ok()
        );
        for invalid in [
            TargetConfiguration {
                target: "x86_64-unknown-linux-gnu".into(),
                cfg: vec!["unix".into(), "target_os=\"linux\"".into()],
            },
            TargetConfiguration {
                target: "x86_64-unknown-windows-msvc".into(),
                cfg: vec!["target_os=\"linux\"".into(), "unix".into()],
            },
            TargetConfiguration {
                target: "x86_64-unknown-linux-gnu".into(),
                cfg: vec!["target_os=\"linux\"".into(), "unix".into(), "unix".into()],
            },
        ] {
            assert!(invalid.canonical().is_err());
        }
    }
}
