//! A syntactic subset, not Rust name resolution or proof of a macro's origin.
//! Only exact helper spans validated in their owning type are admitted later.
use std::collections::HashSet;
use syn::{
    Attribute, Fields, Meta,
    spanned::Spanned,
    visit::{self, Visit},
};

type Location = (usize, usize, usize, usize);
fn location(a: &Attribute) -> Location {
    let s = a.span();
    (
        s.start().line,
        s.start().column,
        s.end().line,
        s.end().column,
    )
}
#[derive(Default)]
pub struct Helpers(HashSet<Location>);
impl Helpers {
    pub fn contains(&self, a: &Attribute) -> bool {
        self.0.contains(&location(a))
    }
}
fn derives(attrs: &[Attribute]) -> syn::Result<Vec<syn::Path>> {
    use syn::punctuated::Punctuated;
    let mut paths = Vec::new();
    for a in attrs.iter().filter(|a| a.path().is_ident("derive")) {
        paths.extend(a.parse_args_with(Punctuated::<syn::Path, syn::Token![,]>::parse_terminated)?);
    }
    Ok(paths)
}
fn direct(p: &syn::Path) -> bool {
    p.leading_colon.is_none()
        && p.segments.len() == 2
        && p.segments[0].ident == "thiserror"
        && p.segments[1].ident == "Error"
        && p.segments
            .iter()
            .all(|s| matches!(s.arguments, syn::PathArguments::None))
}
fn known_derive(p: &syn::Path) -> bool {
    direct(p)
        || (p.leading_colon.is_none()
            && p.segments.len() == 1
            && [
                "Debug",
                "Clone",
                "Copy",
                "PartialEq",
                "Eq",
                "PartialOrd",
                "Ord",
                "Hash",
                "Default",
            ]
            .iter()
            .any(|n| p.is_ident(n)))
}
fn template(value: &str, fields: &Fields) -> Result<(), &'static str> {
    // Grammar: text | '{{' | '}}' | '{' field [':?'] '}'.
    // field is an existing named field or canonical decimal tuple index.
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' if bytes.get(i + 1) == Some(&b'{') => i += 2,
            b'}' if bytes.get(i + 1) == Some(&b'}') => i += 2,
            b'{' => {
                let end = bytes[i + 1..]
                    .iter()
                    .position(|b| *b == b'}')
                    .map(|n| i + 1 + n)
                    .ok_or("unclosed template field")?;
                let raw = &value[i + 1..end];
                let name = raw.strip_suffix(":?").unwrap_or(raw);
                let found = match fields {
                    Fields::Named(f) => f
                        .named
                        .iter()
                        .any(|f| f.ident.as_ref().is_some_and(|id| id == name)),
                    Fields::Unnamed(f) => {
                        !name.is_empty()
                            && name.bytes().all(|b| b.is_ascii_digit())
                            && name
                                .parse::<usize>()
                                .is_ok_and(|n| n.to_string() == name && n < f.unnamed.len())
                    }
                    Fields::Unit => false,
                };
                if !found {
                    return Err("unknown field or unsupported template format");
                }
                i = end + 1;
            }
            b'}' => return Err("unmatched closing template brace"),
            _ => i += 1,
        }
    }
    Ok(())
}
struct Check {
    helpers: Helpers,
    errors: Vec<String>,
}
impl Check {
    fn error(&mut self, message: impl std::fmt::Display, span: proc_macro2::Span) {
        self.errors.push(format!(
            "unsupported thiserror metadata: {message} at {:?}",
            span.start()
        ));
    }
    fn context(&mut self, attrs: &[Attribute]) -> bool {
        let paths = match derives(attrs) {
            Ok(p) => p,
            Err(_) => return false, // Preserve existing derive behavior outside recognized contexts.
        };
        if !paths.iter().any(direct) {
            return false;
        }
        if paths.iter().filter(|p| direct(p)).count() != 1 || paths.iter().any(|p| !known_derive(p))
        {
            self.error("duplicate Error or mixed unknown derive", attrs[0].span());
        }
        true
    }
    fn owner(&mut self, attrs: &[Attribute], fields: &Fields) {
        if derives(attrs).is_ok_and(|p| !p.is_empty() && !p.iter().any(direct)) {
            self.error("derive on variant is outside the subset", fields.span());
        }
        let errors: Vec<_> = attrs
            .iter()
            .filter(|a| a.path().is_ident("error"))
            .collect();
        if errors.len() != 1 {
            self.error(
                "exactly one error attribute required per struct/variant",
                fields.span(),
            );
            return;
        }
        let attr = errors[0];
        let transparent = attr
            .parse_args::<syn::Ident>()
            .is_ok_and(|v| v == "transparent");
        if transparent {
            if fields.len() != 1 {
                self.error("transparent requires exactly one field", attr.span());
            }
        } else {
            match attr.parse_args::<syn::LitStr>() {
                Ok(s) => {
                    if let Err(e) = template(&s.value(), fields) {
                        self.error(e, attr.span());
                    }
                }
                Err(_) => self.error(
                    "expected one literal template or transparent, no extra arguments",
                    attr.span(),
                ),
            }
        }
        self.helpers.0.insert(location(attr));
        let mut sources = HashSet::new();
        let mut froms = Vec::new();
        let mut explicit_sources = 0;
        for (index, field) in fields.iter().enumerate() {
            let implicit = field.ident.as_ref().is_some_and(|n| n == "source");
            if implicit {
                sources.insert(index);
            }
            if field.ident.as_ref().is_some_and(|n| n == "backtrace")
                || matches!(&field.ty, syn::Type::Path(t) if t.path.segments.last().is_some_and(|s| s.ident == "Backtrace"))
            {
                self.error("backtrace is outside the subset", field.span());
            }
            let mut seen = HashSet::new();
            for a in &field.attrs {
                if a.path().is_ident("derive") {
                    self.error("derive on field is outside the subset", a.span());
                }
                let name = if a.path().is_ident("from") {
                    "from"
                } else if a.path().is_ident("source") {
                    "source"
                } else {
                    continue;
                };
                if !seen.insert(name) || !matches!(a.meta, Meta::Path(_)) {
                    self.error("duplicate helper or helper arguments", a.span());
                }
                self.helpers.0.insert(location(a));
                sources.insert(index);
                if name == "from" {
                    froms.push(index);
                } else {
                    explicit_sources += 1;
                }
            }
            if seen.contains("from") && seen.contains("source") {
                self.error(
                    "combined explicit from/source is outside the subset",
                    field.span(),
                );
            }
        }
        if sources.len() > 1 || froms.len() > 1 || explicit_sources > 1 {
            self.error("multiple/conflicting source or from fields", fields.span());
        }
        if !froms.is_empty() && fields.len() != 1 {
            self.error("from requires a single-field owner", fields.span());
        }
        if transparent
            && (explicit_sources > 0
                || fields
                    .iter()
                    .any(|f| f.ident.as_ref().is_some_and(|n| n == "source")))
        {
            self.error(
                "transparent with explicit/implicit source is outside the subset",
                fields.span(),
            );
        }
    }
}
impl<'ast> Visit<'ast> for Check {
    fn visit_item_struct(&mut self, n: &'ast syn::ItemStruct) {
        if self.context(&n.attrs) {
            self.owner(&n.attrs, &n.fields);
        }
        visit::visit_item_struct(self, n);
    }
    fn visit_item_enum(&mut self, n: &'ast syn::ItemEnum) {
        if self.context(&n.attrs) {
            // Enum-level helpers remain unapproved; each direct variant owns its fields.
            for variant in &n.variants {
                self.owner(&variant.attrs, &variant.fields);
            }
        }
        visit::visit_item_enum(self, n);
    }
}
pub fn validate(file: &syn::File) -> Result<Helpers, String> {
    let mut check = Check {
        helpers: Helpers::default(),
        errors: Vec::new(),
    };
    check.visit_file(file);
    if check.errors.is_empty() {
        Ok(check.helpers)
    } else {
        Err(check.errors.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use crate::inventory;
    fn parsed(source: &str) -> bool {
        inventory(source).is_ok()
    }
    #[test]
    fn literal_grammar_and_field_shapes() {
        for text in [
            "ordinary",
            "{{literal}}",
            "{code}",
            "{code:?}",
            "{{{code:?}}}",
            "unicode λ {code}",
        ] {
            assert!(
                parsed(&format!(
                    "#[derive(Debug,thiserror::Error)] #[error({text:?})] struct E {{ code: u32 }}"
                )),
                "{text}"
            );
        }
        for text in ["{0}", "{1:?}", "{{tuple}} {0} {1:?}"] {
            assert!(
                parsed(&format!(
                    "#[derive(Debug,thiserror::Error)] #[error({text:?})] struct E(u32,u32);"
                )),
                "{text}"
            );
        }
        for text in [
            "{}",
            "{absent}",
            "{code:x}",
            "{code:>4}",
            "{code:.2}",
            "{code!}",
            "{code",
            "bad}",
            "{code{code}}",
            "{0}",
        ] {
            assert!(
                !parsed(&format!(
                    "#[derive(Debug,thiserror::Error)] #[error({text:?})] struct E {{ code: u32 }}"
                )),
                "{text}"
            );
        }
        for text in ["{2}", "{00}", "{code}", "{0:x}"] {
            assert!(
                !parsed(&format!(
                    "#[derive(Debug,thiserror::Error)] #[error({text:?})] struct E(u32,u32);"
                )),
                "{text}"
            );
        }
        assert!(parsed(
            "#[derive(Debug,thiserror::Error)] enum E { #[error(\"bad\")] Bad, #[error(\"{value:?}\")] Named{value:u32}, #[error(\"{0}\")] Tuple(u32) }"
        ));
    }
    #[test]
    fn source_and_conversion_constraints() {
        for body in [
            "#[error(\"bad\")] struct E { source: Inner }",
            "#[error(\"bad\")] struct E { #[source] inner: Inner, code:u32 }",
            "#[error(\"bad\")] struct E(#[from] Inner);",
            "#[error(\"bad\")] struct E { #[from] source: Inner }",
            "#[error(transparent)] struct E(#[from] Inner);",
            "#[error(transparent)] struct E(Inner);",
        ] {
            assert!(
                parsed(&format!("#[derive(Debug,thiserror::Error)] {body}")),
                "{body}"
            );
        }
        for body in [
            "#[error(transparent)] struct E;",
            "#[error(transparent)] struct E(Inner,Inner);",
            "#[error(transparent)] struct E(#[source] Inner);",
            "#[error(transparent)] struct E { source: Inner }",
            "#[error(\"bad\")] struct E(#[from] Inner,u32);",
            "#[error(\"bad\")] struct E(#[from] #[source] Inner);",
            "#[error(\"bad\")] struct E(#[from] #[from] Inner);",
            "#[error(\"bad\")] struct E(#[source] #[source] Inner);",
            "#[error(\"bad\")] struct E(#[source()] Inner);",
            "#[error(\"bad\")] struct E(#[from(ignore)] Inner);",
            "#[error(\"bad\")] struct E { source: Inner, #[source] other:Inner }",
            "#[error(\"bad\")] struct E { source: Inner, other:Backtrace }",
            "#[error(\"bad\")] struct E { backtrace: Inner }",
            "#[error(\"bad\")] struct E(#[backtrace] Inner);",
        ] {
            assert!(
                !parsed(&format!("#[derive(Debug,thiserror::Error)] {body}")),
                "{body}"
            );
        }
    }
    #[test]
    fn helpers_do_not_escape_exact_owners() {
        let valid = "#[derive(Debug,thiserror::Error)] #[error(\"bad\")] struct E;";
        for extra in [
            "#[error(\"bad\")] fn adjacent(){}",
            "struct Other { #[source] x: Inner }",
            "impl E { #[from] fn method() {} }",
            "fn outer() { #[error(\"bad\")] struct Nested; }",
            "mod inner { #[source] fn f() {} }",
        ] {
            assert!(!parsed(&format!("{valid} {extra}")), "{extra}");
        }
        for source in [
            "#[derive(Error)] #[error(\"bad\")] struct E;",
            "#[derive(alias::Error)] #[error(\"bad\")] struct E;",
            "#[derive(thiserror::Error,custom::Macro)] #[error(\"bad\")] struct E;",
            "#[derive(thiserror::Error,thiserror::Error)] #[error(\"bad\")] struct E;",
            "#[derive(thiserror::Error)] #[custom] #[error(\"bad\")] struct E;",
            "#[derive(thiserror::Error)] #[error(\"bad\")] #[error(\"other\")] struct E;",
            "#[derive(thiserror::Error)] #[error(\"bad\", callback())] struct E;",
            "#[derive(thiserror::Error)] #[error(123)] struct E;",
            "#[derive(thiserror::Error)] #[error(\"bad\")] enum E { #[error(\"bad\")] A }",
            "#[derive(thiserror::Error)] enum E { Missing }",
            "#[derive(thiserror::Error)] enum E { #[derive(custom::Macro)] #[error(\"bad\")] A }",
            "#[derive(thiserror::Error)] #[error(\"bad\")] struct E { #[derive(custom::Macro)] value:u32 }",
            "#[derive(thiserror::Error)] #[error(\"bad\")] struct E { value:[u8; { #[source] fn nested(){} 1 }] }",
        ] {
            assert!(!parsed(source), "{source}");
        }
        // Existing arbitrary derive handling remains unchanged outside Error context.
        assert!(parsed("#[derive(custom::Macro)] struct Other;"));
        assert!(parsed(
            "#[derive(thiserror::Error)] #[error(\"bad\")] struct E; impl E { fn method(x:bool) { if x {} } } fn outer() { let _f = || if true {1} else {0}; fn nested(){} }"
        ));
    }
}
