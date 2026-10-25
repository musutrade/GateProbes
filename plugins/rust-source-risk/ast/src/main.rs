mod configuration;
mod error_metadata;
mod select;

use configuration::{Configuration, TargetConfiguration};
use proc_macro2::Span;
use serde::Serialize;
use syn::{
    spanned::Spanned,
    visit::{self, Visit},
};

#[derive(Serialize)]
struct Callable {
    name: String,
    kind: &'static str,
    start: [usize; 2],
    end: [usize; 2],
    anchors: Vec<[usize; 2]>,
    body: [usize; 2],
    asynchronous: bool,
    complexity: u64,
}
struct Inventory<'a> {
    source: &'a str,
    functions: Vec<Callable>,
    stack: Vec<usize>,
    errors: Vec<String>,
    error_helpers: error_metadata::Helpers,
}
impl Inventory<'_> {
    fn point(&self, p: proc_macro2::LineColumn) -> [usize; 2] {
        let line = self.source.lines().nth(p.line - 1).unwrap_or("");
        [
            p.line,
            line.chars()
                .take(p.column)
                .map(char::len_utf8)
                .sum::<usize>()
                + 1,
        ]
    }
    fn begin(
        &mut self,
        name: String,
        kind: &'static str,
        span: Span,
        anchors: &[Span],
        body: Span,
        asynchronous: bool,
    ) {
        let index = self.functions.len();
        self.functions.push(Callable {
            name,
            kind,
            start: self.point(span.start()),
            end: self.point(span.end()),
            anchors: anchors.iter().map(|s| self.point(s.start())).collect(),
            body: self.point(body.start()),
            asynchronous,
            complexity: 1,
        });
        self.stack.push(index);
    }
    fn decision(&mut self, n: usize) {
        if let Some(i) = self.stack.last() {
            self.functions[*i].complexity += n as u64;
        }
    }
    fn unsupported(&mut self, kind: &str, span: Span) {
        self.errors
            .push(format!("{kind} at {:?}", self.point(span.start())));
    }
}
// LLVM can start a closure counter at its first evaluated source expression,
// omitting constructors and punctuation. Follow only the leading AST spine;
// never accept arbitrary positions inside a callable or cross into a nested owner.
fn closure_entry_anchors<'a>(expression: &'a syn::Expr, anchors: &mut Vec<Span>) {
    use syn::Expr;
    if let Expr::Async(n) = expression {
        // Returning an async block constructs a future. Its closing brace is
        // the factory region; the opening brace belongs to the separate poll body.
        anchors.push(n.block.brace_token.span.close());
        return;
    }
    if matches!(expression, Expr::Closure(_)) {
        return;
    }
    anchors.push(expression.span());
    let next: Option<&'a Expr> = match expression {
        Expr::Paren(n) => Some(&n.expr),
        Expr::Group(n) => Some(&n.expr),
        Expr::Unary(n) => Some(&n.expr),
        Expr::Reference(n) => Some(&n.expr),
        Expr::Cast(n) => Some(&n.expr),
        Expr::Try(n) => Some(&n.expr),
        Expr::Await(n) => Some(&n.base),
        Expr::Binary(n) => Some(&n.left),
        Expr::If(n) => Some(&n.cond),
        Expr::Match(n) => Some(&n.expr),
        Expr::Tuple(n) => n.elems.first(),
        Expr::Array(n) => n.elems.first(),
        Expr::Repeat(n) => Some(&n.expr),
        Expr::Struct(n) => n.fields.first().map(|f| &f.expr).or(n.rest.as_deref()),
        Expr::Return(n) => n.expr.as_deref(),
        Expr::Break(n) => n.expr.as_deref(),
        Expr::Call(n) if n.args.len() == 1 => match n.func.as_ref() {
            Expr::Path(path)
                if path.qself.is_none()
                    && path.path.segments.len() == 1
                    && ["Ok", "Err", "Some"]
                        .iter()
                        .any(|name| path.path.segments[0].ident == name) =>
            {
                n.args.first()
            }
            _ => None,
        },
        _ => None,
    };
    if let Some(next) = next {
        closure_entry_anchors(next, anchors);
    }
}

// Parse JSON containers while retaining the spans of every Rust expression.
// Macro expansion control flow is outside this source-only metric.
struct JsonExpressions(Vec<syn::Expr>);
impl syn::parse::Parse for JsonExpressions {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut expressions = Vec::new();
        if input.peek(syn::token::Brace) {
            let content;
            syn::braced!(content in input);
            while !content.is_empty() {
                expressions.push(content.parse()?);
                content.parse::<syn::Token![:]>()?;
                expressions.extend(content.parse::<Self>()?.0);
                if content.is_empty() {
                    break;
                }
                content.parse::<syn::Token![,]>()?;
            }
        } else if input.peek(syn::token::Bracket) {
            let content;
            syn::bracketed!(content in input);
            while !content.is_empty() {
                expressions.extend(content.parse::<Self>()?.0);
                if content.is_empty() {
                    break;
                }
                content.parse::<syn::Token![,]>()?;
            }
        } else {
            expressions.push(input.parse()?);
        }
        Ok(Self(expressions))
    }
}
fn serde_metadata(attribute: &syn::Attribute) -> syn::Result<()> {
    attribute.parse_nested_meta(|meta| {
        if [
            "deny_unknown_fields",
            "untagged",
            "transparent",
            "skip",
            "skip_serializing",
            "skip_deserializing",
        ]
        .iter()
        .any(|name| meta.path.is_ident(name))
        {
            return Ok(());
        }
        if [
            "tag",
            "content",
            "rename",
            "rename_all",
            "rename_all_fields",
            "alias",
        ]
        .iter()
        .any(|name| meta.path.is_ident(name))
        {
            meta.value()?.parse::<syn::LitStr>()?;
            return Ok(());
        }
        Err(meta.error("unsupported Serde metadata"))
    })
}
impl<'ast> Visit<'ast> for Inventory<'_> {
    fn visit_item_mod(&mut self, n: &'ast syn::ItemMod) {
        // Exact cfg(test) modules cannot contribute production callables.
        // All other configuration remains unsupported rather than guessed.
        if n.attrs.iter().any(|attr| {
            attr.path().is_ident("cfg")
                && attr
                    .parse_args::<syn::Path>()
                    .is_ok_and(|path| path.is_ident("test"))
        }) {
            return;
        }
        visit::visit_item_mod(self, n);
    }

    fn visit_attribute(&mut self, n: &'ast syn::Attribute) {
        if self.error_helpers.contains(n) {
            return;
        }
        let path = n
            .path()
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        if path == "serde" {
            if serde_metadata(n).is_err() {
                self.unsupported("unsupported Serde metadata", n.span());
            }
            return;
        }
        if ![
            "doc",
            "derive",
            "repr",
            "inline",
            "cold",
            "must_use",
            "allow",
            "warn",
            "deny",
            "forbid",
            "deprecated",
            "tokio::main",
        ]
        .contains(&path.as_str())
        {
            self.unsupported(&format!("unsupported attribute {path}"), n.span());
        }
    }
    fn visit_item_fn(&mut self, n: &'ast syn::ItemFn) {
        for attr in &n.attrs {
            self.visit_attribute(attr);
        }
        self.begin(
            n.sig.ident.to_string(),
            "function",
            n.span(),
            &[
                if matches!(n.vis, syn::Visibility::Inherited) {
                    n.sig.span()
                } else {
                    n.vis.span()
                },
                n.sig.span(),
                n.sig.fn_token.span,
                n.block.brace_token.span.open(),
            ],
            n.block.brace_token.span.open(),
            n.sig.asyncness.is_some(),
        );
        visit::visit_block(self, &n.block);
        self.stack.pop();
    }
    fn visit_impl_item_fn(&mut self, n: &'ast syn::ImplItemFn) {
        for attr in &n.attrs {
            self.visit_attribute(attr);
        }
        self.begin(
            n.sig.ident.to_string(),
            "method",
            n.span(),
            &[
                if matches!(n.vis, syn::Visibility::Inherited) {
                    n.sig.span()
                } else {
                    n.vis.span()
                },
                n.sig.span(),
                n.sig.fn_token.span,
                n.block.brace_token.span.open(),
            ],
            n.block.brace_token.span.open(),
            n.sig.asyncness.is_some(),
        );
        visit::visit_block(self, &n.block);
        self.stack.pop();
    }
    fn visit_trait_item_fn(&mut self, n: &'ast syn::TraitItemFn) {
        for attr in &n.attrs {
            self.visit_attribute(attr);
        }
        if let Some(block) = &n.default {
            self.begin(
                n.sig.ident.to_string(),
                "default-method",
                n.span(),
                &[
                    n.sig.span(),
                    n.sig.fn_token.span,
                    block.brace_token.span.open(),
                ],
                block.brace_token.span.open(),
                n.sig.asyncness.is_some(),
            );
            visit::visit_block(self, block);
            self.stack.pop();
        }
    }
    fn visit_expr_closure(&mut self, n: &'ast syn::ExprClosure) {
        for attr in &n.attrs {
            self.visit_attribute(attr);
        }
        let mut anchors = vec![n.span()];
        closure_entry_anchors(&n.body, &mut anchors);
        self.begin(
            "<closure>".into(),
            "closure",
            n.span(),
            &anchors,
            n.body.span(),
            n.asyncness.is_some(),
        );
        self.visit_expr(&n.body);
        self.stack.pop();
    }
    fn visit_expr_async(&mut self, n: &'ast syn::ExprAsync) {
        for attr in &n.attrs {
            self.visit_attribute(attr);
        }
        self.begin(
            "<async>".into(),
            "async-block",
            n.span(),
            &[n.span(), n.block.brace_token.span.open()],
            n.block.brace_token.span.open(),
            true,
        );
        visit::visit_block(self, &n.block);
        self.stack.pop();
    }
    fn visit_expr_if(&mut self, n: &'ast syn::ExprIf) {
        self.decision(1);
        visit::visit_expr_if(self, n);
    }
    fn visit_expr_for_loop(&mut self, n: &'ast syn::ExprForLoop) {
        self.decision(1);
        visit::visit_expr_for_loop(self, n);
    }
    fn visit_expr_while(&mut self, n: &'ast syn::ExprWhile) {
        self.decision(1);
        visit::visit_expr_while(self, n);
    }
    fn visit_expr_match(&mut self, n: &'ast syn::ExprMatch) {
        self.decision(
            n.arms.len().saturating_sub(1) + n.arms.iter().filter(|a| a.guard.is_some()).count(),
        );
        visit::visit_expr_match(self, n);
    }
    fn visit_expr_binary(&mut self, n: &'ast syn::ExprBinary) {
        if matches!(n.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) {
            self.decision(1);
        }
        visit::visit_expr_binary(self, n);
    }
    fn visit_expr_try(&mut self, n: &'ast syn::ExprTry) {
        self.decision(1);
        visit::visit_expr_try(self, n);
    }
    fn visit_local(&mut self, n: &'ast syn::Local) {
        if n.init.as_ref().is_some_and(|i| i.diverge.is_some()) {
            self.decision(1);
        }
        visit::visit_local(self, n);
    }
    fn visit_item_macro(&mut self, n: &'ast syn::ItemMacro) {
        self.unsupported("item macro", n.span());
    }
    fn visit_macro(&mut self, n: &'ast syn::Macro) {
        use syn::parse::Parser;
        let path = n
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        if ["json", "serde_json::json"].contains(&path.as_str()) {
            match syn::parse2::<JsonExpressions>(n.tokens.clone()) {
                Ok(expressions) => {
                    for expression in expressions.0 {
                        self.visit_expr(&expression);
                    }
                }
                Err(_) => self.unsupported("unsupported json! arguments", n.span()),
            }
        } else if path == "tokio::select" {
            match select::parse.parse2(n.tokens.clone()) {
                Ok(parsed) => {
                    self.decision(parsed.decisions + parsed.guards);
                    for expression in parsed.expressions {
                        self.visit_expr(&expression);
                    }
                }
                Err(_) => self.unsupported("unsupported tokio::select! arguments", n.span()),
            }
        } else if path == "matches" {
            let parser =
                |input: syn::parse::ParseStream| -> syn::Result<(syn::Expr, Option<syn::Expr>)> {
                    let expression = input.parse()?;
                    input.parse::<syn::Token![,]>()?;
                    syn::Pat::parse_multi_with_leading_vert(input)?;
                    let guard = if input.peek(syn::Token![if]) {
                        input.parse::<syn::Token![if]>()?;
                        Some(input.parse()?)
                    } else {
                        None
                    };
                    if input.peek(syn::Token![,]) {
                        input.parse::<syn::Token![,]>()?;
                    }
                    Ok((expression, guard))
                };
            match parser.parse2(n.tokens.clone()) {
                Ok((expression, guard)) => {
                    self.decision(1 + usize::from(guard.is_some()));
                    self.visit_expr(&expression);
                    if let Some(g) = guard {
                        self.visit_expr(&g);
                    }
                }
                Err(_) => self.unsupported("unparsed matches!", n.span()),
            }
        } else if [
            "format",
            "std::format",
            "tracing::info",
            "tracing::warn",
            "tracing::error",
            "tracing::debug",
            "tracing::trace",
            "sqlx::migrate",
        ]
        .contains(&path.as_str())
        {
            let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
            match parser.parse2(n.tokens.clone()) {
                Ok(expressions) => {
                    for e in expressions {
                        self.visit_expr(&e);
                    }
                }
                Err(_) => self.unsupported("unsupported macro arguments", n.span()),
            }
        } else {
            self.unsupported(&format!("unrecognized macro {path}!"), n.span());
        }
    }
}
fn inventory_with_target(
    source: &str,
    target: &TargetConfiguration,
) -> Result<Vec<Callable>, String> {
    let mut syntax = syn::parse_file(source).map_err(|e| e.to_string())?;
    let mut filter = Configuration::new(target.cfg.clone());
    filter.apply(&mut syntax);
    if !filter.errors.is_empty() {
        return Err(filter.errors.join("; "));
    }
    let error_helpers = error_metadata::validate(&syntax)?;
    let mut visitor = Inventory {
        source,
        error_helpers,
        functions: vec![],
        stack: vec![],
        errors: vec![],
    };
    visitor.visit_file(&syntax);
    if !visitor.errors.is_empty() {
        return Err(visitor.errors.join("; "));
    }
    Ok(visitor.functions)
}
fn main() {
    let result = (|| -> Result<(), String> {
        let mut args = std::env::args().skip(1);
        let path = args.next().ok_or("expected Rust source path")?;
        if args.next().as_deref() != Some("--target-cfg") || args.next().is_some() {
            return Err("expected --target-cfg and one JSON target configuration on stdin".into());
        }
        let target: TargetConfiguration = serde_json::from_reader(std::io::stdin())
            .map_err(|e| format!("invalid target configuration: {e}"))?;
        let target = target.canonical()?;
        let source = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        println!(
            "{}",
            serde_json::to_string(&inventory_with_target(&source, &target)?)
                .map_err(|e| e.to_string())?
        );
        Ok(())
    })();
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
#[cfg(test)]
fn inventory(source: &str) -> Result<Vec<Callable>, String> {
    inventory_with_target(
        source,
        &TargetConfiguration {
            target: "x86_64-unknown-linux-gnu".into(),
            cfg: vec!["target_os=\"linux\"".into(), "unix".into()],
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modules_are_outside_the_production_boundary() {
        let rows = inventory("fn production() {} #[cfg(test)] mod tests { #[test] fn only_test() { arbitrary!(); } } #[cfg(test)] #[path=\"../tests/external.rs\"] mod external;").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "production");
        let rows = inventory("#[cfg(not(test))] mod production { fn f() {} }").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "f");
        assert!(inventory("#[cfg(feature=\"test\")] mod feature { fn f() {} }").is_err());
    }
    #[test]
    fn explicit_decisions() {
        let f = inventory("fn f(x: Option<i32>) -> Option<i32> { let Some(y) = x else { return None }; if y > 0 && y < 4 { for _ in 0..y {} } while false {} match y { 0 => {}, 1 if true => {}, _ => {} } Some(x?) }").unwrap();
        assert_eq!(f[0].complexity, 10);
    }
    #[test]
    fn nested_owners() {
        let f = inventory(
            "async fn f() { let g = || if true { 1 } else { 2 }; let h = async { if false {} }; }",
        )
        .unwrap();
        assert_eq!(
            f.iter().map(|f| f.complexity).collect::<Vec<_>>(),
            vec![1, 2, 2]
        );
    }
    #[test]
    fn macros_count_only_source() {
        let f = inventory(
            "fn f(x: Option<i32>) { tracing::info!(\"{}\", x?); matches!(x, Some(y) if y > 0); }",
        )
        .unwrap();
        assert_eq!(f[0].complexity, 4);
        assert!(inventory("fn f() { custom!(); }").is_err());
        assert!(inventory("macro_rules! x { () => {} }").is_err());
        assert!(inventory("#[cfg(feature = \"x\")] fn f() {}").is_err());
    }
    #[test]
    fn business_macros_visit_nested_expressions_and_owners() {
        let f = inventory(r#"fn f() { json!({"n": if true { 1 } else { 2 }, "a": [null, call()?, {"v": (|| if true { 1 } else { 0 })()}]}); format!("{}", if true { 1 } else { 0 }); }"#).unwrap();
        assert_eq!(
            f.iter().map(|f| f.complexity).collect::<Vec<_>>(),
            vec![4, 2]
        );
        let f = inventory(r#"fn f() { serde_json::json!({(if true { "a" } else { "b" }): [1, 2,],}); std::format!("{n}", n = call()?); }"#).unwrap();
        assert_eq!(f[0].complexity, 3);
        assert!(inventory(r#"fn f() { json!({"a": }); }"#).is_err());
        assert!(inventory(r#"fn f() { json!({"a": custom!()}); }"#).is_err());
    }
    #[test]
    fn serde_metadata_is_declarative_and_fail_closed() {
        assert!(inventory(r#"#[derive(Serialize)] #[serde(deny_unknown_fields)] struct A { #[serde(rename = "value")] v: i32 } #[serde(tag = "operation", content = "data")] enum B { A(A) }"#).is_ok());
        for source in [
            r#"#[serde(unknown)] struct A {}"#,
            r#"#[serde(tag = call())] enum A {}"#,
            r#"#[serde(serialize_with = "hidden")] struct A {}"#,
        ] {
            assert!(inventory(source).is_err());
        }
    }
    #[test]
    fn result_wrapped_closure_has_exact_lowered_entry_anchor() {
        let source = "fn f() { let g = |s| Ok(parse(s)?); }";
        let rows = inventory(source).unwrap();
        assert!(
            rows[1]
                .anchors
                .contains(&[1, source.find("parse").unwrap() + 1])
        );
        assert_eq!(rows[1].complexity, 2);
    }
    #[test]
    fn unicode_columns_are_bytes() {
        let src = "fn f() { let café = 1; let g = || café; }";
        let f = inventory(src).unwrap();
        assert_eq!(f[1].start[1], src.find("||").unwrap() + 1);
    }
    #[test]
    fn production_view_handles_compound_and_nested_cfg() {
        let source = r#"
#[cfg(any(test, unix))]
fn unix_or_test() { if true {} }
#[cfg(all(test, target_os = "linux"))]
fn linux_test_only() {}
#[cfg(all(unix, not(test)))]
fn unix_production() { if true {} }
#[cfg(not(any(unix, windows)))]
fn exotic() {}
#[cfg(not(windows))]
fn not_windows() { if true {} }
fn plain() {}
"#;
        let rows = inventory(source).unwrap();
        assert_eq!(
            rows.iter().map(|row| row.name.as_str()).collect::<Vec<_>>(),
            vec!["unix_or_test", "unix_production", "not_windows", "plain"]
        );
        assert_eq!(rows[0].complexity, 2);
        assert_eq!(rows[1].complexity, 2);
    }

    #[test]
    fn cfg_attr_test_derive_is_accepted_only_on_derive_bearing_items() {
        let source = r#"
#[cfg_attr(test, derive(schemars::JsonSchema))]
struct Production { value: String }
#[cfg_attr(test, derive(Debug), derive(Clone))]
enum Mode { A }
#[cfg_attr(test, derive(Debug))]
union Bits { value: u64 }
fn plain() {}
"#;
        let rows = inventory(source).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "plain");
        assert!(inventory("#[cfg_attr(test, derive(Debug))] fn bad() {}").is_err());
        assert!(
            inventory("#[cfg_attr(not(test), derive(Debug))] struct Bad { value: u8 }").is_err()
        );
        assert!(
            inventory("#[cfg_attr(test, cfg(feature = \"x\"))] struct Bad { value: u8 }").is_err()
        );
    }

    #[test]
    fn every_cfg_operand_is_validated_before_reduction() {
        for source in [
            "#[cfg(all(windows, feature = \"x\"))] fn f() {}",
            "#[cfg(any(unix, feature = \"x\"))] fn f() {}",
            "#[cfg(not(feature = \"x\"))] fn f() {}",
        ] {
            assert!(inventory(source).is_err(), "{source}");
        }
    }

    #[test]
    fn async_and_methods() {
        let f = inventory(
            "struct A; impl A { async fn run(&self) { if true {} } } trait T { fn f() {} }",
        )
        .unwrap();
        assert_eq!(f.len(), 2);
        assert!(f[0].asynchronous);
        assert_eq!(f[0].complexity, 2);
    }
}

#[cfg(test)]
mod select_tests {
    use super::inventory;

    #[test]
    fn select_decisions_and_nested_owners() {
        let rows = inventory("async fn f() { tokio::select! { biased; Some(x) = a(), if enabled && ready => { if x {} } _ = async { if test {} }, if enabled => (|| if test { 1 } else { 2 })(), else => fallback()? } }").unwrap();
        // Base + two alternatives + refutable pattern + two guards + && + if + ?.
        assert_eq!(
            rows.iter().map(|r| r.complexity).collect::<Vec<_>>(),
            vec![9, 2, 2]
        );
        assert!(rows[1].asynchronous);
    }

    #[test]
    fn select_rejects_incomplete_or_unknown_syntax() {
        for source in [
            "async fn f() { tokio::select! {} }",
            "async fn f() { tokio::select! { else => {} } }",
            "async fn f() { tokio::select! { _ = a() => 1 _ = b() => 2 } }",
            "async fn f() { tokio::select! { _ = a() => {}, else => {}, _ = b() => {} } }",
            "async fn f() { tokio::select! { _ = a() => unknown!() } }",
            "async fn f() { select! { _ = a() => {} } }",
        ] {
            assert!(inventory(source).is_err(), "{source}");
        }
    }

    #[test]
    fn select_preserves_source_spans_and_counts_handlers() {
        let source = "async fn f() { tokio::select! { result = a() => return result?, _ = b() => { if stopped {} } } }";
        let rows = inventory(source).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].complexity, 4);
        assert_eq!(rows[0].start, [1, 1]);
        assert_eq!(rows[0].end, [1, source.len() + 1]);
    }
}
