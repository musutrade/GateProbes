//! Opt-in source syntax only. Does not certify expanded code or LLVM mapping.
use quote::ToTokens;
use syn::{parse::ParseStream, parse::Parser, Expr, Token};

#[derive(Default)]
pub struct Parsed {
    pub expressions: Vec<Expr>,
    pub decisions: u64,
    pub guards: u64,
}

fn tracing(input: ParseStream) -> syn::Result<Parsed> {
    let mut parsed = Parsed::default();
    while !input.is_empty() {
        // Named fields and target/parent directives. Parse the value separately
        // so `%` and `?` formatting markers cannot hide executable expressions.
        let fork = input.fork();
        let field = fork.parse::<syn::Path>();
        if field.is_ok() && (fork.peek(Token![=]) || fork.peek(Token![:])) {
            input.parse::<syn::Path>()?;
            if input.peek(Token![=]) {
                input.parse::<Token![=]>()?;
            } else {
                input.parse::<Token![:]>()?;
            }
        }
        if input.peek(Token![%]) {
            input.parse::<Token![%]>()?;
        } else if input.peek(Token![?]) {
            input.parse::<Token![?]>()?;
        }
        parsed.expressions.push(input.parse()?);
        if !input.is_empty() {
            input.parse::<Token![,]>()?;
        }
    }
    Ok(parsed)
}

fn select(input: ParseStream) -> syn::Result<Parsed> {
    let mut parsed = Parsed::default();
    let mut branches = 0u64;
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
        parsed.decisions += u64::from(!irrefutable);
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

// These are deliberately separate grammars. Recognizing source syntax does not
// resolve an imported macro or prove the contents of its compiler expansion.
fn nonempty_expressions(input: ParseStream) -> syn::Result<Parsed> {
    let expressions = syn::punctuated::Punctuated::<Expr, Token![,]>::parse_terminated(input)?;
    if expressions.is_empty() {
        return Err(input.error("expected at least one expression"));
    }
    Ok(Parsed {
        expressions: expressions.into_iter().collect(),
        ..Parsed::default()
    })
}

fn try_join(input: ParseStream) -> syn::Result<Parsed> {
    let fork = input.fork();
    if fork.parse::<syn::Ident>().is_ok_and(|id| id == "biased") && fork.peek(Token![;]) {
        input.parse::<syn::Ident>()?;
        input.parse::<Token![;]>()?;
    }
    nonempty_expressions(input)
}

fn metrics(input: ParseStream) -> syn::Result<Parsed> {
    let mut parsed = Parsed::default();
    // Bounded name/labels grammar used by the pinned backend. Directives and
    // ambiguous mixed forms fail; supporting them requires a new grammar rule.
    parsed.expressions.push(input.parse()?);
    while !input.is_empty() {
        input.parse::<Token![,]>()?;
        if input.is_empty() {
            break;
        }
        parsed.expressions.push(input.parse()?);
        if input.peek(Token![=>]) {
            input.parse::<Token![=>]>()?;
            parsed.expressions.push(input.parse()?);
        }
    }
    Ok(parsed)
}

pub fn expressions(node: &syn::Macro) -> syn::Result<Option<Parsed>> {
    let path = node.path.to_token_stream().to_string().replace(' ', "");
    let path = path.strip_prefix("::").unwrap_or(&path);
    if matches!(
        path,
        "tracing::trace"
            | "tracing::debug"
            | "tracing::info"
            | "tracing::warn"
            | "tracing::error"
            | "tracing::trace_span"
            | "tracing::debug_span"
            | "tracing::info_span"
            | "tracing::warn_span"
            | "tracing::error_span"
            | "tracing::event"
            | "tracing::span"
    ) {
        return tracing.parse2(node.tokens.clone()).map(Some);
    }
    if path == "tokio::select" {
        return select.parse2(node.tokens.clone()).map(Some);
    }
    if path == "tokio::try_join" {
        return try_join.parse2(node.tokens.clone()).map(Some);
    }
    if matches!(path, "anyhow::anyhow" | "anyhow" | "anyhow::bail" | "bail") {
        return nonempty_expressions.parse2(node.tokens.clone()).map(Some);
    }
    let metric = path.strip_prefix("metrics::").unwrap_or(path);
    if matches!(
        metric,
        "counter"
            | "gauge"
            | "histogram"
            | "describe_counter"
            | "describe_gauge"
            | "describe_histogram"
    ) {
        return metrics.parse2(node.tokens.clone()).map(Some);
    }
    // Retain the existing supported expression grammars, but don't assume an
    // arbitrary macro with expression-looking tokens has equivalent semantics.
    if matches!(
        path,
        "json"
            | "serde_json::json"
            | "vec"
            | "std::vec"
            | "format"
            | "format_args"
            | "println"
            | "eprintln"
            | "print"
            | "eprint"
            | "write"
            | "writeln"
            | "assert"
            | "assert_eq"
            | "assert_ne"
            | "debug_assert"
            | "debug_assert_eq"
            | "debug_assert_ne"
            | "panic"
            | "unreachable"
            | "todo"
            | "env"
            | "option_env"
            | "file"
            | "line"
            | "column"
            | "module_path"
            | "include_str"
            | "include_bytes"
            | "concat"
            | "matches"
    ) {
        return Ok(None);
    }
    Err(syn::Error::new_spanned(
        &node.path,
        "macro requires explicit grammar/expansion provenance; aliases are not resolved",
    ))
}

#[cfg(test)]
mod tests {
    use crate::Inventory;
    use syn::visit::Visit;

    fn inventory(source: &str, native: bool) -> Inventory {
        let mut result = Inventory {
            native,
            ..Inventory::default()
        };
        result.visit_file(&syn::parse_file(source).unwrap());
        result
    }

    #[test]
    fn tracing_values_keep_decisions_and_closure_ownership() {
        let result = inventory(
            r#"fn f() {
            tracing::error!(target: "app", parent: parent(),
                value = %if ready() { 1 } else { 0 },
                error = ?work()?, callback = ?(|| a() && b()), "failed");
        }"#,
            true,
        );
        assert!(result.errors.is_empty(), "{:?}", result.errors);
        assert_eq!(result.symbols.len(), 2);
        assert_eq!(result.symbols[0]["raw"]["if"], 1);
        assert_eq!(result.symbols[0]["raw"]["question_mark"], 1);
        assert_eq!(result.symbols[1]["raw"]["and_and"], 1);
        assert!(result.symbols[0]["raw"].get("and_and").is_none());
        assert_eq!(result.symbols[1]["span"][0], 4);
    }

    #[test]
    fn select_preserves_future_guard_handler_and_pattern_decisions() {
        let result = inventory(
            r#"async fn f() { tokio::select! {
            biased;
            Some(x) = async { if a() { 1 } else { 2 } }, if a() && b() => {
                let nested = || if x { 1 } else { 0 };
            }
            () = other() => work()?,
            else => { fallback(); }
        }}"#,
            true,
        );
        assert!(result.errors.is_empty(), "{:?}", result.errors);
        let raw = &result.symbols[0]["raw"];
        assert_eq!(raw["select_decisions"], 3);
        assert_eq!(raw["guards"], 1);
        assert_eq!(raw["if"], 1);
        assert_eq!(raw["and_and"], 1);
        assert_eq!(raw["question_mark"], 1);
        assert_eq!(result.symbols[1]["raw"]["if"], 1);
    }

    #[test]
    fn legacy_mode_still_rejects_new_grammars() {
        for source in [
            "fn f() { tracing::error!(value = %value); }",
            "async fn f() { tokio::select! { () = a => {}, () = b => {} } }",
        ] {
            assert!(!inventory(source, false).errors.is_empty());
            assert!(inventory(source, true).errors.is_empty());
        }
    }

    #[test]
    fn unsupported_or_incomplete_syntax_stays_blocked() {
        for body in [
            "tracing::error!(value = %)",
            "tokio::select! {}",
            "tokio::select! { else => {} }",
            "tokio::select! { () = a => 1 () = b => 2 }",
            "tokio::select! { () = a => {}, else => {}, () = b => {} }",
            "select! { () = a => {} }",
            "error!(value)",
            "unknown!(|| hidden())",
            "tokio::task_local! { static KEY: bool; }",
            "macro_rules! hidden { () => { fn generated() {} } }",
        ] {
            assert!(
                !inventory(&format!("fn f() {{ {body}; }}"), true)
                    .errors
                    .is_empty(),
                "{body}"
            );
        }
    }

    #[test]
    fn existing_expression_macros_keep_original_symbols() {
        let source = "fn f() { println!(\"{}\", work().map(|x| x || ready())); }";
        assert_eq!(
            inventory(source, true).symbols,
            inventory(source, false).symbols
        );
    }

    #[test]
    fn explicit_expression_grammars_visit_nested_code() {
        let result = inventory(
            r#"async fn f() {
            metrics::counter!("requests", "kind" => if a() { "a" } else { "b" });
            describe_counter!("requests", "description");
            anyhow::anyhow!("failed {}", work().map(|x| x && ready()));
            anyhow::bail!("failed {}", other());
            tokio::try_join!(biased; async { work()? }, async { other()? });
        }"#,
            true,
        );
        assert!(result.errors.is_empty(), "{:?}", result.errors);
        assert_eq!(result.symbols[0]["raw"]["if"], 1);
        assert_eq!(result.symbols[0]["raw"]["question_mark"], 2);
        assert_eq!(result.symbols[1]["raw"]["and_and"], 1);
    }

    #[test]
    fn expression_shape_is_not_a_fallback_certificate() {
        for body in [
            "unknown!(a(), b())",
            "anyhow::anyhow!()",
            "tokio::try_join!()",
            "tokio::try_join!(biased;)",
            "metrics::counter!()",
            "metrics::counter!(\"x\", \"key\" =>)",
            "other::counter!(\"x\")",
        ] {
            assert!(
                !inventory(&format!("fn f() {{ {body}; }}"), true)
                    .errors
                    .is_empty(),
                "{body}"
            );
        }
    }
}
