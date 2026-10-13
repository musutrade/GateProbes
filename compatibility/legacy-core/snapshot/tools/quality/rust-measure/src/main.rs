//! Development-only AST inventory. Never linked into the product.
mod configuration;
mod native;

use proc_macro2::Span;
use quote::ToTokens;
use serde_json::{json, Value};
use std::{collections::BTreeMap, env, fs};
use syn::{
    parse::Parser,
    spanned::Spanned,
    visit::{self, Visit},
    Expr, Token,
};

fn json_value(input: syn::parse::ParseStream, expressions: &mut Vec<Expr>) -> syn::Result<()> {
    if input.peek(syn::token::Brace) {
        let content;
        syn::braced!(content in input);
        while !content.is_empty() {
            expressions.push(content.parse()?);
            content.parse::<Token![:]>()?;
            json_value(&content, expressions)?;
            if !content.is_empty() {
                content.parse::<Token![,]>()?;
            }
        }
    } else if input.peek(syn::token::Bracket) {
        let content;
        syn::bracketed!(content in input);
        while !content.is_empty() {
            json_value(&content, expressions)?;
            if !content.is_empty() {
                content.parse::<Token![,]>()?;
            }
        }
    } else {
        expressions.push(input.parse()?);
    }
    Ok(())
}

fn span(s: Span) -> Value {
    json!([
        s.start().line,
        s.start().column + 1,
        s.end().line,
        s.end().column + 1
    ])
}

#[derive(Default)]
struct Inventory {
    symbols: Vec<Value>,
    stack: Vec<usize>,
    modules: Vec<String>,
    errors: Vec<String>,
    test_depth: usize,
    native: bool,
    provenance: Vec<Value>,
}

impl Inventory {
    fn count(&mut self, key: &str, n: u64) {
        if let Some(i) = self.stack.last() {
            let raw = self.symbols[*i]["raw"].as_object_mut().unwrap();
            let old = raw.get(key).and_then(Value::as_u64).unwrap_or(0);
            raw.insert(key.into(), json!(old + n));
        }
    }
    fn enter(&mut self, name: String, kind: &str, location: Span, body: Span, syntax: String) {
        let parent = self
            .stack
            .last()
            .map(|i| self.symbols[*i]["name"].as_str().unwrap().to_owned());
        let prefix = parent.unwrap_or_else(|| self.modules.join("::"));
        let name = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}::{name}")
        };
        self.stack.push(self.symbols.len());
        self.symbols.push(json!({"name": name, "kind": kind, "span": span(location),
            "body": span(body), "syntax": syntax, "test": self.test_depth > 0, "raw": BTreeMap::<String,u64>::new()}));
    }
    fn attributes_test(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|a| {
            a.path().is_ident("test")
                || (a.path().is_ident("cfg")
                    && a.parse_args::<syn::Path>()
                        .is_ok_and(|p| p.is_ident("test")))
        })
    }
}

impl<'ast> Visit<'ast> for Inventory {
    fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
        if self.native {
            self.provenance
                .push(json!({"kind": "attribute", "span": span(node.span()),
                "syntax": node.to_token_stream().to_string(), "compiler_resolved": false}));
        } else if node.path().is_ident("cfg") || node.path().is_ident("cfg_attr") {
            self.errors.push(format!(
                "unsupported conditional attribute in macro at {:?}",
                node.span().start()
            ));
        }
        visit::visit_attribute(self, node);
    }
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let test = Self::attributes_test(&node.attrs);
        self.test_depth += usize::from(test);
        self.modules.push(node.ident.to_string());
        visit::visit_item_mod(self, node);
        self.modules.pop();
        self.test_depth -= usize::from(test);
    }
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        // The source span also identifies multiple impls of the same type.
        let name = match node.self_ty.as_ref() {
            syn::Type::Path(p) => p.path.segments.last().unwrap().ident.to_string(),
            _ => {
                self.errors.push("unsupported impl self type".into());
                return;
            }
        };
        self.modules.push(name);
        visit::visit_item_impl(self, node);
        self.modules.pop();
    }
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        for attribute in &node.attrs {
            self.visit_attribute(attribute);
        }
        self.count("nested_functions", 1);
        let test = Self::attributes_test(&node.attrs);
        self.test_depth += usize::from(test);
        self.enter(
            node.sig.ident.to_string(),
            "function",
            node.span(),
            node.block.span(),
            node.to_token_stream().to_string(),
        );
        self.visit_block(&node.block);
        self.stack.pop();
        self.test_depth -= usize::from(test);
    }
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        for attribute in &node.attrs {
            self.visit_attribute(attribute);
        }
        self.enter(
            node.sig.ident.to_string(),
            "function",
            node.span(),
            node.block.span(),
            node.to_token_stream().to_string(),
        );
        self.visit_block(&node.block);
        self.stack.pop();
    }
    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        for attribute in &node.attrs {
            self.visit_attribute(attribute);
        }
        if let Some(body) = &node.default {
            self.enter(
                node.sig.ident.to_string(),
                "function",
                node.span(),
                body.span(),
                node.to_token_stream().to_string(),
            );
            self.visit_block(body);
            self.stack.pop();
        }
    }
    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.count("closures", 1);
        let s = node.span().start();
        self.enter(
            format!("closure_{}_{}", s.line, s.column + 1),
            "closure",
            node.span(),
            node.body.span(),
            node.to_token_stream().to_string(),
        );
        self.visit_expr(&node.body);
        self.stack.pop();
    }
    fn visit_expr(&mut self, node: &'ast Expr) {
        match node {
            Expr::If(_) => self.count("if", 1),
            Expr::While(_) => self.count("while", 1),
            Expr::ForLoop(_) => self.count("for", 1),
            Expr::Loop(_) => self.count("loop", 1),
            Expr::Try(_) => self.count("question_mark", 1),
            Expr::Binary(b) => match b.op {
                syn::BinOp::And(_) => self.count("and_and", 1),
                syn::BinOp::Or(_) => self.count("or_or", 1),
                _ => (),
            },
            Expr::Match(m) => {
                self.count("match", 1);
                self.count("match_arms", m.arms.len() as u64);
                self.count("match_decisions", m.arms.len().saturating_sub(1) as u64);
                self.count(
                    "guards",
                    m.arms.iter().filter(|a| a.guard.is_some()).count() as u64,
                );
            }
            _ => (),
        }
        visit::visit_expr(self, node);
    }
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if node.init.as_ref().is_some_and(|i| i.diverge.is_some()) {
            self.count("if", 1);
        }
        visit::visit_local(self, node);
    }
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if self.native {
            self.provenance
                .push(json!({"kind": "macro", "span": span(node.span()),
                "path": node.path.to_token_stream().to_string(),
                "syntax": node.tokens.to_string(), "compiler_resolved": false}));
            match native::expressions(node) {
                Ok(Some(parsed)) => {
                    self.count("select_decisions", parsed.decisions);
                    self.count("guards", parsed.guards);
                    for expr in parsed.expressions {
                        self.visit_expr(&expr);
                    }
                    return;
                }
                Ok(None) => (),
                Err(error) => {
                    if self.test_depth == 0 {
                        self.errors.push(format!(
                            "unsupported native macro {} at {:?}: {error}",
                            node.path.to_token_stream(),
                            node.span().start()
                        ));
                    }
                    return;
                }
            }
        }
        // Parse source expressions inside macros, including their closures.
        // Unknown grammars fail closed instead of silently dropping symbols.
        let args = if node.path.segments.last().unwrap().ident == "json" {
            (|input: syn::parse::ParseStream| {
                let mut expressions = Vec::new();
                json_value(input, &mut expressions)?;
                Ok(expressions)
            })
            .parse2(node.tokens.clone())
        } else if node.path.segments.last().unwrap().ident == "vec" {
            (|input: syn::parse::ParseStream| {
                let value: Expr = input.parse()?;
                input.parse::<Token![;]>()?;
                let length: Expr = input.parse()?;
                Ok(vec![value, length])
            })
            .parse2(node.tokens.clone())
            .or_else(|_| {
                syn::punctuated::Punctuated::<Expr, Token![,]>::parse_terminated
                    .parse2(node.tokens.clone())
                    .map(|args| args.into_iter().collect())
            })
        } else {
            syn::punctuated::Punctuated::<Expr, Token![,]>::parse_terminated
                .parse2(node.tokens.clone())
                .map(|args| args.into_iter().collect())
        };
        match args {
            Ok(args) => {
                for expr in args {
                    self.visit_expr(&expr);
                }
            }
            Err(_) if self.test_depth > 0 => (),
            Err(e) => self.errors.push(format!(
                "unsupported production macro {} at {:?}: {e}",
                node.path.segments.last().unwrap().ident,
                node.span().start()
            )),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let first = args.next().ok_or("expected source path")?;
    let native = first == "--native-inventory";
    let path = if native {
        args.next().ok_or("expected native source path")?
    } else {
        first
    };
    let configured = args.next();
    if configured.as_deref().is_some_and(|a| a != "--target-cfg") || args.next().is_some() {
        return Err("unexpected argument".into());
    }
    if path == "--demangle" {
        let names: Vec<String> = serde_json::from_reader(std::io::stdin())?;
        let names: Vec<String> = names
            .iter()
            .map(|n| format!("{:#}", rustc_demangle::demangle(n)))
            .collect();
        println!("{}", json!(names));
        return Ok(());
    }
    let source = fs::read_to_string(path)?;
    let mut ast = syn::parse_file(&source)?;
    let mut excluded = Vec::new();
    let mut target_configuration = Value::Null;
    if !native {
        if configured.is_none() {
            return Err("production inventory requires --target-cfg on stdin".into());
        }
        target_configuration = serde_json::from_reader(std::io::stdin())?;
        let values = target_configuration["cfg"]
            .as_array()
            .ok_or("missing compiler cfg")?
            .iter()
            .map(|v| v.as_str().map(String::from).ok_or("invalid compiler cfg"))
            .collect::<Result<Vec<_>, _>>()?;
        let mut filter = configuration::Configuration {
            values,
            excluded: vec![],
            errors: vec![],
        };
        syn::visit_mut::VisitMut::visit_file_mut(&mut filter, &mut ast);
        if !filter.errors.is_empty() {
            return Err(filter.errors.join("\n").into());
        }
        excluded = filter.excluded;
    }
    let mut inventory = Inventory {
        native,
        ..Inventory::default()
    };
    inventory.visit_file(&ast);
    if !inventory.errors.is_empty() {
        return Err(inventory.errors.join("\n").into());
    }
    if native {
        println!(
            "{}",
            json!({"analyzer": "harness-gate-rust-native-inventory",
            "version": "0.2.0", "rule": "source-decisions-native-2",
            "certified_llvm_mapping": false, "symbols": inventory.symbols,
            "provenance": inventory.provenance})
        );
        return Ok(());
    }
    println!(
        "{}",
        json!({"analyzer": "harness-gate-rust-measure", "version": "0.3.1", "rule": "mccabe-rust-3", "configuration": target_configuration, "excluded": excluded, "symbols": inventory.symbols})
    );
    Ok(())
}
