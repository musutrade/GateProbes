#!/usr/bin/env python3
"""Deterministic development complexity analyzer for the frozen fixture subset.

This is the locked in-repository analyzer (identity ``harness-gate-complexity``
0.1.1, MIT).  It deliberately uses only the Python standard library so the
quality-script CI job can rebuild every fixture without installing a third
party analyzer.  It is a development/CI tool and is never linked into the
Harness-Gate release binary.

The analyzer owns a token-level scanner for the Rust fixture subset frozen by
OpenSpec task 1.2:

* item ``fn`` definitions at file/module/trait/impl scope;
* ``if`` / ``if let`` / ``else if`` expressions and ordinary blocks;
* ``match`` expressions with counted arms and per-arm ``if`` guards;
* ``while`` / ``while let``, ``for``, and ``loop``;
* ``&&`` and ``||`` short-circuit operators and the ``?`` operator;
* closures with a braced body (``|...| { ... }``, ``|| { ... }``, and
  ``move |...| { ... }``);
* macro invocations whose token content is skipped and counted once;
* nested ``fn`` items, whose bodies are excluded from every symbol and counted
  by the enclosing function in ``nested_functions``.

Any construct outside this documented subset raises a descriptive error
instead of producing silent evidence.  The analyzer therefore fails closed
when the scanner would otherwise guess.  Rust never has to be installed: the
fixture source is analyzed lexically and the expectations are locked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

from quality_evidence import (
    KIND,
    RAW_KEYS,
    SCHEMA_VERSION,
    validate_evidence,
)


ANALYZER_NAME = "harness-gate-complexity"
ANALYZER_VERSION = "0.1.1"
RULE_NAME = "mccabe-rust-1"
RULE_VERSION = "1"
LICENSE = "MIT"

RAW_ZERO = dict.fromkeys(RAW_KEYS, 0)

ITEM_KEYWORDS = {
    "struct",
    "enum",
    "union",
    "use",
    "type",
    "static",
    "trait",
    "impl",
    "mod",
    "macro_rules",
}
FN_MODIFIERS = {"async", "unsafe", "extern", "default", "const"}
BINARY_OPERATORS = {
    "+",
    "-",
    "*",
    "/",
    "%",
    "==",
    "!=",
    "<",
    ">",
    "<=",
    ">=",
    "&&",
    "||",
    "&",
    "|",
    "^",
    "<<",
    ">>",
    "<<=",
    ">>=",
    "&=",
    "|=",
    "^=",
    "+=",
    "-=",
    "*=",
    "/=",
    "%=",
    "=",
}
MULTI_OPERATORS = (
    "...",
    "..=",
    "..",
    "::",
    "->",
    "=>",
    "&&",
    "||",
    "==",
    "!=",
    "<=",
    ">=",
    "+=",
    "-=",
    "*=",
    "/=",
    "%=",
    "<<=",
    ">>=",
    "<<",
    ">>",
    "&=",
    "|=",
    "^=",
)


class ComplexitySyntaxError(ValueError):
    """The source uses syntax outside the frozen analyzer subset."""


class Token:
    __slots__ = ("kind", "text", "line", "column", "offset")

    def __init__(self, kind: str, text: str, line: int, column: int, offset: int) -> None:
        self.kind = kind
        self.text = text
        self.line = line
        self.column = column
        self.offset = offset

    def __repr__(self) -> str:
        return f"Token({self.kind!r}, {self.text!r}, {self.line}:{self.column})"


class Tokenizer:
    """Line/column-preserving lexer for the Rust fixture subset."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.length = len(source)
        self.position = 0
        self.line = 1
        self.column = 1

    def _advance(self, count: int = 1) -> None:
        for _ in range(count):
            if self.position >= self.length:
                return
            if self.source[self.position] == "\n":
                self.line += 1
                self.column = 1
            else:
                self.column += 1
            self.position += 1

    def _peek(self, distance: int = 0) -> str:
        index = self.position + distance
        return self.source[index] if index < self.length else ""

    def _starts_with(self, value: str) -> bool:
        return self.source.startswith(value, self.position)

    def _skip_ws_and_comments(self) -> None:
        while self.position < self.length:
            char = self._peek()
            if char.isspace():
                self._advance()
                continue
            if self._starts_with("//"):
                while self.position < self.length and self._peek() != "\n":
                    self._advance()
                continue
            if self._starts_with("/*"):
                start_line, start_column = self.line, self.column
                self._advance(2)
                depth = 1
                while self.position < self.length and depth:
                    if self._starts_with("/*"):
                        depth += 1
                        self._advance(2)
                    elif self._starts_with("*/"):
                        depth -= 1
                        self._advance(2)
                    else:
                        self._advance()
                if depth:
                    raise ComplexitySyntaxError(
                        f"unterminated block comment at {start_line}:{start_column}"
                    )
                continue
            break

    def _token(self, kind: str, text: str) -> Token:
        token = Token(kind, text, self.line, self.column, self.position)
        self._advance(len(text))
        return token

    def _string_literal(self) -> Token:
        token = Token("literal", "", self.line, self.column, self.position)
        quote = self._peek()
        self._advance()
        while self.position < self.length:
            char = self._peek()
            if char == "\\":
                self._advance(2)
                continue
            self._advance()
            if char == quote:
                break
        else:
            raise ComplexitySyntaxError(
                f"unterminated string literal at {token.line}:{token.column}"
            )
        token.text = self.source[token.offset : self.position]
        return token

    def _raw_string_literal(self, hashes: int) -> Token:
        token = Token("literal", "", self.line, self.column, self.position)
        self._advance(2 + hashes)
        closing = '"' + "#" * hashes
        index = self.source.find(closing, self.position)
        if index < 0:
            raise ComplexitySyntaxError(
                f"unterminated raw string literal at {token.line}:{token.column}"
            )
        while self.position < index:
            self._advance()
        self._advance(1 + hashes)
        token.text = self.source[token.offset : self.position]
        return token

    def _char_literal(self) -> Token:
        token = Token("literal", "", self.line, self.column, self.position)
        self._advance()
        if self._peek() == "\\":
            self._advance()
            if self._peek() in ("x", "u"):
                while self._peek() and self._peek() not in ("'", "\n"):
                    self._advance()
            elif self._peek():
                self._advance()
        elif self._peek() and self._peek() not in ("'", "\n"):
            self._advance()
        if self._peek() != "'":
            raise ComplexitySyntaxError(
                f"unterminated char literal at {token.line}:{token.column}"
            )
        self._advance()
        token.text = self.source[token.offset : self.position]
        return token

    def _lifetime(self) -> Token:
        token = Token("lifetime", "", self.line, self.column, self.position)
        self._advance()
        while self._peek().isalnum() or self._peek() == "_":
            self._advance()
        token.text = self.source[token.offset : self.position]
        return token

    def _ident(self) -> Token:
        token = Token("name", "", self.line, self.column, self.position)
        while self._peek().isalnum() or self._peek() == "_":
            self._advance()
        token.text = self.source[token.offset : self.position]
        return token

    def _number(self) -> Token:
        token = Token("literal", "", self.line, self.column, self.position)
        if self._peek() in ("0",):
            if self._peek(1) in ("x", "X", "b", "B", "o", "O"):
                self._advance(2)
                while self._peek().isalnum() or self._peek() == "_":
                    self._advance()
                token.text = self.source[token.offset : self.position]
                return token
        while self._peek().isalnum() or self._peek() in (".", "_"):
            self._advance()
        token.text = self.source[token.offset : self.position]
        return token

    def _punct(self) -> Token:
        for operator in MULTI_OPERATORS:
            if self._starts_with(operator):
                return self._token("op", operator)
        return self._token("op", self._peek())

    def next(self) -> Token | None:
        self._skip_ws_and_comments()
        if self.position >= self.length:
            return None
        char = self._peek()
        if char.isalpha() or char == "_":
            return self._ident()
        if char.isdigit():
            return self._number()
        if char == '"':
            return self._string_literal()
        if char in ("b", "c", "r") and self._peek(1) in ('"', "'"):
            prefix = self._peek()
            token_start = self.position
            line, column = self.line, self.column
            self._advance()
            if prefix == "r" and self._peek() == '"':
                hashes = 0
                while self._peek() == "#":
                    hashes += 1
                    self._advance()
                if self._peek() == '"':
                    token = self._raw_string_literal(hashes)
                    token.line, token.column = line, column
                    token.offset = token_start
                    return token
            if prefix in ("b", "c") and self._peek() == "'":
                token = self._char_literal()
                token.text = self.source[token_start : self.position]
                token.line, token.column = line, column
                token.offset = token_start
                return token
            # Fall through to a normal identifier/punctuation token.
            self.position = token_start
            self.line, self.column = line, column
            return self._ident() if char in ("b", "c", "r") else self._punct()
        if char == "'":
            if self._peek(1) == "\\":
                return self._char_literal()
            following = self._peek(1)
            if following.isalpha() or following == "_":
                return self._lifetime()
            if following and self._peek(2) == "'":
                return self._char_literal()
            return self._token("op", "'")
        return self._punct()

    def tokenize(self) -> list[Token]:
        tokens: list[Token] = []
        while True:
            token = self.next()
            if token is None:
                return tokens
            tokens.append(token)


class ComplexityAnalyzer:
    """Scans one Rust fixture and builds versioned complexity evidence."""

    def __init__(self, source_text: str, source_path: str) -> None:
        self.source_text = source_text
        self.source_path = source_path
        self.source_bytes = len(source_text.encode("utf-8"))
        self.source_sha256 = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
        self.tokens = Tokenizer(source_text).tokenize()
        self.position = 0
        self.module_path: list[str] = []
        self.symbols: list[dict[str, Any]] = []
        self._contexts: list[dict[str, Any] | None] = []

    # -- token helpers -----------------------------------------------------
    @property
    def current(self) -> Token | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _peek(self, distance: int = 1) -> Token | None:
        index = self.position + distance
        return self.tokens[index] if index < len(self.tokens) else None

    def _consume(self) -> Token:
        if self.current is None:
            raise ComplexitySyntaxError("unexpected end of input")
        token = self.current
        self.position += 1
        return token

    def _expect(self, text: str) -> Token:
        token = self.current
        if token is None or token.text != text:
            found = token.text if token is not None else "end of input"
            raise ComplexitySyntaxError(f"expected {text!r}, found {found!r}")
        return self._consume()

    def _expect_name(self) -> Token:
        token = self.current
        if token is None or token.kind != "name":
            found = token.text if token is not None else "end of input"
            raise ComplexitySyntaxError(f"expected an identifier, found {found!r}")
        return self._consume()

    def _error(self, message: str) -> None:
        token = self.current
        location = f"{token.line}:{token.column}" if token is not None else "end of input"
        raise ComplexitySyntaxError(f"{self.source_path}:{location}: {message}")

    def _skip_balanced(self, opening: str, closing: str) -> None:
        """Consume one balanced delimiter group starting at ``opening``."""
        self._expect(opening)
        depth = 1
        while depth:
            token = self.current
            if token is None:
                self._error(f"unterminated {opening!r} group")
            if token.text == opening:
                depth += 1
            elif token.text == closing:
                depth -= 1
            self._consume()

    def _skip_attributes(self) -> None:
        while self.current is not None and self.current.text == "#":
            self._consume()
            self._skip_balanced("[", "]")

    # -- counting ----------------------------------------------------------
    def _count(self, key: str, amount: int = 1) -> None:
        if self._contexts and self._contexts[-1] is None:
            # Constructs inside a nested fn body are excluded from every
            # emitted symbol; only the nested_functions counter may record
            # that the nested item existed.
            return
        for context in reversed(self._contexts):
            if context is not None:
                context["raw"][key] += amount
                return

    def _count_source_symbol(self, raw: dict[str, Any], key: str) -> None:
        raw[key] += 1

    def _symbol_source(self) -> dict[str, str]:
        return {"path": self.source_path, "sha256": self.source_sha256}

    def _qualified_name(self, name: str) -> str:
        return "::".join([*self.module_path, name])

    def _make_function(self, start: Token, name: str) -> dict[str, Any]:
        symbol = {
            "kind": "function",
            "qualified_name": self._qualified_name(name),
            "source": self._symbol_source(),
            "span": {
                "start_line": start.line,
                "start_column": start.column,
                "end_line": None,
                "end_column": None,
            },
            "metrics": {"cyclomatic_complexity": None},
            "raw": dict(RAW_ZERO),
        }
        self.symbols.append(symbol)
        return symbol

    def _make_closure(self, start: Token, parent: dict[str, Any]) -> dict[str, Any]:
        ordinal = parent["raw"]["closures"] + 1
        symbol = {
            "kind": "closure",
            "qualified_name": f"{parent['qualified_name']}::closure_{ordinal}",
            "source": self._symbol_source(),
            "span": {
                "start_line": start.line,
                "start_column": start.column,
                "end_line": None,
                "end_column": None,
            },
            "metrics": {"cyclomatic_complexity": None},
            "raw": dict(RAW_ZERO),
        }
        self.symbols.append(symbol)
        return symbol

    def _finish_symbol(self, symbol: dict[str, Any], end: Token) -> None:
        symbol["span"]["end_line"] = end.line
        symbol["span"]["end_column"] = end.column
        arms = symbol["raw"]["match_arms"]
        matches = symbol["raw"]["match"]
        symbol["metrics"]["cyclomatic_complexity"] = (
            1
            + symbol["raw"]["if"]
            + symbol["raw"]["guards"]
            + symbol["raw"]["while"]
            + symbol["raw"]["for"]
            + symbol["raw"]["loop"]
            + max(0, arms - matches)
            + symbol["raw"]["and_and"]
            + symbol["raw"]["or_or"]
            + symbol["raw"]["question_mark"]
        )

    # -- items -------------------------------------------------------------
    def _item_after_prefix(self) -> Token | None:
        """Return the keyword token of an item after attributes/modifiers."""
        index = self.position
        while True:
            token = self.tokens[index] if index < len(self.tokens) else None
            if token is None:
                return None
            if token.text == "#":
                index += 1
                if index >= len(self.tokens):
                    return None
                index = self._skip_balanced_from(index, "[", "]")
                continue
            if token.text == "pub":
                index += 1
                if index < len(self.tokens) and self.tokens[index].text == "(":
                    index = self._skip_balanced_from(index, "(", ")")
                continue
            if token.text in FN_MODIFIERS:
                index += 1
                if token.text == "extern":
                    if index < len(self.tokens) and self.tokens[index].kind == "literal":
                        index += 1
                continue
            return token

    def _skip_balanced_from(self, index: int, opening: str, closing: str) -> int:
        """Return the next index after a balanced group beginning at ``index``."""
        if index >= len(self.tokens) or self.tokens[index].text != opening:
            return index
        depth = 0
        while index < len(self.tokens):
            text = self.tokens[index].text
            if text == opening:
                depth += 1
            elif text == closing:
                depth -= 1
                if depth == 0:
                    return index + 1
            index += 1
        self._error("unterminated delimiter group")

    def parse(self) -> None:
        while self.current is not None:
            self._parse_item()

    def _parse_item(self, prefix: Token | None = None) -> None:
        self._skip_attributes()
        token = self.current
        if token is None:
            return
        text = token.text
        if text == "pub":
            self._consume()
            if self.current is not None and self.current.text == "(":
                self._skip_balanced("(", ")")
            self._parse_item(prefix or token)
            return
        if text in FN_MODIFIERS and self._looks_like_fn_item():
            self._consume()
            if text == "extern" and self.current is not None and self.current.kind == "literal":
                self._consume()
            self._parse_item(prefix or token)
            return
        if text == "fn":
            self._parse_function(prefix=prefix)
            return
        if text == "mod":
            self._parse_module()
            return
        if text in ("trait", "impl"):
            self._parse_named_body_item()
            return
        if text in ITEM_KEYWORDS:
            self._skip_generic_item()
            return
        self._error(f"expected an item, found {text!r}")

    def _parse_module(self) -> None:
        self._expect("mod")
        name = self._expect_name().text
        if self.current is not None and self.current.text == ";":
            self._consume()
            return
        self._expect("{")
        self.module_path.append(name)
        while self.current is not None and self.current.text != "}":
            self._parse_item()
        self._expect("}")
        self.module_path.pop()

    def _type_qualifier(self, start_index: int) -> str | None:
        """Best-effort type name used to qualify methods inside impl/trait."""
        index = start_index
        depth = 0
        candidate: str | None = None
        after_for = False
        while index < len(self.tokens):
            token = self.tokens[index]
            text = token.text
            if depth == 0 and text == "{":
                break
            if depth == 0 and text == ";":
                break
            if token.kind == "name" and depth == 0:
                if after_for or candidate is None:
                    candidate = text
                if text == "for":
                    after_for = True
                index += 1
                continue
            if depth == 0 and text in ("(", "[", "<"):
                depth += 1
            elif depth and text in (")", "]", ">"):
                depth -= 1
            index += 1
        return candidate

    def _parse_named_body_item(self) -> None:
        keyword = self._consume().text
        name = self._type_qualifier(self.position)
        while self.current is not None:
            token = self.current
            if token.text == "{":
                break
            if token.text == ";":
                return
            if token.text in ("(", "[", "<", "{"):
                self._skip_balanced(token.text, {"(": ")", "[": "]", "<": ">", "{": "}"}[token.text])
                continue
            if token.text in (")", "]", ">"):
                self._error(f"unbalanced {token.text!r} in {keyword} header")
            self._consume()
        if self.current is None or self.current.text != "{":
            return
        self._expect("{")
        previous = self.module_path[:]
        if keyword == "impl" and name:
            self.module_path.append(name)
        elif keyword == "trait" and name:
            self.module_path.append(name)
        while self.current is not None and self.current.text != "}":
            self._parse_item()
        self._expect("}")
        self.module_path = previous

    def _skip_generic_item(self) -> None:
        token = self.current
        if token is None:
            return
        if token.text == "macro_rules":
            while self.current is not None:
                if self.current.text == "{":
                    self._skip_balanced("{", "}")
                    return
                if self.current.text == ";":
                    self._consume()
                    return
                self._consume()
            self._error("unterminated macro_rules definition")
        self._consume()
        depth = 0
        while self.current is not None:
            text = self.current.text
            if text in ("(", "[", "{"):
                depth += 1
            elif text in (")", "]", "}"):
                if depth == 0:
                    return
                depth -= 1
            elif text == ";" and depth == 0:
                self._consume()
                return
            self._consume()
        self._error("unterminated item")

    # -- functions ---------------------------------------------------------
    def _parse_function(self, *, nested: bool = False, prefix: Token | None = None) -> None:
        start = prefix or self.current
        self._expect("fn")
        name = self._expect_name().text
        if self.current is not None and self.current.text == "<":
            self._skip_balanced("<", ">")
        if self.current is not None and self.current.text == "(":
            self._skip_balanced("(", ")")
        if self.current is not None and self.current.text == "->":
            self._consume()
            self._consume_type_header_tokens()
        if self.current is not None and self.current.text == ";":
            self._consume()
            return
        if self.current is None or self.current.text != "{":
            self._error(f"expected fn body for {name!r}")
        if nested:
            self._count("nested_functions")
            # A nested fn is a separate item, not part of the enclosing
            # function's control flow.  Its whole body is skipped so that no
            # construct inside it is counted for or attributed to the outer
            # symbol (and no nested closure symbol is emitted).
            self._skip_balanced("{", "}")
            return
        symbol = self._make_function(start, name)
        self._contexts.append(symbol)
        self._expect("{")
        self._parse_body()
        self._contexts.pop()
        self._finish_symbol(symbol, self.tokens[self.position - 1])

    def _consume_type_header_tokens(self) -> None:
        """Consume a return/where type header up to a body brace or semicolon."""
        stack: list[str] = []
        pairs = {"(": ")", "[": "]", "{": "}"}
        while self.current is not None:
            text = self.current.text
            if not stack and text in ("{", ";"):
                return
            if text in pairs:
                stack.append(pairs[text])
            elif stack and text == stack[-1]:
                stack.pop()
            self._consume()
        self._error("unterminated fn signature")

    def _looks_like_fn_item(self) -> bool:
        token = self._item_after_prefix()
        return token is not None and token.text == "fn"

    def _parse_body(self) -> None:
        """Parse a brace body; caller has already consumed the opening brace."""
        while self.current is not None and self.current.text != "}":
            self._parse_statement()
        self._expect("}")

    def _parse_statement(self) -> None:
        if self.current is None:
            return
        if self.current.text == ";":
            self._consume()
            return
        if self.current.text == "#":
            self._skip_attributes()
        if self._looks_like_fn_item():
            # Skip modifiers, then parse the nested fn with fn keyword.
            while self.current is not None and self.current.text in FN_MODIFIERS:
                if self.current.text == "extern":
                    self._consume()
                    if self.current is not None and self.current.kind == "literal":
                        self._consume()
                    continue
                self._consume()
            if self.current is not None and self.current.text == "pub":
                self._consume()
                if self.current is not None and self.current.text == "(":
                    self._skip_balanced("(", ")")
            self._parse_function(nested=True)
            return
        token = self.current
        if token.text == "let":
            self._parse_let()
            return
        if token.text in ITEM_KEYWORDS and token.text not in ("trait", "impl", "mod", "macro_rules"):
            self._skip_generic_item()
            return
        if token.text == "macro_rules":
            self._skip_generic_item()
            return
        self._parse_expression(allow_block_after_path=True)
        if self.current is not None and self.current.text == ";":
            self._consume()

    def _parse_let(self) -> None:
        self._expect("let")
        depth = 0
        while self.current is not None:
            text = self.current.text
            if text in ("(", "[", "{"):
                depth += 1
            elif text in (")", "]", "}"):
                if depth == 0:
                    break
                depth -= 1
            elif text == "=" and depth == 0:
                self._consume()
                self._parse_expression(allow_block_after_path=True)
                return
            self._consume()
        self._error("expected '=' in let binding")

    # -- expressions -------------------------------------------------------
    def _parse_expression(
        self,
        *,
        allow_block_after_path: bool = False,
        stop_tokens: set[str] | None = None,
    ) -> None:
        stops = stop_tokens or set()
        self._parse_prefix_or_atom(allow_block_after_path=allow_block_after_path)
        while self.current is not None:
            token = self.current
            text = token.text
            if text in stops or text in (";", ",", ")", "]", "}", "=>", "{") and text not in stops:
                if text == "{" and allow_block_after_path and False:
                    self._parse_struct_literal_fields()
                    continue
                break
            if text == "?":
                self._consume()
                self._count("question_mark")
                continue
            if text == ".":
                self._consume()
                if self.current is not None and self.current.text == "await":
                    self._consume()
                elif self.current is not None and self.current.kind == "name":
                    self._consume()
                continue
            if text == "::":
                self._consume()
                if self.current is not None and self.current.text == "<":
                    self._skip_balanced("<", ">")
                elif self.current is not None and self.current.kind == "name":
                    name = self._consume()
                    if self.current is not None and self.current.text == "!":
                        self._parse_macro_invocation(name)
                continue
            if text in ("(", "["):
                self._parse_delimited_group(text)
                continue
            if text == "as":
                self._consume()
                self._consume_type_header_tokens()
                continue
            if text in BINARY_OPERATORS:
                self._consume()
                if text == "&&":
                    self._count("and_and")
                elif text == "||":
                    self._count("or_or")
                self._parse_prefix_or_atom(allow_block_after_path=allow_block_after_path)
                continue
            break

    def _parse_delimited_group(self, opening: str) -> None:
        closing = {"(": ")", "[": "]"}[opening]
        self._expect(opening)
        while self.current is not None and self.current.text != closing:
            if self.current.text == ",":
                self._consume()
                continue
            self._parse_expression(allow_block_after_path=True)
        self._expect(closing)

    def _parse_macro_invocation(self, name: Token) -> None:
        self._count("macro_invocations_skipped")
        self._expect("!")
        if self.current is None or self.current.text not in ("(", "[", "{"):
            self._error(f"macro {name.text!r} is not followed by a delimiter group")
        opening = self._consume().text
        closing = {"(": ")", "[": "]", "{": "}"}[opening]
        self._contexts.append(None)
        depth = 1
        while depth:
            token = self.current
            if token is None:
                self._error(f"unterminated macro body for {name.text!r}")
            if token.text == opening:
                depth += 1
            elif token.text == closing:
                depth -= 1
            self._consume()
        self._contexts.pop()

    def _parse_prefix_or_atom(self, *, allow_block_after_path: bool) -> None:
        token = self.current
        if token is None:
            self._error("expected an expression")
        text = token.text
        if text in ("!", "-", "*", "&", "&&"):
            self._consume()
            if text == "&&":
                self._count("and_and")
            self._parse_prefix_or_atom(allow_block_after_path=allow_block_after_path)
            return
        if text in ("move", "async"):
            self._consume()
            if self.current is not None and self.current.text in ("|", "||"):
                self._parse_closure(token)
                return
            if self.current is not None and self.current.text == "move":
                self._consume()
                if self.current is not None and self.current.text in ("|", "||"):
                    self._parse_closure(token)
                    return
            self._parse_prefix_or_atom(allow_block_after_path=allow_block_after_path)
            return
        if text in ("return", "break", "continue"):
            self._consume()
            return
        if text == "if":
            self._parse_if()
            return
        if text == "match":
            self._parse_match()
            return
        if text == "while":
            self._parse_while()
            return
        if text == "for":
            self._parse_for()
            return
        if text == "loop":
            self._consume()
            self._count("loop")
            self._expect("{")
            self._parse_body()
            return
        if text == "unsafe":
            self._consume()
            if self.current is not None and self.current.text == "{":
                self._expect("{")
                self._parse_body()
            return
        if text == "|":
            self._parse_closure(token)
            return
        if text == "||":
            self._parse_closure(token)
            return
        if text == "{":
            self._expect("{")
            self._parse_body()
            return
        if text == "(":
            self._parse_delimited_group("(")
            return
        if text == "[":
            self._parse_delimited_group("[")
            return
        if token.kind in ("name", "literal", "lifetime"):
            consumed = self._consume()
            if self.current is not None and self.current.text == "!" and token.kind == "name":
                self._parse_macro_invocation(consumed)
                return
            if self.current is not None and self.current.text == "{" and allow_block_after_path:
                self._parse_struct_literal_fields()
                return
            return
        self._error(f"unsupported expression token {text!r}")

    def _parse_struct_literal_fields(self) -> None:
        self._expect("{")
        while self.current is not None and self.current.text != "}":
            if self.current.text == ",":
                self._consume()
                continue
            self._parse_expression(allow_block_after_path=True)
            if self.current is not None and self.current.text == ":":
                self._consume()
                if self.current is not None and self.current.text != "," and self.current.text != "}":
                    self._parse_expression(allow_block_after_path=True)
        self._expect("}")

    def _parse_condition(self) -> None:
        if self.current is not None and self.current.text == "let":
            self._expect("let")
            depth = 0
            while self.current is not None:
                text = self.current.text
                if text in ("(", "[", "{"):
                    depth += 1
                elif text in (")", "]", "}"):
                    if depth == 0:
                        break
                    depth -= 1
                elif text == "=" and depth == 0:
                    self._consume()
                    self._parse_expression(stop_tokens={"{", ";"})
                    return
                self._consume()
            self._error("expected '=' in if/while let condition")
        self._parse_expression(stop_tokens={"{", ";"})

    def _parse_if(self) -> None:
        self._expect("if")
        self._count("if")
        self._parse_condition()
        self._expect("{")
        self._parse_body()
        if self.current is not None and self.current.text == "else":
            self._consume()
            if self.current is not None and self.current.text == "if":
                self._parse_if()
                return
            self._expect("{")
            self._parse_body()

    def _parse_while(self) -> None:
        self._expect("while")
        self._count("while")
        self._parse_condition()
        self._expect("{")
        self._parse_body()

    def _parse_for(self) -> None:
        self._expect("for")
        self._count("for")
        depth = 0
        while self.current is not None:
            text = self.current.text
            if text in ("(", "[", "{"):
                depth += 1
            elif text in (")", "]", "}"):
                if depth == 0:
                    break
                depth -= 1
            elif text == "in" and depth == 0:
                self._consume()
                self._parse_expression(stop_tokens={"{", ";"})
                self._expect("{")
                self._parse_body()
                return
            self._consume()
        self._error("expected 'in' in for loop")

    def _parse_closure(self, start: Token) -> None:
        parent = self._active_symbol()
        if parent is None:
            self._error("closure appears outside an analyzed function body")
        if self.current is not None and self.current.text == "||":
            self._consume()
        else:
            self._expect("|")
            depth = 0
            while self.current is not None:
                text = self.current.text
                if text == "|" and depth == 0:
                    self._consume()
                    break
                if text in ("(", "[", "{"):
                    depth += 1
                elif text in (")", "]", "}"):
                    if depth == 0:
                        self._error("unbalanced closure parameter delimiter")
                    depth -= 1
                self._consume()
            else:
                self._error("unterminated closure parameters")
        if self.current is None or self.current.text != "{":
            self._error(
                "non-braced closure body is outside the frozen syntax subset "
                "(braced closures only)"
            )
        closure = self._make_closure(start, parent)
        self._count("closures")
        self._contexts.append(closure)
        self._expect("{")
        self._parse_body()
        self._contexts.pop()
        self._finish_symbol(closure, self.tokens[self.position - 1])

    def _active_symbol(self) -> dict[str, Any] | None:
        for context in reversed(self._contexts):
            if context is not None:
                return context
        return None

    # -- match arms --------------------------------------------------------
    def _parse_match(self) -> None:
        self._expect("match")
        self._count("match")
        self._parse_expression(stop_tokens={"{", ";"})
        self._expect("{")
        while self.current is not None and self.current.text != "}":
            self._parse_match_arm()
        self._expect("}")

    def _parse_match_arm(self) -> None:
        depth = 0
        seen_guard = False
        while self.current is not None:
            token = self.current
            text = token.text
            if text in ("(", "[", "{"):
                depth += 1
                self._consume()
                continue
            if text in (")", "]", "}"):
                if depth == 0:
                    self._error("unbalanced match pattern delimiter")
                depth -= 1
                self._consume()
                continue
            if depth == 0 and text == "if" and not seen_guard:
                seen_guard = True
                self._count("guards")
                self._consume()
                self._parse_expression(stop_tokens={"=>"})
                continue
            if depth == 0 and text == "=>":
                self._consume()
                break
            self._consume()
        else:
            self._error("match arm has no '=>'")
        self._count("match_arms")
        if self.current is not None and self.current.text == "{":
            self._expect("{")
            self._parse_body()
        elif self.current is not None and self.current.text != "," and self.current.text != "}":
            self._parse_expression(stop_tokens={",", "}"})
        if self.current is not None and self.current.text == ",":
            self._consume()


def _git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path.cwd(),
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def analyze_source(source_text: str, source_path: str) -> dict[str, Any]:
    analyzer = ComplexityAnalyzer(source_text, source_path)
    analyzer.parse()
    series = {
        "analyzer": {
            "name": ANALYZER_NAME,
            "version": ANALYZER_VERSION,
            "license": LICENSE,
        },
        "rule": {
            "name": RULE_NAME,
            "version": RULE_VERSION,
            "license": LICENSE,
        },
        "toolchain": {
            "target": platform.machine(),
            "python": platform.python_version(),
        },
        "source": {
            "path": source_path,
            "sha256": analyzer.source_sha256,
            "bytes": analyzer.source_bytes,
            "language": "rust",
        },
    }
    record = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "series": series,
        "symbols": analyzer.symbols,
    }
    for symbol in record["symbols"]:
        symbol["id"] = (
            f"{source_path}::{symbol['kind']}::{symbol['qualified_name']}"
            f"@{symbol['span']['start_line']}:{symbol['span']['start_column']}"
            f":{analyzer.source_sha256[:12]}"
        )
    commit = _git_commit()
    if commit:
        record["commit"] = commit
    return record


def write_evidence(record: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")


def _source_relative(source: Path, source_root: Path) -> str:
    try:
        return source.resolve().relative_to(source_root.resolve()).as_posix()
    except ValueError as exc:
        raise ComplexitySyntaxError(
            f"{source} is not inside source root {source_root}"
        ) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a Rust fixture with the locked complexity rules."
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        source_text = args.source.read_text(encoding="utf-8")
        source_path = _source_relative(args.source, args.source_root)
        record = analyze_source(source_text, source_path)
        validate_evidence(
            record,
            expected_source_sha256=record["series"]["source"]["sha256"],
            expected_source_bytes=record["series"]["source"]["bytes"],
        )
        if args.output:
            write_evidence(record, args.output)
            print(f"wrote {args.output}")
        else:
            print(json.dumps(record, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, ComplexitySyntaxError) as exc:
        print(f"complexity analyzer failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
