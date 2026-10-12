"use strict";
// Measurement only. No threshold, debt, exception or release decision lives here.
const ts = require("typescript");
const crypto = require("node:crypto");
const assert = require("node:assert/strict");
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const pointKey = (p) => `${p.line}:${p.column}`;
const compare = (a, b) => a.line - b.line || a.column - b.column;
const callable = (n) => ts.isFunctionLike(n) && n.body !== undefined;
const decisions = new Set([
  ts.SyntaxKind.IfStatement,
  ts.SyntaxKind.ConditionalExpression,
  ts.SyntaxKind.ForStatement,
  ts.SyntaxKind.ForInStatement,
  ts.SyntaxKind.ForOfStatement,
  ts.SyntaxKind.WhileStatement,
  ts.SyntaxKind.DoStatement,
  ts.SyntaxKind.CatchClause,
  ts.SyntaxKind.CaseClause,
]);
const logical = new Set([
  ts.SyntaxKind.AmpersandAmpersandToken,
  ts.SyntaxKind.BarBarToken,
  ts.SyntaxKind.QuestionQuestionToken,
  ts.SyntaxKind.AmpersandAmpersandEqualsToken,
  ts.SyntaxKind.BarBarEqualsToken,
  ts.SyntaxKind.QuestionQuestionEqualsToken,
]);

function complexity(fn) {
  let cc = 1;
  function visit(node) {
    if (node !== fn && callable(node)) return; // A nested callable has its own owner.
    if (decisions.has(node.kind)) cc++;
    if (ts.isBinaryExpression(node) && logical.has(node.operatorToken.kind))
      cc++;
    if (node.questionDotToken) cc++;
    if ((ts.isParameter(node) || ts.isBindingElement(node)) && node.initializer)
      cc++;
    ts.forEachChild(node, visit);
  }
  visit(fn);
  return cc;
}

function inventory(name, text) {
  assert.equal(ts.version, "6.0.2", "unsupported TypeScript parser version");
  assert(
    !name.endsWith(".tsx") && !name.endsWith(".d.ts"),
    "unsupported source kind",
  );
  const source = ts.createSourceFile(
    name,
    text,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  assert.equal(source.parseDiagnostics.length, 0, "invalid TypeScript source");
  const point = (offset) => {
    const p = source.getLineAndCharacterOfPosition(offset);
    return { line: p.line + 1, column: p.character };
  };
  const functions = [];
  function visit(node) {
    if (callable(node)) {
      // Native instrumentation must join each body, including constructors/accessors.
      const start = point(node.getStart(source));
      const namedFunction =
        (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)) &&
        node.name;
      const declaration = point(
        namedFunction ? node.name.getStart(source) : node.getStart(source),
      );
      functions.push({
        name: node.name ? node.name.getText(source) : ts.SyntaxKind[node.kind],
        kind: ts.SyntaxKind[node.kind],
        start,
        declaration,
        body: point(node.body.getStart(source)),
        end: point(node.end),
        cc: complexity(node),
      });
    }
    ts.forEachChild(node, visit);
  }
  visit(source);
  const declarationOnly = source.statements.every(
    (node) =>
      ts.isInterfaceDeclaration(node) ||
      ts.isTypeAliasDeclaration(node) ||
      (ts.isImportDeclaration(node) && node.importClause?.isTypeOnly) ||
      (ts.isExportDeclaration(node) && node.isTypeOnly),
  );
  return { sha256: sha(text), functions, declarationOnly };
}

function counter(value) {
  assert(Number.isSafeInteger(value) && value >= 0, "invalid native counter");
  return value;
}

function checkPoint(point, text) {
  const lines = text.split("\n");
  assert(
    point &&
      Number.isSafeInteger(point.line) &&
      point.line > 0 &&
      point.line <= lines.length,
    "invalid source line",
  );
  assert(
    Number.isSafeInteger(point.column) &&
      point.column >= 0 &&
      point.column <= lines[point.line - 1].length,
    "invalid UTF-16 source column",
  );
}

function rational(cc, covered, total) {
  assert(total > 0 && covered <= total, "missing function line denominator");
  const c = BigInt(cc),
    missed = BigInt(total - covered),
    t = BigInt(total);
  let numerator = c * c * missed ** 3n + c * t ** 3n;
  let denominator = t ** 3n;
  let a = numerator,
    b = denominator;
  while (b !== 0n) [a, b] = [b, a % b];
  numerator /= a;
  denominator /= a;
  assert(
    numerator <= BigInt(Number.MAX_SAFE_INTEGER) &&
      denominator <= BigInt(Number.MAX_SAFE_INTEGER),
    "exact rational exceeds JSON integer precision",
  );
  return {
    type: "rational",
    numerator: Number(numerator),
    denominator: Number(denominator),
  };
}

function measure(name, text, native) {
  const info = inventory(name, text);
  for (const [map, counts] of [
    ["statementMap", "s"],
    ["fnMap", "f"],
    ["branchMap", "b"],
  ]) {
    assert(native[map] && native[counts], "missing native coverage map");
    assert.deepEqual(
      Object.keys(native[map]).sort(),
      Object.keys(native[counts]).sort(),
      "missing native counters",
    );
    for (const [key, value] of Object.entries(native[counts])) {
      if (counts === "b") {
        assert(
          Array.isArray(value) &&
            value.length === native[map][key].locations.length,
          "missing native branch counters",
        );
        value.forEach(counter);
      } else counter(value);
    }
  }
  const joined = new Map();
  for (const [key, entry] of Object.entries(native.fnMap)) {
    [entry.decl.start, entry.decl.end, entry.loc.start, entry.loc.end].forEach(
      (p) => checkPoint(p, text),
    );
    const matches = info.functions.filter(
      (fn) =>
        pointKey(fn.declaration) === pointKey(entry.decl.start) &&
        compare(fn.declaration, entry.loc.start) <= 0 &&
        compare(entry.loc.start, fn.body) <= 0 &&
        compare(fn.end, entry.loc.end) === 0,
    );
    assert.equal(
      matches.length,
      1,
      "ambiguous or transformed function coverage",
    );
    assert(!joined.has(matches[0]), "duplicate native function identity");
    joined.set(matches[0], key);
  }
  assert.equal(
    joined.size,
    info.functions.length,
    "incomplete function coverage inventory",
  );
  const statements = Object.entries(native.statementMap).map(([key, span]) => {
    checkPoint(span.start, text);
    checkPoint(span.end, text);
    assert(compare(span.start, span.end) <= 0, "reversed statement span");
    const owners = info.functions.filter(
      (fn) =>
        compare(fn.body, span.start) <= 0 && compare(span.start, fn.end) < 0,
    );
    owners.sort((a, b) => compare(b.start, a.start));
    return { key, line: span.start.line, owner: owners[0] };
  });
  const fileLines = new Map();
  for (const item of statements)
    fileLines.set(
      item.line,
      Math.max(fileLines.get(item.line) || 0, native.s[item.key]),
    );
  const fileTotal = fileLines.size;
  return {
    source: { path: name, sha256: info.sha256 },
    file: {
      values: fileTotal
        ? {
            "coverage.line": {
              type: "ratio",
              covered: [...fileLines.values()].filter((v) => v > 0).length,
              total: fileTotal,
            },
          }
        : {},
      unavailable: fileTotal ? [] : ["coverage.line"],
    },
    functions: info.functions.map((fn) => {
      const lines = new Map();
      for (const item of statements.filter((s) => s.owner === fn)) {
        lines.set(
          item.line,
          Math.max(lines.get(item.line) || 0, native.s[item.key]),
        );
      }
      const total = lines.size,
        covered = [...lines.values()].filter((v) => v > 0).length;
      const values = {
        "complexity.cyclomatic": { type: "count", value: fn.cc },
        "coverage.function": {
          type: "ratio",
          covered: Number(native.f[joined.get(fn)] > 0),
          total: 1,
        },
      };
      if (total > 0) {
        values["coverage.line"] = { type: "ratio", covered, total };
        values["risk.crap"] = rational(fn.cc, covered, total);
      }
      return {
        ...fn,
        values,
        unavailable: total === 0 ? ["coverage.line", "risk.crap"] : [],
      };
    }),
  };
}
module.exports = { inventory, measure, rational, sha };
