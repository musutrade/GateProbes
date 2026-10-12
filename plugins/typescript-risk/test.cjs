"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const ts = require("typescript");
const { createInstrumenter } = require("istanbul-lib-instrument");
const { inventory, measure, rational } = require("./measure.cjs");

function native(source, invoke = "") {
  const tool = createInstrumenter({
    parserPlugins: ["typescript"],
    compact: false,
    produceSourceMap: true,
  });
  const instrumented = tool.instrumentSync(source, "/fixture/src/sample.ts");
  const js = ts.transpileModule(instrumented, {
    compilerOptions: { target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const context = {};
  vm.runInNewContext(js + "\n" + invoke, context, { timeout: 1000 });
  return JSON.parse(
    JSON.stringify(context.__coverage__["/fixture/src/sample.ts"]),
  );
}

test("decision corpus uses a pinned AST rule, including nested owners", () => {
  const fixtures = [
    ["function f(x: boolean) { return x; }", [1]],
    ["function f(x: boolean) { if(x) return 1; else return 0; }", [2]],
    ["function f(x: boolean) { return x ? 1 : 0; }", [2]],
    ["function f(x: number[]) { for (const n of x) { if(n) continue; } }", [3]],
    ["function f(x: any) { return x?.a?.() ?? 0; }", [4]],
    ["function f(x = 1) { let y = x; y ||= 2; return y && x; }", [4]],
    [
      "function f(x: number) { switch(x) { case 1: return 1; case 2: return 2; default: return 0; } }",
      [3],
    ],
    [
      "function f() { try { return 1; } catch(e) { return 0; } finally {} }",
      [2],
    ],
    [
      "function f() { const g = (x: boolean) => x ? 1 : 0; return g(true); }",
      [1, 2],
    ],
    [
      "class A { constructor(x: boolean) { if(x) {} } get x() { return 1; } }",
      [2, 1],
    ],
    [
      "function f(x: number) { while(x) x--; do { x++; } while(x < 1); for(let i=0;i<x;i++) {} }",
      [4],
    ],
  ];
  for (const [source, expected] of fixtures)
    assert.deepEqual(
      inventory("src/sample.ts", source).functions.map((f) => f.cc),
      expected,
    );
});

test("real original-source instrumentation measures tested and untested branches", () => {
  const source =
    "function f(x: boolean) {\n if (x) {\n  return 1;\n }\n return 0;\n}\n";
  const none = measure("src/sample.ts", source, native(source)).functions[0];
  assert.deepEqual(none.values["coverage.line"], {
    type: "ratio",
    covered: 0,
    total: 3,
  });
  assert.deepEqual(none.values["risk.crap"], {
    type: "rational",
    numerator: 6,
    denominator: 1,
  });
  const all = measure(
    "src/sample.ts",
    source,
    native(source, "f(true); f(false);"),
  ).functions[0];
  assert.deepEqual(all.values["risk.crap"], {
    type: "rational",
    numerator: 2,
    denominator: 1,
  });
  const partial = measure("src/sample.ts", source, native(source, "f(true);"))
    .functions[0];
  assert.deepEqual(partial.values["risk.crap"], {
    type: "rational",
    numerator: 58,
    denominator: 27,
  });
});

test("nested anonymous functions do not inherit parent coverage or decisions", () => {
  const source =
    "function outer() {\n const inner = (x: boolean) => {\n  if (x) return 1;\n  return 0;\n };\n return inner;\n}\n";
  const rows = measure(
    "src/sample.ts",
    source,
    native(source, "outer();"),
  ).functions;
  assert.equal(rows[0].cc, 1);
  assert.equal(rows[1].cc, 2);
  assert.equal(rows[0].values["coverage.line"].covered, 2);
  assert.equal(rows[1].values["coverage.line"].covered, 0);
});

test("exact boundary arithmetic is not rounded and has no threshold authority", () => {
  assert.deepEqual(rational(10, 3, 3), {
    type: "rational",
    numerator: 10,
    denominator: 1,
  });
  assert.deepEqual(rational(10, 2, 3), {
    type: "rational",
    numerator: 370,
    denominator: 27,
  });
  assert.deepEqual(rational(11, 3, 3), {
    type: "rational",
    numerator: 11,
    denominator: 1,
  });
  assert.throws(() => rational(1, 0, 0));
});

test("missing, malformed, fractional and duplicate measurement inputs fail closed", () => {
  const source = "function f() { return 1; }";
  const valid = native(source, "f();");
  for (const mutate of [
    (n) => {
      delete n.f["0"];
    },
    (n) => {
      n.f["0"] = -1;
    },
    (n) => {
      n.s["0"] = 0.5;
    },
    (n) => {
      n.f["0"] = true;
    },
    (n) => {
      n.fnMap["0"].decl.start.column++;
    },
    (n) => {
      n.fnMap["1"] = n.fnMap["0"];
      n.f["1"] = 0;
    },
    (n) => {
      n.statementMap["0"].start.line = 99;
    },
  ]) {
    const altered = structuredClone(valid);
    mutate(altered);
    assert.throws(() => measure("src/sample.ts", source, altered));
  }
  assert.throws(() => inventory("src/sample.ts", "function {"));
  assert.throws(() => inventory("src/sample.tsx", "<div/>"));
});

test("empty bodies do not become 100 percent or numeric CRAP", () => {
  const source = "function empty() {}";
  const row = measure("src/sample.ts", source, native(source)).functions[0];
  assert.deepEqual(row.unavailable, ["coverage.line", "risk.crap"]);
  assert.equal(row.values["risk.crap"], undefined);
});

const fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  COLLECTOR,
  canonical,
  discover,
  binding,
  collect,
} = require("./protocol.cjs");
const { sha } = require("./measure.cjs");
const parse = require("./strict-json.cjs");
function scenario(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "typescript-plugin-"));
  try {
    fs.mkdirSync(path.join(root, "src"));
    fs.mkdirSync(path.join(root, "output"));
    const source =
      "function f(x: boolean) {\n if (x) return 1;\n return 0;\n}\n";
    fs.writeFileSync(path.join(root, "src/sample.ts"), source);
    const coverage = JSON.stringify({
      "/fixture/src/sample.ts": native(source, "f(true); f(false);"),
    });
    fs.writeFileSync(path.join(root, "coverage.json"), coverage);
    const request = {
      schema: "harness-collector-request/v1",
      project: "fixture",
      component: "frontend",
      collector: COLLECTOR,
      context: {
        commit: "1".repeat(40),
        base_commit: "0".repeat(40),
        target: "node",
        run: "native-fixture",
      },
      requested_capabilities: [
        "risk.crap",
        "coverage.line",
        "coverage.function",
        "complexity.cyclomatic",
      ],
      workspace_root: root,
      output_root: path.join(root, "output"),
      parameters: {
        source_root: "src",
        boundary: "production",
        coverage: "coverage.json",
      },
    };
    const inventory = discover(request);
    request.parameters.subjects = inventory.subjects;
    request.parameters.receipt = {
      schema: "typescript-original-coverage-receipt/v1",
      request: binding(request),
      sources: inventory.sources.map(({ path, sha256 }) => ({ path, sha256 })),
      coverage_sha256: sha(coverage),
      coverage_root: "/fixture",
      toolchain: {
        typescript: "6.0.2",
        instrumenter: "istanbul-lib-instrument@6.0.3",
        instrumentation: "original-typescript-before-transpile/v1",
        node: process.versions.node,
      },
    };
    return run({ root, request });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test("file coverage includes top-level statements without borrowing function coverage", () => {
  const source = "const unused = 42;\nfunction f() { return 1; }\n";
  const raw = native(source, "f();");
  const top = Object.keys(raw.statementMap).find(
    (k) => raw.statementMap[k].start.line === 1,
  );
  raw.s[top] = 0;
  const result = measure("src/sample.ts", source, raw);
  assert.deepEqual(result.file.values["coverage.line"], {
    type: "ratio",
    covered: 1,
    total: 2,
  });
  assert.equal(result.functions[0].values["coverage.line"].covered, 1);
  const empty = measure(
    "src/type.ts",
    "interface Value { x: number }",
    native("interface Value { x: number }", ""),
  );
  assert.deepEqual(empty.file.values, {});
  assert.deepEqual(empty.file.unavailable, ["coverage.line"]);
});

test("declaration classification never treats unexecuted runtime code as erased types", () => {
  assert(
    inventory("types.ts", "export interface X { n: number }\ntype Y = X;")
      .declarationOnly,
  );
  assert(!inventory("runtime.ts", "const n = 42;").declarationOnly);
  assert(!inventory("side-effect.ts", "import './setup';").declarationOnly);
  assert(!inventory("class.ts", "export class X {};").declarationOnly);
});

test("file subject inventory and capture pipeline pins are part of the measured series", () => {
  scenario(({ root, request }) => {
    request.parameters.include_files = true;
    request.parameters.subjects = discover(request).subjects;
    request.parameters.receipt.request = binding(request);
    fs.writeFileSync(path.join(root, "angular.json"), "{}");
    request.parameters.receipt.pipeline = {
      schema: "typescript-capture-pipeline/v1",
      files: { "angular.json": sha("{}") },
      tools: { builder: "angular-test-fixture" },
    };
    const result = collect(request);
    assert.deepEqual(
      result.evidence.map((e) => e.subject.kind),
      ["file/v1", "function/v1"],
    );
    fs.writeFileSync(path.join(root, "angular.json"), "{ }");
    const output = path.join(root, "fresh");
    fs.mkdirSync(output);
    request.output_root = output;
    assert.throws(() => collect(request), /capture configuration changed/);
    assert.deepEqual(fs.readdirSync(output), []);
  });
});

test("standard protocol returns facts and source/context-bound raw artifacts", () =>
  scenario(({ root, request }) => {
    const response = collect(request);
    assert.equal(response.error, null);
    assert.equal(response.evidence.length, 1);
    assert.equal(response.artifacts.length, 2);
    const metric = response.evidence[0].metrics.find(
      (m) => m.name === "risk.crap",
    );
    assert.deepEqual(metric.value, {
      type: "rational",
      numerator: 2,
      denominator: 1,
    });
    for (const artifact of response.artifacts)
      assert.equal(
        sha(fs.readFileSync(path.join(request.output_root, artifact.path))),
        artifact.sha256,
      );
    assert(!canonical(response).includes('"pass"'));
    assert(!canonical(response).includes('"threshold"'));
    assert.throws(() => collect(request), /fresh/);
  }));

test("protocol rejects stale sources, coverage, context, missing subjects, escape and symlinks", () => {
  for (const mutate of [
    ({ request }) =>
      (request.parameters.receipt.coverage_sha256 = "0".repeat(64)),
    ({ request }) =>
      (request.parameters.receipt.request = {
        ...request.parameters.receipt.request,
        project: "other",
      }),
    ({ request }) => (request.parameters.subjects = []),
    ({ request }) => (request.parameters.coverage = "../coverage.json"),
    ({ request }) =>
      (request.parameters.receipt.toolchain.instrumentation =
        "mapped-v8-coverage"),
    ({ root }) =>
      fs.appendFileSync(path.join(root, "src/sample.ts"), "\n// changed"),
    ({ root }) =>
      fs.writeFileSync(
        path.join(root, "src/omitted.ts"),
        "function omitted() { return 2; }",
      ),
    ({ root }) =>
      fs.symlinkSync(
        path.join(root, "src/sample.ts"),
        path.join(root, "src/alias.ts"),
      ),
  ])
    scenario((value) => {
      mutate(value);
      assert.throws(() => collect(value.request));
      assert.equal(fs.readdirSync(value.request.output_root).length, 0);
    });
});

test("incompatible collector protocol version fails closed with an explicit diagnostic", () =>
  scenario(({ request }) => {
    request.schema = "harness-collector-request/v2";
    assert.throws(
      () => collect(request),
      /incompatible collector protocol version: expected request schema harness-collector-request\/v1, received "harness-collector-request\/v2"/,
    );
    request.schema = "harness-collector-request/v1";
    request.collector = { ...COLLECTOR, version: "9.9.9" };
    assert.throws(
      () => collect(request),
      /incompatible collector version: expected typescript-risk@0\.1\.0-rc\.4, received/,
    );
  }));

test("subprocess supports version/inventory and strict one-response error semantics", () =>
  scenario(({ request }) => {
    const version = spawnSync(
      process.execPath,
      [path.join(__dirname, "cli.cjs"), "--version"],
      { encoding: "utf8" },
    );
    assert.equal(version.status, 0);
    assert.match(version.stdout, /0.1.0-rc.4/);
    const result = spawnSync(
      process.execPath,
      [path.join(__dirname, "cli.cjs")],
      { input: canonical(request), encoding: "utf8" },
    );
    assert.equal(result.status, 0);
    assert.equal(JSON.parse(result.stdout).error, null);
    const invalid = spawnSync(
      process.execPath,
      [path.join(__dirname, "cli.cjs")],
      { input: '{"schema":"x","schema":"y"}', encoding: "utf8" },
    );
    const error = JSON.parse(invalid.stdout);
    assert.deepEqual(error.evidence, []);
    assert.equal(error.error.code, "measurement_error");
  }));

test("strict JSON rejects ambiguity and unsafe numeric inputs", () => {
  for (const input of [
    '{"x":1,"x":2}',
    '{"x":1,"\\u0078":2}',
    "NaN",
    "9007199254740993",
    "1.5",
    "{}junk",
    '{"x":1,}',
    "[1,]",
  ])
    assert.throws(() => parse(input));
  assert.equal(parse('{"__proto__":42}').__proto__, 42);
});

test("native method, getter, named/anonymous expression and Unicode coordinates join", () => {
  const fixtures = [
    [
      "class A { method(x: boolean) { if(x) return 1; return 0; } }",
      "new A().method(true);",
    ],
    ["class A { get value() { return 1; } }", "new A().value;"],
    ["const f = (x: number) => x + 1;", "f(1);"],
    ["const f = function named(x: number) { return x; };", "f(1);"],
    ['const emoji = "😀"; function f() { return emoji; }', "f();"],
  ];
  for (const [source, invoke] of fixtures) {
    const rows = measure(
      "src/sample.ts",
      source,
      native(source, invoke),
    ).functions;
    assert(rows.length > 0);
    assert(rows.every((r) => r.values["coverage.function"].covered === 1));
  }
});
test("production files with test-looking names are inventoried unless host explicitly excludes them", () =>
  scenario(({ root, request }) => {
    fs.writeFileSync(
      path.join(root, "src/real.spec.ts"),
      "function stillProduction() { return 0; }",
    );
    assert.equal(discover(request).subjects.length, 2);
    request.parameters.exclude = ["src/real.spec.ts"];
    assert.equal(discover(request).subjects.length, 1);
    assert.throws(() => collect(request)); // Existing receipt did not authorize this scope change.
  }));


test("collectors share a root but exclusively own their artifact subdirectory", () => {
  scenario(({ root, request }) => {
    fs.writeFileSync(path.join(request.output_root, "other-collector.json"), "retained");
    request.parameters.artifact_subdir = "frontend";
    const response = collect(request);
    assert(response.artifacts.every(a => a.path.startsWith("frontend/")));
    assert.equal(fs.readFileSync(path.join(request.output_root, "other-collector.json"), "utf8"), "retained");
    assert.throws(() => collect(request), /fresh/);
    request.parameters.artifact_subdir = "../escape";
    assert.throws(() => collect(request), /relative/);
  });
});
