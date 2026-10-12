"use strict";
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const { inventory, measure, sha } = require("./measure.cjs");
const parse = require("./strict-json.cjs");
const COLLECTOR = { name: "typescript-risk", version: "0.1.0-rc.4" };
const REQUEST_SCHEMA = "harness-collector-request/v1";
const TYPES = {
  "complexity.cyclomatic": "count",
  "coverage.function": "ratio",
  "coverage.line": "ratio",
  "risk.crap": "rational",
};
const canonical = (value) => JSON.stringify(sort(value));
function sort(value) {
  if (Array.isArray(value)) return value.map(sort);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((k) => [k, sort(value[k])]),
    );
  return value;
}
const equal = (a, b, reason) =>
  assert.equal(canonical(a), canonical(b), reason);
function relative(value) {
  assert(
    typeof value === "string" &&
      value.length > 0 &&
      value === value.normalize("NFC"),
    "invalid relative path",
  );
  assert(
    !/[\\:\x00-\x1f]/.test(value) &&
      !path.isAbsolute(value) &&
      !value.split("/").some((v) => ["", ".", ".."].includes(v)),
    "noncanonical relative path",
  );
  return value;
}
function file(root, name) {
  relative(name);
  let current = root;
  for (const part of name.split("/")) {
    current = path.join(current, part);
    assert(!fs.lstatSync(current).isSymbolicLink(), "symlink input rejected");
  }
  assert(fs.statSync(current).isFile(), "input is not a regular file");
  assert(fs.statSync(current).size <= 64 * 1024 * 1024, "input exceeds 64 MiB");
  return fs.readFileSync(current);
}
function rootDirectory(root) {
  assert(
    path.isAbsolute(root) &&
      fs.realpathSync(root) === root &&
      fs.statSync(root).isDirectory(),
    "noncanonical root",
  );
  return root;
}
function sources(root, sourceRoot, excluded = []) {
  relative(sourceRoot);
  const files = [];
  assert(
    Array.isArray(excluded) && new Set(excluded).size === excluded.length,
    "invalid exclusions",
  );
  for (const name of excluded) {
    relative(name);
    assert(
      name.startsWith(sourceRoot + "/"),
      "excluded source outside boundary",
    );
    file(root, name);
  }
  function walk(directory) {
    for (const entry of fs.readdirSync(path.join(root, directory), {
      withFileTypes: true,
    })) {
      const name = `${directory}/${entry.name}`;
      assert(!entry.isSymbolicLink(), "symlink source inventory");
      if (entry.isDirectory()) walk(name);
      else if (name.endsWith(".tsx"))
        throw new Error("TSX is outside the measured scope");
      else if (
        name.endsWith(".ts") &&
        !name.endsWith(".d.ts") &&
        !excluded.includes(name)
      ) {
        const bytes = file(root, name),
          text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        files.push({ path: relative(name), sha256: sha(bytes), text });
      }
    }
  }
  // Inspect each root component as well; readdir alone would follow a symlink root.
  let current = root;
  for (const part of sourceRoot.split("/")) {
    current = path.join(current, part);
    assert(!fs.lstatSync(current).isSymbolicLink());
  }
  walk(sourceRoot);
  assert(files.length > 0, "empty TypeScript source inventory");
  return files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}
function subject(request, source, fn) {
  const result = {
    identity_version: "subject-identity/v1",
    component: request.component,
    target: request.context.target,
    boundary: request.parameters.boundary,
    kind: "function/v1",
    path: source.path,
    discriminator: `typescript-ast-risk/v1:${fn.kind}:${fn.start.line}:${fn.start.column}:${fn.end.line}:${fn.end.column}`,
    span: {
      start_line: fn.start.line,
      start_column: fn.start.column + 1,
      end_line: fn.end.line,
      end_column: fn.end.column + 1,
    },
    source_sha256: source.sha256,
  };
  return {
    id:
      "subject-identity/v1:" +
      sha(canonical({ project: request.project, ...result })),
    ...result,
    metadata: {},
  };
}
function fileSubject(request, source) {
  const result = {
    identity_version: "subject-identity/v1",
    component: request.component,
    target: request.context.target,
    boundary: request.parameters.boundary,
    kind: "file/v1",
    path: source.path,
    discriminator: "typescript-original-file/v1",
    source_sha256: source.sha256,
  };
  return {
    id:
      "subject-identity/v1:" +
      sha(canonical({ project: request.project, ...result })),
    ...result,
    metadata: {},
  };
}
function discover(request) {
  const files = sources(
    rootDirectory(request.workspace_root),
    request.parameters.source_root,
    request.parameters.exclude,
  );
  const subjects = files.flatMap((source) => [
    ...(request.parameters.include_files ? [fileSubject(request, source)] : []),
    ...inventory(source.path, source.text).functions.map((fn) =>
      subject(request, source, fn),
    ),
  ]);
  assert(subjects.length > 0, "no production function subjects");
  return { sources: files, subjects };
}
function binding(request) {
  return {
    ...Object.fromEntries(
      [
        "project",
        "component",
        "collector",
        "context",
        "requested_capabilities",
      ].map((k) => [k, request[k]]),
    ),
    scope: {
      source_root: request.parameters.source_root,
      boundary: request.parameters.boundary,
      exclude: request.parameters.exclude || [],
      include_files: request.parameters.include_files || false,
    },
  };
}
function series(request, receipt) {
  const implementation = Object.fromEntries(
    [
      "measure.cjs",
      "protocol.cjs",
      "strict-json.cjs",
      "cli.cjs",
      "project.cjs",
      "npm-shrinkwrap.json",
    ].map((name) => [name, sha(fs.readFileSync(path.join(__dirname, name)))]),
  );
  const value = {
    name: "typescript-original-function-risk",
    collector: COLLECTOR,
    tool: {
      name: "typescript-original-instrumentation",
      version: sha(
        canonical({
          toolchain: receipt.toolchain,
          pipeline: receipt.pipeline || null,
        }),
      ),
    },
    rule: {
      name: "typescript-decision-count-innermost-lines",
      version: sha(canonical(implementation)),
    },
    runtime: { name: "node", version: process.versions.node },
    target: request.context.target,
    source_identity: { name: "typescript-ast-risk/v1", version: "1" },
    normalization: {
      name: "istanbul-original-lines-innermost/v1",
      version: "1",
    },
    metrics: Object.keys(TYPES)
      .sort()
      .map((name) => ({ name, type: TYPES[name] })),
  };
  return { id: "measurement-series/v1:" + sha(canonical(value)), ...value };
}
function collect(request) {
  equal(
    Object.keys(request).sort(),
    [
      "schema",
      "project",
      "component",
      "collector",
      "context",
      "requested_capabilities",
      "workspace_root",
      "output_root",
      "parameters",
    ].sort(),
    "unknown/missing request field",
  );
  const allowedParameters = [
    "source_root",
    "boundary",
    "coverage",
    "subjects",
    "receipt",
    "exclude",
    "include_files",
    "artifact_subdir",
  ];
  assert(
    Object.keys(request.parameters).every((k) => allowedParameters.includes(k)),
    "unknown collector parameter",
  );
  for (const name of ["project", "component"])
    assert(/^[a-z][a-z0-9._-]*$/.test(request[name]), "invalid identifier");
  assert(
    /^[a-z][a-z0-9._-]*$/.test(request.parameters.boundary),
    "invalid boundary",
  );
  equal(
    Object.keys(request.context).sort(),
    ["base_commit", "commit", "run", "target"].sort(),
    "invalid context fields",
  );
  assert(
    /^[a-f0-9]{40}$/.test(request.context.commit) &&
      /^[a-f0-9]{40}$/.test(request.context.base_commit),
    "invalid source revision",
  );
  if (request.schema !== REQUEST_SCHEMA)
    throw new Error(
      `incompatible collector protocol version: expected request schema ${REQUEST_SCHEMA}, received ${JSON.stringify(request.schema)}`,
    );
  if (canonical(request.collector) !== canonical(COLLECTOR))
    throw new Error(
      `incompatible collector version: expected ${COLLECTOR.name}@${COLLECTOR.version}, received ${JSON.stringify(request.collector)}`,
    );
  assert(
    request.requested_capabilities.length > 0 &&
      request.requested_capabilities.every((m) => m in TYPES),
    "unsupported requested metric",
  );
  assert.equal(
    new Set(request.requested_capabilities).size,
    request.requested_capabilities.length,
    "duplicate requested metric",
  );
  const root = rootDirectory(request.workspace_root),
    output = rootDirectory(request.output_root);
  assert(
    output !== root && !root.startsWith(output + path.sep),
    "output contains workspace",
  );
  assert(
    !output.startsWith(
      path.join(root, relative(request.parameters.source_root)) + path.sep,
    ),
    "output overlaps sources",
  );
  const prefix = request.parameters.artifact_subdir || "";
  if (prefix) {
    relative(prefix);
    assert(!prefix.includes("/"), "artifact subdirectory must be one component");
    assert(!fs.existsSync(path.join(output, prefix)), "artifact subdirectory must be fresh");
  } else assert.equal(fs.readdirSync(output).length, 0, "output must be fresh");
  const { sources: files, subjects } = discover(request),
    receipt = request.parameters.receipt;
  equal(
    subjects,
    request.parameters.subjects,
    "incomplete or modified host subject inventory",
  );
  assert.equal(receipt.schema, "typescript-original-coverage-receipt/v1");
  equal(receipt.request, binding(request), "coverage receipt context mismatch");
  equal(
    receipt.sources,
    files.map(({ path, sha256 }) => ({ path, sha256 })),
    "stale or incomplete source inventory",
  );
  equal(
    receipt.toolchain,
    {
      typescript: "6.0.2",
      instrumenter: "istanbul-lib-instrument@6.0.3",
      instrumentation: "original-typescript-before-transpile/v1",
      node: process.versions.node,
    },
    "unsupported instrumentation series",
  );
  if (receipt.pipeline) {
    const pipeline = receipt.pipeline;
    equal(
      Object.keys(pipeline).sort(),
      ["files", "schema", "tools"],
      "invalid capture pipeline fields",
    );
    assert.equal(pipeline.schema, "typescript-capture-pipeline/v1");
    assert(
      Object.keys(pipeline.files).length > 0 &&
        Object.keys(pipeline.tools).length > 0,
      "empty capture pipeline",
    );
    for (const [name, digest] of Object.entries(pipeline.files))
      assert.equal(
        sha(file(root, name)),
        digest,
        "capture configuration changed: " + name,
      );
    assert(
      Object.values(pipeline.tools).every(
        (v) => typeof v === "string" && v.length > 0,
      ),
      "invalid capture tool identity",
    );
  }
  if (receipt.inputs) {
    assert(Object.keys(receipt.inputs).length > 0, "empty capture inputs");
    for (const [name, digest] of Object.entries(receipt.inputs))
      assert.equal(
        sha(file(root, name)),
        digest,
        "capture input changed: " + name,
      );
  }
  const coverageBytes = file(root, request.parameters.coverage);
  assert.equal(
    sha(coverageBytes),
    receipt.coverage_sha256,
    "coverage digest mismatch",
  );
  const coverage = parse(coverageBytes.toString("utf8"));
  const names = files.map((f) => receipt.coverage_root + "/" + f.path);
  equal(
    Object.keys(coverage).sort(),
    names.sort(),
    "incomplete or extra original coverage files",
  );
  // Finish all validation/measurement before publishing any usable evidence.
  const rows = files.map((source) => {
    const name = receipt.coverage_root + "/" + source.path;
    assert.equal(coverage[name].path, name, "coverage path mismatch");
    return {
      source,
      measurement: measure(source.path, source.text, coverage[name]),
    };
  });
  const allArtifacts = [],
    records = [],
    identity = series(request, receipt);
  if (prefix) fs.mkdirSync(path.join(output, prefix), { mode: 0o700 });
  for (const { source, measurement } of rows.filter(
    (row) =>
      request.parameters.include_files || row.measurement.functions.length > 0,
  )) {
    const refs = [];
    for (const [suffix, bytes] of [
      ["coverage.json", coverageBytes],
      ["receipt.json", Buffer.from(canonical(receipt))],
    ]) {
      const name = (prefix ? prefix + "/" : "") + sha(source.path) + "-" + suffix;
      fs.writeFileSync(path.join(output, name), bytes, {
        flag: "wx",
        mode: 0o600,
      });
      refs.push({
        id: "raw-" + name.replaceAll("/", "-"),
        kind: "raw",
        media_type: "application/json",
        path: name,
        sha256: sha(bytes),
        bytes: bytes.length,
        context: request.context,
        source: { path: source.path, sha256: source.sha256 },
      });
    }
    allArtifacts.push(...refs);
    const links = refs.map((r) => r.id);
    const measuredSubjects = [
      ...(request.parameters.include_files
        ? [
            {
              ...measurement.file,
              owner: fileSubject(request, source),
              types: Object.keys(TYPES),
              unavailable: [
                ...measurement.file.unavailable,
                "coverage.function",
                "complexity.cyclomatic",
                "risk.crap",
              ],
            },
          ]
        : []),
      ...measurement.functions.map((fn) => ({
        ...fn,
        owner: subject(request, source, fn),
        types: Object.keys(TYPES),
      })),
    ];
    for (const fn of measuredSubjects) {
      const owner = fn.owner;
      records.push({
        schema: "harness-evidence/v1",
        id: "typescript-" + owner.id.split(":")[1],
        project: request.project,
        component: request.component,
        collector: COLLECTOR,
        series: identity,
        subject: owner,
        context: request.context,
        source: { path: source.path, sha256: source.sha256 },
        metrics: Object.entries(fn.values)
          .sort()
          .map(([name, value]) => ({ name, value, artifacts: links })),
        capabilities: fn.types.sort().map((metric) => ({
          metric,
          state: fn.unavailable.includes(metric)
            ? "not_applicable"
            : "supported",
          reason: fn.unavailable.includes(metric)
            ? owner.kind === "file/v1" && metric !== "coverage.line"
              ? "metric is defined for function subjects only"
              : "no original line denominator"
            : "pinned original TypeScript instrumentation",
          artifacts: links,
        })),
        artifacts: refs,
        status: Object.keys(fn.values).length ? "measured" : "unavailable",
      });
    }
  }
  return {
    schema: "harness-collector-response/v1",
    evidence: records,
    artifacts: allArtifacts,
    error: null,
  };
}
module.exports = {
  COLLECTOR,
  TYPES,
  canonical,
  discover,
  binding,
  collect,
  series,
};
