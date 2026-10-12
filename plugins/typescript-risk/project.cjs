"use strict";
// Core authenticates the adapter request. This bridge only validates its pinned
// measurement binding and translates between the two documented envelopes.
const fs = require("node:fs");
const assert = require("node:assert/strict");
const { sha } = require("./measure.cjs");
const parse = require("./strict-json.cjs");
const {
  canonical,
  collect,
  COLLECTOR,
  series,
  discover,
  TYPES,
} = require("./protocol.cjs");
const equal = (a, b, message) =>
  assert.equal(canonical(a), canonical(b), message);

function project(request, args) {
  assert(
    args.length === 5 &&
      args[0] === "project" &&
      args[1] === "--binding" &&
      args[3] === "--binding-sha256",
    "invalid project arguments",
  );
  equal(request.args, args, "signed arguments mismatch");
  assert.equal(request.protocol_version, 2);
  assert.equal(request.result_schema_version, "1");
  for (const [variable, field] of [
    ["HARNESS_GATE_INVOCATION_ID", "invocation_id"],
    ["HARNESS_GATE_STEP_ID", "step_id"],
    ["HARNESS_GATE_ARTIFACT_ROOT", "artifact_root"],
  ])
    assert.equal(
      process.env[variable],
      request[field],
      "Core invocation environment mismatch",
    );
  const bytes = fs.readFileSync(args[2]);
  assert.equal(sha(bytes), args[4], "project binding digest mismatch");
  const binding = parse(bytes.toString("utf8"));
  equal(
    Object.keys(binding).sort(),
    ["config_digest", "input", "request", "schema"],
    "invalid project binding fields",
  );
  assert.equal(binding.schema, "typescript-project-collector-binding/v1");
  equal(request.input, binding.input, "project input mismatch");
  assert.equal(
    request.config_digest,
    binding.config_digest,
    "project configuration mismatch",
  );
  const measurement = binding.request;
  const identity = series(measurement, measurement.parameters.receipt);
  const input = request.input;
  assert.equal(input.schema, "harness-project-collector-request/v1");
  equal(input.collector, COLLECTOR, "project collector identity mismatch");
  equal(
    { name: request.adapter.name, version: request.adapter.version },
    COLLECTOR,
    "adapter identity mismatch",
  );
  for (const name of [
    "project",
    "collector",
    "context",
    "workspace_root",
    "output_root",
  ])
    equal(
      input[name],
      measurement[name],
      "measurement context mismatch: " + name,
    );
  assert.equal(input.output_root, request.artifact_root);
  assert.equal(input.context.run, request.invocation_id);
  const subjects = discover(measurement).subjects;
  const capabilities = measurement.requested_capabilities;
  equal(
    [...capabilities].sort(),
    Object.keys(TYPES).sort(),
    "project request must cover the complete measurement series",
  );
  const expected = subjects
    .flatMap((subject) =>
      capabilities.map((capability) => ({
        subject: subject.id,
        capability,
        series: identity.id,
      })),
    )
    .sort(
      (a, b) =>
        a.subject.localeCompare(b.subject) ||
        a.capability.localeCompare(b.capability),
    );
  equal(input.bindings, expected, "incomplete project capability bindings");
  const result = collect(measurement);
  for (const record of result.evidence) {
    record.metrics = record.metrics.filter((metric) =>
      capabilities.includes(metric.name),
    );
    record.capabilities = record.capabilities.filter((cap) =>
      capabilities.includes(cap.metric),
    );
    if (!record.metrics.length) record.status = "unavailable";
  }
  return {
    schema_version: "1",
    status: "PASS",
    invocation_id: request.invocation_id,
    artifacts: result.artifacts,
    collection: {
      schema: "harness-project-collector-response/v1",
      evidence: result.evidence,
      error: null,
    },
  };
}
module.exports = project;
