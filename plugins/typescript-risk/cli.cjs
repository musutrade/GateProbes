#!/usr/bin/env node
"use strict";
const fs = require("node:fs");
const parse = require("./strict-json.cjs");
const { COLLECTOR, discover, collect } = require("./protocol.cjs");
if (process.argv[2] === "--version") {
  process.stdout.write(
    `harness-gate-typescript-collector ${COLLECTOR.version}\n`,
  );
} else {
  try {
    const input = fs.readFileSync(0);
    if (input.length > 64 * 1024 * 1024)
      throw new Error("request exceeds 64 MiB");
    const request = parse(
      new TextDecoder("utf-8", { fatal: true }).decode(input),
    );
    const result =
      process.argv[2] === "project"
        ? require("./project.cjs")(request, process.argv.slice(2))
        : process.argv[2] === "inventory"
          ? discover(request)
          : collect(request);
    if (process.argv[2] === "inventory")
      result.sources = result.sources.map(({ path, sha256 }) => ({
        path,
        sha256,
      }));
    process.stdout.write(JSON.stringify(result) + "\n");
  } catch (error) {
    if (process.argv[2] === "project") {
      process.stderr.write(error.message + "\n");
      process.exitCode = 1;
      return;
    }
    process.stdout.write(
      JSON.stringify({
        schema: "harness-collector-response/v1",
        evidence: [],
        artifacts: [],
        error: { code: "measurement_error", message: error.message },
      }) + "\n",
    );
  }
}
