#!/usr/bin/env python3
"""Pinned Core evidence-schema acceptance for the http-json-contract plugin.

Runs the plugin's own file-argument CLI on an end-to-end fixture and validates
every produced evidence record against the pinned Harness-Gate
`harness-evidence` schema. Startup, input parsing and error handling remain
covered by the plugin's protocol suites; this contract checks the records the
fixed Core consumes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(node: str, cli: Path, *args: str, cwd: Path) -> bytes:
    result = subprocess.run([node, str(cli), *args], cwd=cwd, capture_output=True, check=True)
    return result.stdout


def parse(data: bytes):
    return json.loads(data.decode("utf-8"))


def fixture():
    responses = {}
    for status, word in ((200, "ok"), (503, "unavailable")):
        responses[str(status)] = {
            "description": word,
            "content": {"application/json": {"schema": {
                "type": "object", "additionalProperties": False,
                "required": ["status", "database"],
                "properties": {key: {"type": "string", "enum": [word]}
                               for key in ("status", "database")}}}},
        }
    spec = {"openapi": "3.0.3", "info": {"title": "Fixture", "version": "1"},
            "paths": {"/api/health": {"get": {"operationId": "health",
                                              "responses": responses}}}}
    client = ("import {httpResource} from '@angular/common/http'; "
              "const value=httpResource<HealthResponse>(()=>'/api/health');")
    observations = [
        {"method": "GET", "path": "/api/health", "status": 200,
         "content_type": "application/json", "body": {"status": "ok", "database": "ok"}},
        {"method": "GET", "path": "/api/health", "status": 503,
         "content_type": "application/json",
         "body": {"status": "unavailable", "database": "unavailable"}},
    ]
    return spec, client, observations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--node", default="node")
    parser.add_argument("--core-root", type=Path, required=True,
                        help="directory with the pinned core harness_evidence module and schema/")
    parser.add_argument("--plugin", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    package = json.loads((args.plugin / "package.json").read_text())
    cli = args.cli.resolve()
    if not cli.is_file():
        raise SystemExit(f"missing plugin cli: {cli}")
    with tempfile.TemporaryDirectory(prefix="http-json-contract-") as directory:
        root = Path(directory)
        (root / "api").mkdir()
        (root / "web/angular/src").mkdir(parents=True)
        (root / "evidence").mkdir()
        spec, client, observations = fixture()
        head = json.dumps(spec).encode()
        (root / "api/openapi.json").write_bytes(head)
        run(args.node, cli, "generate", "api/openapi.json", "HealthResponse",
            "web/angular/src/response.ts", cwd=root)
        (root / "web/angular/src/client.ts").write_text(client)
        (root / "observations.json").write_text(json.dumps(observations))
        (root / "baseline.json").write_bytes(head)
        sources = {name: (root / name).read_bytes() for name in (
            "api/openapi.json", "web/angular/src/response.ts",
            "web/angular/src/client.ts", "observations.json")}
        context = {"commit": "1" * 40, "base_commit": "1" * 40, "target": "node", "run": "test"}
        request = {
            "schema": "harness-collector-request/v1", "project": "fixture",
            "component": "backend",
            "collector": {"name": "http-json-contract", "version": package["version"]},
            "context": context, "workspace_root": str(root),
            "output_root": str(root / "evidence"),
            "requested_capabilities": ["contract.breaking_changes", "contract.client_drift",
                                       "contract.compatible"],
            "parameters": {
                "boundary": "contract", "consumer_boundary": "production",
                "consumer": "frontend", "relationship": "api",
                "contract": "api/openapi.json",
                "type_file": "web/angular/src/response.ts",
                "client": "web/angular/src/client.ts", "type_name": "HealthResponse",
                "consumer_source_root": "web/angular/src", "exclude": [],
                "observations": "observations.json", "artifact_subdir": "contract",
                "receipt": {
                    "schema": "http-json-capture/v1", "context": context,
                    "inputs": {name: sha(data) for name, data in sources.items()},
                    "consumer_sources": {name: sha(data) for name, data in sources.items()
                                         if name.endswith(".ts")},
                    "baseline": {"path": str(root / "baseline.json"), "sha256": sha(head),
                                 "commit": context["base_commit"]},
                    "observations_sha256": sha(sources["observations.json"]),
                },
            },
        }
        (root / "request.json").write_text(json.dumps(request))
        discovered = parse(run(args.node, cli, "discover", "request.json", cwd=root))
        request["parameters"]["subjects"] = discovered["subjects"]
        (root / "request.json").write_text(json.dumps(request))
        response = parse(run(args.node, cli, "collect", "request.json", cwd=root))
        if response.get("error") is not None:
            raise SystemExit(f"collector reported an error: {response['error']}")
        evidence = response.get("evidence") or []
        if not evidence:
            raise SystemExit("collector returned no evidence")
        sys.path.insert(0, str(args.core_root.resolve()))
        import harness_evidence
        for record in evidence:
            harness_evidence._shape(record)
            for capability in record["capabilities"]:
                if capability["metric"] not in request["requested_capabilities"]:
                    raise SystemExit(f"undeclared capability: {capability['metric']}")
        summary = {"records": len(evidence),
                   "metrics": sorted({metric["name"] for record in evidence
                                      for metric in record["metrics"]}),
                   "contract_compatible": [metric["value"]["value"] for record in evidence
                                           for metric in record["metrics"]
                                           if metric["name"] == "contract.compatible"]}
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
