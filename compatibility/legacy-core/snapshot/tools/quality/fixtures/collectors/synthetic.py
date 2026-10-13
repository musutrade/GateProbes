#!/usr/bin/env python3
"""Synthetic retained-evidence adapter; no ecosystem tools are executed."""
import copy
import json
from pathlib import Path
import shutil
import sys
import time

FIXTURES = Path(__file__).resolve().parents[1]


def collect(request):
    scenario = request["parameters"].get("scenario", "success")
    if scenario == "measurement_error":
        return {"schema": "harness-collector-response/v1", "evidence": [], "artifacts": [],
                "error": {"code": "measurement_error", "message": "synthetic parser failure"}}
    records = json.loads((FIXTURES / "harness-evidence/polyglot.json").read_text())
    record = next(r for r in records if r["component"] == request["component"])
    output = Path(request["output_root"])
    for artifact in record["artifacts"]:
        destination = output / artifact["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(FIXTURES / "harness-evidence" / artifact["path"], destination)
    response = {"schema": "harness-collector-response/v1", "evidence": [record],
                "artifacts": copy.deepcopy(record["artifacts"]), "error": None}
    if scenario == "stale_commit":
        record["context"]["commit"] = "f" * 40
    elif scenario == "duplicate_subject":
        duplicate = copy.deepcopy(record)
        duplicate["id"] += "-duplicate"
        response["evidence"].append(duplicate)
    elif scenario == "artifact_tamper":
        (output / record["artifacts"][0]["path"]).write_text("tampered")
    elif scenario == "undeclared_artifact":
        (output / "undeclared.txt").write_text("unregistered raw output")
    elif scenario == "unlisted_artifact":
        response["artifacts"] = []
    elif scenario == "output_escape":
        response["artifacts"][0]["path"] = "../outside.json"
    elif scenario == "symlink_escape":
        artifact_path = output / record["artifacts"][0]["path"]
        artifact_path.unlink()
        artifact_path.symlink_to(FIXTURES / "harness-evidence" / record["artifacts"][0]["path"])
    elif scenario == "release_decision":
        response["release_decision"] = "pass"
    elif scenario == "missing_capability":
        record["capabilities"] = [c for c in record["capabilities"]
                                  if c["metric"] != "coverage.line"]
    return response


if __name__ == "__main__":
    request = json.load(sys.stdin)
    scenario = request["parameters"].get("scenario", "success")
    if scenario == "nonzero":
        print(json.dumps(collect(request)))
        sys.exit(7)
    if scenario == "timeout":
        time.sleep(30)
    elif scenario == "malformed_json":
        print("{not json")
    elif scenario == "duplicate_json_key":
        print('{"error": null, "error": null}')
    elif scenario == "invalid_utf8":
        sys.stdout.buffer.write(b"\xff")
    else:
        print(json.dumps(collect(request)))
