#!/usr/bin/env python3
"""Version 3 AST inventory, distinguishing closure instrumentation and LLVM join.

This required series covers the original hotspots and linked generic production.
The version 1 analyzer remains reproducible.
Inserted bytes and compiler-excluded ranges leave the coverage denominator.
Every compiled production function must have its own LLVM record; every LLVM
record in the production boundary must join.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from functools import lru_cache
from collections import defaultdict
from pathlib import Path

from function_risk import contains, crap_line, own_lines
from production_coverage import counts, require

SERIES = {"analyzer": "harness-gate-rust-measure/0.3.1", "rule": "mccabe-rust-3/1",
          "instrumentation": "closure-black-box/1", "mapping": "insertions-utf8/1",
          "selection": "gh315-review-low/1", "configuration": "compiler-target-production/4"}
PREFIX = "{ ::std::hint::black_box(()); "
SUFFIX = " }"
HOTSPOTS = {
    "doctor/checks.rs": ["run_check", "check_path", "check_env", "check_env_or_file", "check_git_config", "check_version"],
    "app/commands.rs": ["run", "run_doctor", "run_cleanup", "run_scope", "run_secrets", "run_audit", "run_verify", "run_hook"],
    "verify/mod.rs": ["run_selected", "service_results", "merge_results", "publish_report"],
    "verify/steps.rs": ["configured_task", "configure_runner", "configure_isolation", "configure_shard", "inject_task_environment"],
    "verify/parser.rs": ["count_json_results", "count_json_path", "discover_json_results"],
    "process/adapter.rs": ["run_with_cancel", "prepare_request", "run_process", "wait_for_adapter",
                           "validate_process_output", "finish_response"],
    "project/input.rs": ["allocate_snapshot_root"],
}


# Source paths remain relative to src for lineage with the established series.
# Both commits are measured with this exact inventory and tool version.
SOURCE_FILES = sorted({f"preset/{name}.rs" for name in ("catalog", "composition", "filesystem", "import", "initialize", "migration", "mod")} | set(HOTSPOTS) | {"app/mod.rs", "app/quality.rs", "cli.rs", "lib.rs", "main.rs", "config/mod.rs", "config/import.rs", "config/validation/mod.rs", "process/mod.rs", "process/command.rs", "process/replay.rs", "process/reader.rs", "project/discovery.rs", "project/mod.rs", "failure.rs", "verify/quality.rs", "verify/report.rs", "utils/redaction.rs", "service/lease.rs", "service/mod.rs", "service/report_directory.rs", "net_policy.rs",
    "audit/runner.rs", "config/loader.rs", "config/migration.rs", "config/model.rs", "process/signal.rs", "secrets/config.rs"} |
    # Reviewed 2026-10-12: the Postgres recipe moved out of the unmeasured
    # service/postgres.rs into the measured recipes series.
    {f"recipes/{name}.rs" for name in ("mod", "postgres")} |
    {f"config/quality/{name}.rs" for name in ("mod", "model", "policy", "validation", "compiler", "collectors", "baseline", "baseline/git")} |
    {f"../quality-core/{name}.rs" for name in (
    "comparison", "cross_component", "evidence", "json", "mod", "model",
    "policy", "project", "project_report", "ratchet", "replay", "schema")})

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@lru_cache(maxsize=8)
def compiler_configuration(target=None) -> dict:
    if target is None:
        version = subprocess.check_output(["rustc", "-vV"], text=True)
        target = next(line.removeprefix("host: ") for line in version.splitlines() if line.startswith("host: "))
    values = subprocess.check_output(["rustc", "--print", "cfg", "--target", target], text=True).splitlines()
    require(bool(values) and len(values) == len(set(values)), "invalid compiler target configuration")
    return {"target": target, "cfg": sorted(values)}


def ast(source: Path, binary: Path, configuration=None) -> dict:
    configuration = compiler_configuration() if configuration is None else configuration
    result = json.loads(subprocess.check_output([str(binary.resolve()), str(source), "--target-cfg"],
                                               input=json.dumps(configuration), encoding="utf-8"))
    require((result.get("analyzer"), result.get("version"), result.get("rule")) ==
            ("harness-gate-rust-measure", "0.3.1", "mccabe-rust-3"), "incompatible AST analyzer")
    require(result.get("configuration") == configuration, "AST target configuration mismatch")
    return result


def provenance(binary: Path) -> dict:
    """Record the real pinned release identity, never plugin source hashes."""
    root = Path(__file__).resolve().parent
    pin = json.loads((root / 'rust-measure-release.json').read_text())
    require(pin.get('schema') == 'rust-measure-release-pin/v1', 'unknown measurer pin schema')
    for field in ('release', 'asset', 'sha256', 'analyzer', 'version', 'rule'):
        require(isinstance(pin.get(field), str) and pin[field], f'invalid measurer pin {field}')
    files = ["source_measure.py", "function_risk.py", "production_coverage.py"]
    return {"sources": {p: digest((root / p).read_bytes()) for p in files},
            "release": {"repository": "musutrade/Harness-Gate", "tag": pin['release'],
                        "asset": pin['asset'], "sha256": pin['sha256']},
            "analyzer": {"name": pin['analyzer'], "version": pin['version'], "rule": pin['rule']},
            "binary_sha256": digest(binary.read_bytes()),
            "rustc": subprocess.check_output(["rustc", "-vV"], text=True).strip()}


def char_offset(source: str, point: list[int]) -> int:
    lines = source.splitlines(keepends=True)
    return sum(map(len, lines[:point[0] - 1])) + point[1] - 1


def byte_point(source: str, point: list[int]) -> tuple[int, int]:
    line, column = point
    return line, len(source.splitlines(keepends=True)[line - 1][:column - 1].encode()) + 1


def byte_span(source: str, span: list[int]) -> tuple:
    return (*byte_point(source, span[:2]), *byte_point(source, span[2:]))


def instrument(source: str, inventory: dict) -> tuple[str, list[dict]]:
    edits = []
    for symbol in inventory["symbols"]:
        if symbol["kind"] == "closure" and not symbol["test"]:
            body = symbol["body"]
            edits.extend([(char_offset(source, body[:2]), PREFIX),
                          (char_offset(source, body[2:]), SUFFIX)])
    # Multiple nested closures can end at the same point. Closing insertions
    # are identical; stable order handles adjacent closing/opening boundaries.
    result, previous, insertions = [], 0, []
    for offset, text in sorted(edits, key=lambda e: (e[0], e[1] != SUFFIX)):
        result.extend([source[previous:offset], text])
        line = source[:offset].count("\n") + 1
        column = len(source[:offset].rsplit("\n", 1)[-1].encode()) + 1
        insertions.append({"line": line, "column": column, "text": text})
        previous = offset
    result.append(source[previous:])
    return "".join(result), insertions


def original_point(point: list[int], edits: list[dict]) -> tuple[int, int]:
    line, column = point
    shift = 0
    for edit in edits:
        if edit["line"] != line:
            continue
        start = edit["column"] + shift
        width = len(edit["text"].encode())
        if column < start:
            break
        if column <= start + width:
            return line, edit["column"]
        shift += width
    return line, column - shift


def prepare(crate: Path, binary: Path, paths=None, target=None) -> dict:
    configuration = compiler_configuration(target)
    manifest = {"series": SERIES, "configuration": configuration, "files": {}, "absent_sources": []}
    for path in (SOURCE_FILES if paths is None else paths):
        file = crate / "src" / path
        if not file.exists():
            require(path not in HOTSPOTS, f"missing selected source: {path}")
            manifest["absent_sources"].append(path)
            continue
        source = file.read_text(encoding="utf-8")
        inventory = ast(file, binary, configuration)
        transformed, edits = instrument(source, inventory)
        manifest["files"][path] = {"original": source, "original_sha256": digest(source.encode()),
            "instrumented_sha256": digest(transformed.encode()), "inventory": inventory, "edits": edits}
        file.write_bytes(transformed.encode())
    return manifest


def complexity(raw: dict) -> int:
    return 1 + sum(raw.get(k, 0) for k in ("if", "guards", "while", "for", "loop",
        "and_and", "or_or", "question_mark", "match_decisions"))


def closure_name(name: str) -> bool:
    # Closure types in a function's generic arguments do not make the
    # instantiated function itself a closure. Inspect the terminal component.
    return re.search(r"::(?:\{closure#\d+\}|\{\{closure\}\})$", name) is not None


def measure(manifest: dict, llvm: dict, crate: Path, binary: Path) -> list[dict]:
    require(manifest["series"] == SERIES, "incompatible measurement series")
    configuration = manifest["configuration"]
    require(configuration == compiler_configuration(configuration["target"]), "compiler target configuration changed")
    require(llvm["type"] == "llvm.coverage.json.export" and len(llvm["data"]) == 1, "invalid LLVM dataset")
    symbols, excluded = {}, {}
    source_paths = {(crate / "src" / path).resolve(): path for path in manifest["files"]}
    for path, file in manifest["files"].items():
        source = file["original"]
        require(digest(source.encode()) == file["original_sha256"], "original digest mismatch")
        transformed, edits = instrument(source, file["inventory"])
        require(edits == file["edits"] and digest(transformed.encode()) == file["instrumented_sha256"],
                "instrumentation does not reproduce")
        require((crate / "src" / path).read_bytes() == transformed.encode(), "instrumented source mismatch")
        # Reparse original source without changing the measured source file.
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            original = Path(temp) / "original.rs"
            original.write_bytes(source.encode())
            require(ast(original, binary, configuration) == file["inventory"], "AST inventory does not reproduce")
        excluded[path] = [byte_span(source, span) for span in file["inventory"]["excluded"]]
        for symbol in file["inventory"]["symbols"]:
            span = byte_span(source, symbol["span"])
            if symbol["test"]:
                excluded[path].append(span)
                continue
            key = (path, *span)
            require(key not in symbols, "duplicate AST symbol")
            symbols[key] = {**symbol, "instances": [], "regions": {}}
    names = json.loads(subprocess.check_output([str(binary.resolve()), "--demangle"],
        input=json.dumps([f["name"] for f in llvm["data"][0]["functions"]]), encoding="utf-8"))
    for index, function in enumerate(llvm["data"][0]["functions"]):
        require(function["regions"], "LLVM function without regions")
        first = function["regions"][0]
        path = source_paths.get(Path(function["filenames"][first[5]]).resolve())
        if path is None:
            continue
        file = manifest["files"][path]
        mapped = []
        for region in function["regions"]:
            require(len(region) == 8 and all(type(v) is int and v >= 0 for v in region), "invalid LLVM region")
            require(region[7] in (0, 2, 3), "unsupported macro expansion region")
            require(Path(function["filenames"][region[5]]).resolve() == (crate / "src" / path).resolve(),
                    "cross-source LLVM region")
            location = (*original_point(region[:2], file["edits"]), *original_point(region[2:4], file["edits"]))
            if location[:2] != location[2:]:
                mapped.append((*location, region[7], region[4]))
        require(mapped, "function has only synthetic coverage")
        envelope = (*min(r[:2] for r in mapped), *max(r[2:4] for r in mapped))
        if any(contains(s, envelope) for s in excluded[path]):
            continue
        candidates = [k for k in symbols if k[0] == path and contains(k[1:], envelope)]
        inner = [k for k in candidates if not any(k != c and contains(k[1:], c[1:]) for c in candidates)]
        require(len(inner) == 1, f"unmapped/ambiguous LLVM function {path}:{envelope}: {function['name']}")
        key = inner[0]
        symbol = symbols[key]
        # A closure may never borrow its parent's record or counters.
        is_closure = closure_name(names[index])
        require(is_closure == (symbol["kind"] == "closure"), f"function kind mismatch: {path}:{symbol['name']}")
        require(type(function["count"]) is int and function["count"] >= 0, "invalid function counter")
        symbol["instances"].append({"index": index, "name": names[index], "count": function["count"]})
        for *location, kind, hits in mapped:
            region = (*location, kind)
            symbol["regions"][region] = max(symbol["regions"].get(region, 0), hits)
    result = []
    for key, symbol in symbols.items():
        path, *span = key
        require(symbol["instances"], f"missing LLVM function: {path}:{symbol['name']}:{span}")
        children = [k[1:] for k in symbols if k != key and k[0] == path and contains(tuple(span), k[1:])]
        children += [s for s in excluded[path] if contains(tuple(span), s)]
        regions = {r: n for r, n in symbol["regions"].items() if not any(contains(c, r[:4]) for c in children)}
        lines = counts(own_lines(regions, children))
        code = counts({r: n for r, n in regions.items() if r[4] == 0})
        require(code["count"] > 0, "no executable original regions")
        cc = complexity(symbol["raw"])
        score = crap_line(cc, lines["covered"], lines["count"])
        passed = lines["covered"] * 5 >= lines["count"] * 4 and code["covered"] * 5 >= code["count"] * 4 and score <= 30
        result.append({"source": path, **{k: symbol[k] for k in ("name", "kind", "span", "raw", "instances")},
            "syntax_sha256": digest(symbol["syntax"].encode()),
            "source_sha256": manifest["files"][path]["original_sha256"], "cc": cc, "lines": lines, "regions": code,
            "crap_line": float(score), "crap_exact": [score.numerator, score.denominator], "passed": passed,
            "raw_regions": [{"span": list(r[:4]), "kind": r[4], "count": n} for r, n in sorted(regions.items())]})
    return result


def compare(base: dict, head: dict, *, series=SERIES, hotspots=HOTSPOTS) -> dict:
    """Apply the documented incremental ratchet without losing closure debt."""
    require(base["series"] == head["series"] == series, "incompatible base/head series")
    require(base["tools"] == head["tools"], "incompatible base/head measurement tools")
    if series == SERIES or "configuration" in base or "configuration" in head:
        require(base.get("configuration") == head.get("configuration") and base.get("configuration") is not None,
                "incompatible base/head target configurations")
    for report in (base, head):
        if "source_inventory" in report:
            require(set(report["source_inventory"]) == set(SOURCE_FILES), "incomplete production source inventory")
            present = {p for p, sha in report["source_inventory"].items() if sha is not None}
            require(set(hotspots) <= present, "missing selected source inventory")
            require({r["source"] for r in report["functions"]} <= present, "function outside source inventory")
        else:
            require({r["source"] for r in report["functions"]} == set(hotspots), "incomplete selected source inventory")
        for source, names in hotspots.items():
            require(any(r["source"] == source and r["name"] == names[0] for r in report["functions"]),
                    f"missing original hotspot: {source}")
    for source, names in hotspots.items():
        require(all(any(r["source"] == source and r["name"] == name for r in head["functions"])
                    for name in names), f"missing extracted hotspot: {source}")
    old = defaultdict(list)
    for row in base["functions"]:
        old[(row["source"], row["kind"], row["syntax_sha256"])].append(row)
    decisions, failures = [], []
    for row in head["functions"]:
        matches = old[(row["source"], row["kind"], row["syntax_sha256"])]
        previous = matches.pop(0) if matches else None
        changed = previous is None
        selected = row["name"] in hotspots.get(row["source"], [])
        high_risk = selected or (changed and row["cc"] > 10)
        from fractions import Fraction
        passed = row["passed"] if high_risk else (Fraction(*row["crap_exact"]) <= 30 if changed else True)
        identity = {"source": row["source"], "name": row["name"], "span": row["span"],
            "syntax_sha256": row["syntax_sha256"], "changed": changed, "selected": selected,
            "high_risk": high_risk, "accepted": passed,
            "base": None if previous is None else {k: previous[k] for k in ("name", "span", "source_sha256")},
            "head_source_sha256": row["source_sha256"],
            "coverage_debt": not row["passed"]}
        decisions.append(identity)
        if not passed:
            failures.append(f"{row['source']}::{row['name']}")
    return {"series": series, "identities": decisions, "failures": failures,
            **({"configuration": head["configuration"]} if "configuration" in head else {}),
            "decompositions": hotspots,
            "retired_or_changed_base": [{k: r[k] for k in ("source", "name", "span", "syntax_sha256")}
                for rows in old.values() for r in rows]}


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "measure", "compare"))
    parser.add_argument("--crate", type=Path, help="disposable workspace-local source snapshot")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--llvm", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--base", type=Path)
    parser.add_argument("--head", type=Path)
    parser.add_argument("--target", help="compiler target triple; use the same target for coverage")
    args = parser.parse_args()
    if args.operation == "compare":
        require(all((args.base, args.head, args.output)), "compare needs --base, --head and --output")
        report = compare(json.loads(args.base.read_text()), json.loads(args.head.read_text()))
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"failures": report["failures"], "identities": len(report["identities"])}))
        raise SystemExit(bool(report["failures"]))
    require(all((args.crate, args.binary, args.manifest)), "prepare/measure need --crate, --binary and --manifest")
    if args.operation == "prepare":
        require(not args.manifest.exists(), "refusing to overwrite an instrumentation manifest")
        manifest = prepare(args.crate, args.binary, target=args.target)
        args.manifest.write_text(json.dumps(manifest, indent=2) + "\n")
    else:
        require(args.llvm is not None and args.output is not None, "measure needs --llvm and --output")
        manifest = json.loads(args.manifest.read_text())
        require(set(manifest["files"]) | set(manifest["absent_sources"]) == set(SOURCE_FILES),
                "incomplete production source manifest")
        require(not set(manifest["files"]) & set(manifest["absent_sources"]), "ambiguous source presence")
        rows = measure(manifest, json.loads(args.llvm.read_text()), args.crate, args.binary)
        for row in rows:
            row["selected"] = row["name"] in HOTSPOTS.get(row["source"], [])
        report = {"series": SERIES, "configuration": manifest["configuration"], "tools": provenance(args.binary), "functions": rows,
                  "source_inventory": {**{p: f["original_sha256"] for p, f in manifest["files"].items()},
                                       **{p: None for p in manifest["absent_sources"]}},
                  "manifest_sha256": digest(args.manifest.read_bytes()),
                  "llvm_sha256": digest(args.llvm.read_bytes()),
                  "selected_failures": [f"{r['source']}::{r['name']}" for r in rows if r["selected"] and not r["passed"]],
                  "nonselected_debt": [f"{r['source']}::{r['name']}" for r in rows if not r["selected"] and not r["passed"]]}
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"functions": len(rows), "selected_failures": report["selected_failures"],
                          "nonselected_debt_count": len(report["nonselected_debt"])}))
        if report["selected_failures"]:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
