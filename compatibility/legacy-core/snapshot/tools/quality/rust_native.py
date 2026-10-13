#!/usr/bin/env python3
"""Opt-in, bounded native MIR/LLVM experiment. Never an authoritative collector.

The supported domain is one dependency-free rustc binary, without test cfg.
Cargo/procedural macro backends are audited separately, not certified by this
fixture adapter. MIR is unstable: accepting another compiler requires review.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


SERIES = {
    "id": "rust-native-production-experiment/1",
    "mapping": "mir-instrument-coverage-exact-regions/1",
    "complexity": "mir-normal-cfg/1",
    "selection": "single-crate-no-test-cfg/1",
    "lines": "any-owned-code-region/1",
    "instances": "same-mir-owner-sum-counters/1",
}
# The compiler's textual MIR is not a versioned interface.
SUPPORTED_COMMIT = "8bab26f4f68e0e26f0bb7960be334d5b520ea452"
REGION = re.compile(r"^    coverage Code \{ bcb: bcb\d+ \} => (.*):(\d+):(\d+): (\d+):(\d+) \(#(\d+)\);$", re.M)
HEADER = re.compile(r"^// MIR for `(.+)` after InstrumentCoverage$")
BLOCK = re.compile(r"^    bb(\d+)( \(cleanup\))?: \{\n(.*?)^    \}", re.M | re.S)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def cfg_complexity(text):
    """E-N+2 over reachable normal edges plus one common exit.

    Unwind, coroutine drop and imaginary edges are excluded explicitly. Every
    normal terminator must be recognized; new compiler syntax fails closed.
    """
    graph = {}
    for number, cleanup, body in BLOCK.findall(text):
        if cleanup:
            continue
        code = "\n".join(line.split("//", 1)[0].strip() for line in body.splitlines())
        statements = [s.strip() for s in code.split(";") if s.strip()]
        require(bool(statements), "empty MIR basic block")
        terminator = statements[-1]
        if terminator in {"return", "unreachable", "coroutine_drop", "abort"}:
            successors = ["exit"]
        elif "->" in terminator:
            target = terminator.rsplit("->", 1)[1]
            target = re.sub(r"(?:unwind|drop|imaginary): bb\d+", "", target)
            successors = re.findall(r"\bbb(\d+)\b", target)
            require(bool(successors) or "unwind" in target, "unknown MIR terminator: " + terminator)
            successors = successors or ["exit"]
        else:
            raise ValueError("unknown MIR terminator: " + terminator)
        graph[number] = successors
    require("0" in graph, "missing MIR entry")
    visited, pending, edges = set(), ["0"], 0
    while pending:
        block = pending.pop()
        if block in visited:
            continue
        visited.add(block)
        if block == "exit":
            continue
        require(block in graph, "normal edge to missing/cleanup block")
        edges += len(graph[block])
        pending.extend(graph[block])
    require("exit" in visited, "nonterminating CFG needs a separate rule")
    result = edges - len(visited) + 2
    require(result >= 1, "invalid CFG complexity")
    return result


def mir_inventory(directory):
    owners, excluded = [], []
    for path in sorted(directory.glob("*.InstrumentCoverage.after.mir")):
        text = path.read_text()
        match = HEADER.fullmatch(text.splitlines()[0])
        require(match is not None, f"unsupported MIR header: {path.name}")
        name = match[1]
        if not re.search(r"^fn ", text, re.M):
            excluded.append({"name": name, "artifact": path.name, "reason": "compiler-constant-body"})
            continue
        regions = []
        for source, *coords, context in REGION.findall(text):
            regions.append({"source": source, "span": list(map(int, coords)), "context": int(context)})
        coverage_lines = re.findall(r"^    coverage .*", text, re.M)
        require(len(coverage_lines) == len(regions), f"unsupported MIR mapping kind: {name}")
        owners.append({"name": name, "artifact": path.name, "mir_sha256": digest(path.read_bytes()),
                       "kind": "async-body" if re.search(r"^yields ", text, re.M) else
                       "closure" if "{closure#" in name else "function",
                       "regions": regions, "cc": cfg_complexity(text) if regions else None})
    require(bool(owners), "empty compiler function inventory")
    return owners, excluded


def region_key(region):
    return (region["source"], *region["span"])


def expansion_contexts(text, owners):
    """Retain compiler hygiene chains; this dump does not supply call-site spans."""
    expansions, contexts = {}, {}
    expansion = re.compile(r"(crate\d+::\{\{expn\d+\}\}): parent: (crate\d+::\{\{expn\d+\}\}), call_site_ctxt: #(\d+), def_site_ctxt: #(\d+), kind: (.+)")
    context = re.compile(r"#(\d+): parent: #(\d+), outer_mark: \((crate\d+::\{\{expn\d+\}\}), (Opaque|Transparent|SemiOpaque)\)")
    for line in text.splitlines():
        if match := expansion.fullmatch(line):
            key, parent, call, definition, kind = match.groups()
            require(key not in expansions, "duplicate expansion identity")
            expansions[key] = {"parent": parent, "call_context": int(call), "definition_context": int(definition), "kind": kind}
        if match := context.fullmatch(line):
            key, parent, mark, transparency = match.groups()
            require(int(key) not in contexts, "duplicate syntax context")
            contexts[int(key)] = {"parent": int(parent), "expansion": mark, "transparency": transparency}
    require(0 in contexts and bool(expansions), "missing compiler expansion graph")
    for node in expansions.values():
        require(node["parent"] in expansions and node["call_context"] in contexts and
                node["definition_context"] in contexts, "incomplete expansion graph")
    for owner in owners:
        for region in owner["regions"]:
            current, seen = region["context"], set()
            while True:
                require(current in contexts and current not in seen, "missing/cyclic syntax context")
                seen.add(current)
                node = contexts[current]
                require(node["expansion"] in expansions, "unowned expansion context")
                if current == 0:
                    break
                current = node["parent"]
    return {"expansions": expansions, "contexts": contexts, "invocation_spans_complete": False}


def name_matches(owner, demangled):
    # This adapter supports free functions and their nested closures. Methods
    # and opaque generated identities need compiler DefId evidence, not guesses.
    return demangled == "native_probe::" + owner or demangled.startswith("native_probe::" + owner + "::<")


def map_functions(owners, llvm, demangled):
    require(llvm.get("type") == "llvm.coverage.json.export" and llvm.get("version") == "3.1.0",
            "unsupported LLVM export schema")
    require(len({r["name"] for r in owners}) == len(owners), "ambiguous MIR owner identity")
    require(len(llvm.get("data", [])) == 1, "ambiguous LLVM data units")
    functions = llvm["data"][0]["functions"]
    require(len(demangled) == len(functions), "missing demangled identity")
    require(len({f["name"] for f in functions}) == len(functions), "duplicate LLVM function instance")
    expected = {}
    for owner in owners:
        keys = [region_key(r) for r in owner["regions"]]
        require(bool(keys), f"unobserved compiler function: {owner['name']}")
        require(len(keys) == len(set(keys)), f"duplicate MIR region: {owner['name']}")
        expected[owner["name"]] = frozenset(keys)
    groups = defaultdict(list)
    for function, demangle in zip(functions, demangled):
        require(type(function["count"]) is int and function["count"] >= 0, "invalid function counter")
        require(not function.get("branches") and not function.get("mcdc_records"), "unsupported branch/MC/DC mappings")
        regions = []
        for raw in function["regions"]:
            require(len(raw) == 8 and all(type(v) is int and v >= 0 for v in raw), "invalid raw region")
            require(raw[7] == 0 and raw[6] == 0, "unsupported LLVM region/expansion kind")
            require(raw[5] < len(function["filenames"]), "invalid LLVM file ID")
            require((raw[0], raw[1]) < (raw[2], raw[3]), "empty/reversed LLVM region")
            regions.append({"source": function["filenames"][raw[5]], "span": raw[:4], "count": raw[4]})
        keys = [region_key(r) for r in regions]
        require(len(keys) == len(set(keys)), "duplicate LLVM region")
        candidates = [o for o in owners if expected[o["name"]] == frozenset(keys)
                      and name_matches(o["name"], demangle)]
        require(len(candidates) == 1, f"unowned/ambiguous LLVM instance: {demangle}")
        groups[candidates[0]["name"]].append({"name": function["name"], "demangled": demangle,
                                            "count": function["count"], "regions": regions})
    require(set(groups) == set(expected), "missing LLVM owner(s): " + ", ".join(sorted(set(expected) - set(groups))))
    rows = []
    for owner in owners:
        instances = groups[owner["name"]]
        merged = {key: 0 for key in expected[owner["name"]]}
        for instance in instances:
            for region in instance["regions"]:
                merged[region_key(region)] += region["count"]
        lines = defaultdict(int)
        for (source, start, _column, end, end_column), count in merged.items():
            for line in range(start, end + (end_column > 1)):
                lines[(source, line)] = max(lines[(source, line)], count)
        covered = sum(v > 0 for v in lines.values())
        require(bool(lines), "no measurable production lines")
        coverage = Fraction(covered, len(lines))
        crap = owner["cc"] ** 2 * (1 - coverage) ** 3 + owner["cc"]
        region_covered = sum(v > 0 for v in merged.values())
        rows.append({**owner, "instances": instances, "count": sum(i["count"] for i in instances),
                     "lines": {"covered": covered, "count": len(lines)},
                     "line_counts": [[source, line, count] for (source, line), count in sorted(lines.items())],
                     "region_coverage": {"covered": region_covered, "count": len(merged)},
                     "crap_exact": [crap.numerator, crap.denominator],
                     "passed": coverage >= Fraction(4, 5) and Fraction(region_covered, len(merged)) >= Fraction(4, 5) and crap <= 30})
    return rows


def run(command, directory, name, *, env=None, stdin=None):
    result = subprocess.run(list(map(str, command)), cwd=directory, env=env,
                            input=stdin, capture_output=True)
    (directory / (name + ".stdout")).write_bytes(result.stdout)
    (directory / (name + ".stderr")).write_bytes(result.stderr)
    write_json(directory / (name + ".command.json"), {
        "argv": list(map(str, command)), "cwd": str(directory), "exit_code": result.returncode,
        "environment": {key: env[key] for key in ("RUSTC_BOOTSTRAP", "LLVM_PROFILE_FILE") if env and key in env}})
    require(result.returncode == 0, f"{name} failed ({result.returncode}): {directory / (name + '.stderr')}")
    return result.stdout


def compiler_flags(cfg):
    require(all(re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*(?:="[A-Za-z_0-9-]+")?', item)
                and item != "test" for item in cfg), "unsupported/test cfg")
    flags = ["--edition=2021", "--crate-name=native_probe", "-C", "instrument-coverage",
             "-C", "link-dead-code", "-C", "opt-level=0"]
    for item in cfg:
        flags.extend(["--cfg", item])
    return flags


def collect(source, output, analyzer, cfg=()):
    require(not output.exists(), "refusing to overwrite raw native evidence")
    flags = compiler_flags(cfg)
    output.mkdir(parents=True)
    output = output.resolve()
    raw = output / "raw"
    raw.mkdir()
    env = {**os.environ, "RUSTC_BOOTSTRAP": "1", "LLVM_PROFILE_FILE": str(raw / "sample.profraw")}
    try:
        shutil.copyfile(source, raw / "source.rs")
        shutil.copyfile(analyzer, raw / "analyzer")
        (raw / "analyzer").chmod(0o755)
        rustc = run(["rustc", "-vV"], raw, "rustc", env=env).decode()
        require(f"commit-hash: {SUPPORTED_COMMIT}\n" in rustc, "unsupported rustc commit for textual MIR")
        host = re.search(r"^host: (.+)$", rustc, re.M)[1]
        sysroot = run(["rustc", "--print", "sysroot"], raw, "sysroot", env=env).decode().strip()
        llvm_bin = Path(sysroot) / "lib/rustlib" / host / "bin"
        cov, profdata = llvm_bin / "llvm-cov", llvm_bin / "llvm-profdata"
        tools = {"rustc": rustc, "bootstrap": "1", "analyzer_sha256": digest(analyzer.read_bytes())}
        for path in (cov, profdata):
            tools[path.name] = {"sha256": digest(path.read_bytes()),
                               "version": run([path, "--version"], raw, path.name, env=env).decode()}
        run(["rustc", "--print", "cfg", *flags], raw, "cfg", env=env)
        run(["rustc", "source.rs", *flags, "-Zunpretty=expanded,hygiene"], raw, "expansion", env=env)
        run(["rustc", "source.rs", *flags, "--emit=link,llvm-ir,mir,dep-info",
             "-Zmir-include-spans=yes", "-Zdump-mir=InstrumentCoverage", "-Zdump-mir-dir=mir"], raw, "compile", env=env)
        deps = (raw / "native_probe.d").read_text()
        require(all(line.endswith(": source.rs") or line == "source.rs:" or not line
                    for line in deps.splitlines()), "single-file adapter cannot certify additional compilation inputs")
        run([raw / "native_probe"], raw, "sample", env=env)
        run([profdata, "merge", "-sparse", "sample.profraw", "-o", "sample.profdata"], raw, "merge", env=env)
        export = run([cov, "export", "native_probe", "-instr-profile=sample.profdata"], raw, "llvm", env=env)
        functions = json.loads(export)["data"][0]["functions"]
        run([raw / "analyzer", "--demangle"], raw, "demangle", env=env,
            stdin=json.dumps([f["name"] for f in functions]).encode())
        write_json(raw / "identity.json", {"series": SERIES, "tools": tools, "flags": flags, "cfg": list(cfg),
                   "build_directory": str(raw),
                   "scope": "standalone-single-file-fixture", "test_selection": "rustc-without-test-cfg"})
    finally:
        write_json(output / "evidence.json", {"artifacts": {str(p.relative_to(raw)): digest(p.read_bytes())
                   for p in sorted(raw.rglob("*")) if p.is_file()}})
    return digest((output / "evidence.json").read_bytes())


def certify(output, expected_sha256):
    """Recompute a bounded certificate from anchored raw compiler artifacts."""
    output = output.resolve()
    manifest = output / "evidence.json"
    require(not manifest.is_symlink(), "evidence manifest must not be a symlink")
    require(digest(manifest.read_bytes()) == expected_sha256, "evidence manifest anchor mismatch")
    raw = output / "raw"
    paths = sorted(raw.rglob("*"))
    require(not raw.is_symlink() and not any(p.is_symlink() for p in paths), "raw evidence symlink")
    actual = {str(p.relative_to(raw)): digest(p.read_bytes()) for p in paths if p.is_file()}
    require(actual == json.loads(manifest.read_text())["artifacts"], "raw evidence tampering/omission")
    identity = json.loads((raw / "identity.json").read_text())
    require(identity["series"] == SERIES, "incompatible native series")
    require(f"commit-hash: {SUPPORTED_COMMIT}\n" in identity["tools"]["rustc"], "incompatible toolchain")
    require(identity["scope"] == "standalone-single-file-fixture", "unsupported certification scope")
    require(identity["flags"] == compiler_flags(identity["cfg"]), "unsupported compiler flags")
    require(json.loads((raw / "compile.command.json").read_text())["argv"] ==
            ["rustc", "source.rs", *identity["flags"], "--emit=link,llvm-ir,mir,dep-info",
             "-Zmir-include-spans=yes", "-Zdump-mir=InstrumentCoverage", "-Zdump-mir-dir=mir"],
            "compile command identity mismatch")
    require(all(line.endswith(": source.rs") or line == "source.rs:" or not line
                for line in (raw / "native_probe.d").read_text().splitlines()), "unretained compilation inputs")
    require(identity["test_selection"] == "rustc-without-test-cfg", "unsupported test selection")
    require("test" not in (raw / "cfg.stdout").read_text().splitlines(), "test cfg is not production")
    for stage in ("rustc", "sysroot", "cfg", "expansion", "compile", "sample", "merge", "llvm", "demangle"):
        require(json.loads((raw / (stage + ".command.json")).read_text())["exit_code"] == 0,
                f"failed native evidence stage: {stage}")
    require((raw / "rustc.stdout").read_text() == identity["tools"]["rustc"], "compiler identity mismatch")
    require(digest((raw / "analyzer").read_bytes()) == identity["tools"]["analyzer_sha256"], "analyzer identity mismatch")
    require((raw / "native_probe.ll").stat().st_size > 0, "missing LLVM IR")
    owners, excluded = mir_inventory(raw / "mir")
    provenance = expansion_contexts((raw / "expansion.stdout").read_text(), owners)
    aggregate_names = re.findall(r"^fn (.*?)\(", (raw / "native_probe.mir").read_text(), re.M)
    require(sorted(aggregate_names) == sorted(o["name"] for o in owners), "MIR inventory omission/ambiguity")
    # A new hash of edited JSON is not native evidence. Re-export the retained
    # binary and raw profile with locally installed, hash-matched LLVM tools.
    # Never execute an archived binary or analyzer during certification.
    sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    host = re.search(r"^host: (.+)$", identity["tools"]["rustc"], re.M)[1]
    llvm_bin = sysroot / "lib/rustlib" / host / "bin"
    for name in ("llvm-cov", "llvm-profdata"):
        require(digest((llvm_bin / name).read_bytes()) == identity["tools"][name]["sha256"], "incompatible replay toolchain")
    with tempfile.TemporaryDirectory(prefix="audit-", dir=output) as temp:
        merged = Path(temp) / "sample.profdata"
        subprocess.run([llvm_bin / "llvm-profdata", "merge", "-sparse", raw / "sample.profraw", "-o", merged],
                       capture_output=True, check=True)
        replay = subprocess.check_output([llvm_bin / "llvm-cov", "export", raw / "native_probe",
                                          "-instr-profile=" + str(merged)])
        require(json.loads(replay) == json.loads((raw / "llvm.stdout").read_text()), "LLVM export differs from native artifacts")
    # LLVM filenames may be made absolute by the compiler. Both inputs must
    # identify the actual retained source, never a matching basename elsewhere.
    llvm = json.loads((raw / "llvm.stdout").read_text())
    for function in llvm["data"][0]["functions"]:
        function["filenames"] = ["source.rs" if Path(p) == Path(identity["build_directory"]) / "source.rs" else p
                                 for p in function["filenames"]]
    require(all(r["source"] == "source.rs" for o in owners for r in o["regions"]), "unretained source origin")
    rows = map_functions(owners, llvm, json.loads((raw / "demangle.stdout").read_text()))
    line_counts = defaultdict(int)
    for row in rows:
        for source, line, count in row["line_counts"]:
            line_counts[(source, line)] = max(line_counts[(source, line)], count)
    return {**identity, "evidence_sha256": expected_sha256, "certified_llvm_mapping": True,
            "backend_complete": False, "source_provenance_complete": False,
            "expansion_provenance": provenance,
            "functions": rows, "excluded_constant_bodies": excluded,
            "source_sha256": digest((raw / "source.rs").read_bytes()),
            "coverage": {"lines": {"covered": sum(v > 0 for v in line_counts.values()), "count": len(line_counts)},
                         "regions": {k: sum(r["region_coverage"][k] for r in rows) for k in ("covered", "count")},
                         "functions": {"covered": sum(r["count"] > 0 for r in rows), "count": len(rows)}},
            "threshold_failures": [r["name"] for r in rows if not r["passed"]]}


def compatible(base, head):
    for key in ("series", "tools", "flags", "cfg", "scope", "test_selection"):
        require(base[key] == head[key], f"incompatible history: {key}")
    require(base["series"] == SERIES, "incompatible history series")
    require(base.get("certified_llvm_mapping") is True and head.get("certified_llvm_mapping") is True,
            "uncertified history")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("collect", "certify", "audit-mir"))
    parser.add_argument("--source", type=Path)
    parser.add_argument("--analyzer", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--cfg", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "collect":
        require(args.source is not None and args.analyzer is not None, "collect requires source and analyzer")
        print(collect(args.source, args.output, args.analyzer, args.cfg))
    elif args.operation == "audit-mir":
        owners, excluded = mir_inventory(args.evidence)
        names = defaultdict(list)
        for owner in owners:
            names[owner["name"]].append(owner["artifact"])
        report = {"certified_llvm_mapping": False, "functions": owners, "constant_bodies": excluded,
                  "unobserved": [r["name"] for r in owners if not r["regions"]],
                  "ambiguous_names": {name: paths for name, paths in names.items() if len(paths) > 1}}
        write_json(args.output, report)
        print(json.dumps({"functions": len(owners), "unobserved": len(report["unobserved"])}))
    else:
        report = certify(args.evidence, args.expected_sha256)
        write_json(args.output, report)
        print(json.dumps({"coverage": report["coverage"], "threshold_failures": report["threshold_failures"]}))
        raise SystemExit(bool(report["threshold_failures"]))


if __name__ == "__main__":
    main()
