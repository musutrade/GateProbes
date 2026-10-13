#!/usr/bin/env python3
"""Versioned, source-location based joins of locked complexity and LLVM evidence."""
from __future__ import annotations

import hashlib
from fractions import Fraction
from pathlib import Path

from complexity_analyzer import analyze_source
from production_coverage import counts, require, test_ranges
from quality_evidence import validate_evidence

MAPPING_VERSION = "function-location-1"
CRAP_VERSION = "crap-line-1"


def crap_line(cc: int, covered: int, total: int) -> Fraction:
    require(type(cc) is int and cc >= 1, "invalid complexity")
    require(type(covered) is int and type(total) is int and 0 <= covered <= total and total > 0,
            "missing/invalid executable line counts")
    return cc * cc * (1 - Fraction(covered, total)) ** 3 + cc


def span_key(span: dict, source: str | None = None) -> tuple:
    start, end = span["start_column"], span["end_column"] + 1
    if source is not None:
        lines = source.splitlines(keepends=True)
        start = len(lines[span["start_line"] - 1][:start - 1].encode()) + 1
        end = len(lines[span["end_line"] - 1][:end - 1].encode()) + 1
    return (span["start_line"], start, span["end_line"], end)


def contains(outer: tuple, inner: tuple) -> bool:
    return outer[:2] <= inner[:2] and inner[2:4] <= outer[2:4]


def source_slice(source: str, span: tuple) -> str:
    data = source.encode()
    lines = data.splitlines(keepends=True)
    start = sum(map(len, lines[:span[0] - 1])) + span[1] - 1
    end = sum(map(len, lines[:span[2] - 1])) + span[3] - 1
    require(0 <= start < end <= len(data), "invalid symbol source span")
    return data[start:end].decode()


def own_lines(regions: dict, children: list[tuple]) -> dict:
    """Sweep own LLVM regions; nested regions override enclosing counters.

    Line coverage is the union of counted, non-gap intervals on each physical
    line. Child symbol intervals are removed so closure execution cannot supply
    evidence for its parent. Instantiations are merged by max before this sweep.
    """
    points = sorted({p for r in regions for p in (r[:2], r[2:4])} |
                    {p for r in children for p in (r[:2], r[2:4])})
    lines = {}
    for start, end in zip(points, points[1:]):
        if any(c[:2] <= start < c[2:4] for c in children):
            continue
        active = [r for r in regions if r[:2] <= start < r[2:4]]
        if not active:
            continue
        # Innermost source interval; contradictory equal spans are rejected at join.
        inner = max(active, key=lambda r: (r[:2], tuple(-v for v in r[2:4])))
        if inner[4] != 0:  # skipped and gap regions carry no executable lines
            continue
        last = end[0] - (end[1] == 1)
        for line in range(start[0], last + 1):
            lines[line] = max(lines.get(line, 0), regions[inner])
    return lines


def map_functions(records: list[dict], llvm: dict, crate: Path, owners: dict,
                  commit: str, unmapped: set[str] | None = None, *,
                  coverage_root: Path | None = None) -> list[dict]:
    """Join bidirectionally: neither missing complexity nor missing LLVM is OK."""
    require(llvm["type"] == "llvm.coverage.json.export" and len(llvm["data"]) == 1,
            "expected one LLVM coverage dataset")
    symbols = {}
    sources = {}
    excluded = {}
    seen = set()
    for record in records:
        path = record["series"]["source"]["path"]
        require(path in owners and path not in seen, f"unknown/duplicate complexity source: {path}")
        seen.add(path)
        data = (crate / path).read_bytes()
        source = data.decode("utf-8")
        validate_evidence(record, expected_commit=commit,
                          expected_source_sha256=hashlib.sha256(data).hexdigest(),
                          expected_source_bytes=len(data))
        rebuilt = analyze_source(source, path)
        require(record["series"]["analyzer"] == rebuilt["series"]["analyzer"] and
                record["series"]["rule"] == rebuilt["series"]["rule"] and
                record["symbols"] == rebuilt["symbols"],
                f"complexity evidence does not reproduce: {path}")
        sources[path] = source
        excluded[path] = test_ranges(source)
        for symbol in record["symbols"]:
            span = span_key(symbol["span"], source)
            if any(a <= span[0] <= span[2] <= b for a, b in excluded[path]):
                continue
            key = (path, *span)
            require(key not in symbols, f"ambiguous complexity location: {key}")
            symbols[key] = {**symbol, "instances": [], "regions": {}, "hits": 0}
    require(set(owners) - (unmapped or set()) <= seen, "missing complexity source reports")

    def relative(filename):
        try:
            return Path(filename).resolve().relative_to((coverage_root or crate).resolve()).as_posix()
        except ValueError:
            return None

    for index, function in enumerate(llvm["data"][0]["functions"]):
        regions = function["regions"]
        require(bool(regions), "LLVM function without regions")
        require(type(function["count"]) is int and function["count"] >= 0, "invalid function counter")
        paths = [relative(p) for p in function["filenames"]]
        for region in regions:
            require(len(region) == 8 and all(type(v) is int and v >= 0 for v in region),
                    "invalid LLVM region")
            require(region[5] < len(paths) and tuple(region[:2]) < tuple(region[2:4]) and
                    region[7] in (0, 1, 2, 3), "unsupported/invalid LLVM region mapping")
        first = regions[0]
        path = paths[first[5]]
        if path not in owners:
            continue  # production inventory validator checks external exclusions
        if any(a <= first[0] <= first[2] <= b for a, b in excluded.get(path, [])):
            continue
        # LLVM 22 emits disjoint signature/body regions, not one enclosing
        # region. Their envelope joins to the source symbol's closing token.
        envelope = (*min(tuple(r[:2]) for r in regions), *max(tuple(r[2:4]) for r in regions))
        candidates = [k for k in symbols if k[0] == path and contains(k[1:], envelope)
                      and k[3:5] == envelope[2:4]]
        innermost = [k for k in candidates if not any(
            k != other and contains(k[1:], other[1:]) for other in candidates)]
        require(len(innermost) == 1, f"unmapped/ambiguous LLVM function: {path}:{first[:4]}")
        key = innermost[0]
        symbol = symbols[key]
        symbol["instances"].append({"index": index, "name": function["name"], "count": function["count"]})
        symbol["hits"] = max(symbol["hits"], function["count"])
        for region in regions:
            require(paths[region[5]] == path and contains(key[1:], tuple(region[:4])),
                    f"unmapped expansion/outside function region: {path}:{region[:4]}")
            require(region[7] != 1, "macro expansion requires reviewed source mapping")
            location = (*region[:4], region[7])
            require(not any(r[:4] == location[:4] and r[4] != location[4]
                            for r in symbol["regions"]), "conflicting LLVM region kinds")
            symbol["regions"][location] = max(symbol["regions"].get(location, 0), region[4])
    result = []
    for key, symbol in sorted(symbols.items()):
        path, *span = key
        require(bool(symbol["instances"]), f"missing LLVM function: {symbol['id']}")
        children = [k[1:] for k in symbols if k != key and k[0] == path and contains(tuple(span), k[1:])]
        regions = {r: hit for r, hit in symbol["regions"].items()
                   if not any(contains(c, r[:4]) for c in children)}
        lines = counts(own_lines(regions, children))
        code_regions = {r: hit for r, hit in regions.items() if r[4] == 0}
        require(bool(code_regions), f"missing executable regions: {symbol['id']}")
        cc = symbol["metrics"]["cyclomatic_complexity"]
        score = crap_line(cc, lines["covered"], lines["count"])
        result.append({
            **{k: symbol[k] for k in ("id", "kind", "qualified_name", "source", "span", "raw")},
            "body_sha256": hashlib.sha256(source_slice(sources[path], tuple(span)).encode()).hexdigest(),
            "boundary": owners[path], "cc": cc, "lines": lines,
            "functions": counts({tuple(span): symbol["hits"]}), "regions": counts(code_regions),
            "crap_line": float(score), "crap_line_exact": {"numerator": score.numerator, "denominator": score.denominator},
            "instances": symbol["instances"],
            "raw_regions": [{"span": list(r[:4]), "kind": r[4], "count": hit} for r, hit in sorted(regions.items())],
        })
    require(bool(result), "empty production function evidence")
    return result
