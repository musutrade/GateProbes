#!/usr/bin/env python3
"""Strict production-location coverage; CI adoption is OpenSpec task 8.1."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
import re

from complexity_analyzer import Tokenizer
from quality_common import CRATE, metadata, read_json, sha256, write_json

INVENTORY = Path(__file__).with_name("production-source.json")
METRICS = ("lines", "functions", "regions")
REQUIRED = {"config", "verify", "process", "audit", "scope", "secrets",
            "app", "project", "doctor", "service-core", "quality-core"}


class CoverageTokenizer(Tokenizer):
    """Extend the fixture lexer for production raw/byte/C string literals."""

    def next(self):
        self._skip_ws_and_comments()
        raw = re.match(r'(br|cr|r)(#*)"', self.source[self.position:])
        if raw:
            self._advance(len(raw[1]) - 1)
            return self._raw_string_literal(len(raw[2]))
        if self._peek() in ("b", "c") and self._peek(1) in ('"', "'"):
            self._advance()
            return self._string_literal() if self._peek() == '"' else self._char_literal()
        if self._peek() == "'" and self._peek(2) == "'":
            return self._char_literal()
        return super().next()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def test_ranges(source: str) -> list[tuple[int, int]]:
    """Lex cfg(test) items, never interpreting braces in strings/comments.

    Unsupported compound test cfgs fail instead of guessing their truth table.
    Production cfgs are retained, including cfg(not(test)).
    """
    tokens = CoverageTokenizer(source).tokenize()
    pairs = {}
    stack = []
    for i, token in enumerate(tokens):
        if token.text in ("(", "[", "{"):
            stack.append(i)
        elif token.text in (")", "]", "}"):
            require(bool(stack), "unbalanced Rust source")
            start = stack.pop()
            require(tokens[start].text == {")": "(", "]": "[", "}": "{"}[token.text],
                    "unbalanced Rust source")
            pairs[start] = i
    require(not stack, "unbalanced Rust source")
    ranges = []
    i = 0
    while i < len(tokens) - 1:
        if tokens[i].text != "#" or tokens[i + 1].text != "[":
            i += 1
            continue
        end = pairs[i + 1]
        attribute = [t.text for t in tokens[i + 2:end]]
        is_test = attribute in (["cfg", "(", "test", ")"], ["test"])
        # A conjunction with test as its first operand cannot compile in
        # production, regardless of its remaining platform predicates.
        is_test = is_test or attribute[:6] == ["cfg", "(", "all", "(", "test", ","]
        if attribute[:1] in (["cfg"], ["cfg_attr"]) and "test" in attribute:
            require(is_test or attribute == ["cfg", "(", "not", "(", "test", ")", ")"],
                    "unsupported compound test cfg; extend the exclusion rule explicitly")
        if not is_test:
            i = end + 1
            continue
        j = end + 1
        while j < len(tokens):
            text = tokens[j].text
            if text == "{" or text == ";":
                last = pairs[j] if text == "{" else j
                ranges.append((tokens[i].line, tokens[last].line))
                i = last + 1
                break
            j = pairs[j] + 1 if j in pairs else j + 1
        else:
            raise ValueError("test attribute without a complete item")
    return ranges


def load_inventory(path: Path, crate: Path) -> tuple[dict, dict, dict]:
    inventory = read_json(path)
    require(inventory["schema_version"] == 1 and inventory["version"] == "production-source-2",
            "unsupported production inventory version")
    require(inventory["source_roots"] == ["src", "quality-core"] and inventory["threshold"] == 80,
            "production policy requires src and quality-core inventory and 80% threshold")
    require(inventory["metrics_version"] == "production-location-1", "unknown metrics version")
    require(inventory["inline_exclusions"]["rule"] == "cfg-test-items-1",
            "unknown inline exclusion rule")
    require(bool(inventory["inline_exclusions"]["reason"].strip()), "missing inline exclusion reason")
    boundaries = inventory["boundaries"]
    require({name for name, row in boundaries.items() if row["blocking"]} == REQUIRED,
            "missing or changed blocking boundaries")
    require("service-adapters" in boundaries and not boundaries["service-adapters"]["blocking"],
            "service adapters must remain informational")
    owners = {}
    excluded = {}
    for name, boundary in boundaries.items():
        require(bool(boundary["files"]), f"empty boundary: {name}")
        for source in boundary["files"]:
            require(source not in owners, f"duplicate assignment: {source}")
            owners[source] = name
    for row in inventory["exclusions"]:
        source = row["path"]
        require(source not in owners and source not in excluded, f"duplicate exclusion: {source}")
        require(row["kind"] in ("test", "generated", "benchmark-only") and bool(row["reason"].strip()),
                f"invalid exclusion reason/kind: {source}")
        excluded[source] = row
    for row in inventory["external_exclusions"]:
        require((row["prefix"], row["kind"]) in (("tests/", "test"), ("quality-replay/", "migration-reference")) and bool(row["reason"].strip()),
                "unsupported external exclusion")
    actual = {p.relative_to(crate).as_posix() for root in inventory["source_roots"] for p in (crate / root).rglob("*.rs")}
    declared = owners.keys() | excluded.keys()
    require(actual == declared,
            f"source inventory mismatch: unknown={sorted(actual - declared)}, missing={sorted(declared - actual)}")
    unmapped = set()
    for row in inventory["unmapped_sources"]:
        source = row["path"]
        require(source in owners and source not in unmapped and bool(row["reason"].strip()),
                f"invalid/duplicate unmapped source: {source}")
        require(sha256(crate / source) == row["sha256"],
                f"unmapped declaration source changed; review its executable mappings: {source}")
        unmapped.add(source)
    return inventory, owners, excluded


def read_lcov(path: Path) -> dict[str, dict[int, int]]:
    records = {}
    current = None
    for line in path.read_text().splitlines():
        if line.startswith("SF:"):
            require(current is None, "unterminated LCOV file")
            current = line[3:]
            require(current not in records, f"duplicate LCOV file: {current}")
            records[current] = {}
        elif line.startswith("DA:"):
            require(current is not None, "LCOV line outside file")
            number, count = map(int, line[3:].split(",")[:2])
            require(number > 0 and count >= 0 and number not in records[current], "invalid/duplicate LCOV line")
            records[current][number] = count
        elif line == "end_of_record":
            require(current is not None, "unexpected LCOV end")
            current = None
    require(current is None and bool(records), "empty or incomplete LCOV report")
    return records


def counts(hits: dict) -> dict:
    return metric(sum(bool(hit) for hit in hits.values()), len(hits))


def segment_lines(segments: list) -> dict[int, int]:
    """Reconstruct LLVM LineCoverageStats, independently checking LCOV DA.

    File summaries can count overlapping instantiation lines more than once;
    this series counts each physical executable line once.
    """
    by_line = {}
    previous = (0, 0)
    for segment in segments:
        require(len(segment) == 6 and all(type(v) is int and v >= 0 for v in segment[:3])
                and all(type(v) is bool for v in segment[3:]), "invalid LLVM segment")
        position = tuple(segment[:2])
        require(position >= previous and all(position), "unsorted/invalid LLVM segment")
        previous = position
        by_line.setdefault(segment[0], []).append(segment)
    lines = {}
    wrapped = None
    for line in range(min(by_line, default=1), max(by_line, default=0) + 1):
        current = by_line.get(line, [])
        entries = [s for s in current if s[3] and s[4] and not s[5]]
        skipped = bool(current and not current[0][3] and current[0][4])
        mapped = (not skipped and (bool(wrapped and wrapped[3]) or bool(entries))) or any(
            s[3] and s[4] for s in current)
        if mapped:
            lines[line] = max([wrapped[2] if wrapped else 0, *(s[2] for s in entries)])
        if current:
            wrapped = current[-1]
    return lines


def metric(covered: int, count: int) -> dict:
    return {"covered": covered, "count": count,
            "percent": covered * 100 / count if count else None}


def meets_threshold(covered: int, count: int, threshold: Decimal = Decimal(80)) -> bool:
    require(threshold.is_finite() and Decimal(80) <= threshold <= 100, "invalid threshold (minimum 80)")
    return count > 0 and Decimal(covered) * 100 >= threshold * count


def summarize(raw: Path, lcov: Path, inventory_path: Path = INVENTORY,
              crate: Path = CRATE, threshold: Decimal = Decimal(80), *,
              coverage_root: Path | None = None) -> dict:
    meets_threshold(0, 1, threshold)
    inventory, owners, excluded = load_inventory(inventory_path, crate)
    report = read_json(raw)
    require(report.get("type") == "llvm.coverage.json.export" and len(report["data"]) == 1,
            "expected one LLVM coverage export dataset")
    data = report["data"][0]
    require(bool(data["files"]) and bool(data["functions"]), "empty raw coverage report")
    ranges = {source: test_ranges((crate / source).read_text()) for source in owners}
    line_counts = {source: len((crate / source).read_text().splitlines()) for source in owners}
    files = {source: {name: {} for name in METRICS} for source in owners}

    def source_path(filename: str) -> str:
        path = Path(filename.replace("\\", "/"))
        require(path.is_absolute(), f"coverage path must be absolute: {filename}")
        try:
            relative = path.resolve().relative_to((coverage_root or crate).resolve()).as_posix()
        except ValueError as error:
            raise ValueError(f"unknown coverage path: {filename}") from error
        require(relative in owners or relative in excluded or any(
            relative.startswith(row["prefix"]) for row in inventory["external_exclusions"]),
            f"unknown coverage path: {relative}")
        return relative

    def production(source: str, start: int, end: int) -> bool:
        if source not in owners:
            return False
        require(0 < start <= end <= line_counts[source],
                f"invalid source range: {source}:{start}-{end}")
        for first, last in ranges[source]:
            if first <= start <= end <= last:
                return False
            require(end < first or start > last, f"mixed production/test range: {source}:{start}-{end}")
        return True

    seen = set()
    summaries = {}
    expected_lines = {}
    for item in data["files"]:
        source = source_path(item["filename"])
        require(source not in seen, f"duplicate raw file: {source}")
        seen.add(source)
        summaries[source] = item["summary"]
        expected_lines[source] = segment_lines(item["segments"])
    # A missing source file must never disappear from the denominator. Files
    # without executable mappings are represented explicitly in the inventory.
    unmapped = {row["path"] for row in inventory["unmapped_sources"]}
    require(set(owners) - unmapped <= seen, f"missing raw source reports: {sorted(set(owners) - unmapped - seen)}")
    lcov_seen = set()
    for filename, lines in read_lcov(lcov).items():
        source = source_path(filename)
        require(source in seen and source not in lcov_seen, f"unknown/duplicate LCOV source: {source}")
        lcov_seen.add(source)
        require(lines == expected_lines[source],
                f"LLVM/LCOV line counts disagree: {source}")
        for line, count in lines.items():
            if production(source, line, line):
                files[source]["lines"][line] = count
    require(lcov_seen == seen, f"missing LCOV source reports: {sorted(seen - lcov_seen)}")
    mapped = {source: {"functions": {}, "regions": {}} for source in seen}
    for function in data["functions"]:
        regions = function["regions"]
        require(bool(regions), "function without source regions")
        paths = [source_path(name) for name in function["filenames"]]
        first = regions[0]
        source = paths[first[5]]
        if source not in seen and source not in owners:
            continue
        require(source in seen, f"function missing file report: {source}")
        require(type(function["count"]) is int and function["count"] >= 0, "invalid function count")
        key = tuple(first[:4])
        mapped[source]["functions"][key] = mapped[source]["functions"].get(key, False) or function["count"] > 0
        if production(source, first[0], first[2]):
            key = tuple(first[:4])
            files[source]["functions"][key] = files[source]["functions"].get(key, False) or function["count"] > 0
        for region in regions:
            require(len(region) == 8 and type(region[4]) is int and region[4] >= 0, "invalid region")
            source = paths[region[5]]
            if source not in seen and source not in owners:
                continue
            require(source in seen, f"region missing file report: {source}")
            if region[7] == 0:
                key = tuple(region[:4])
                mapped[source]["regions"][key] = mapped[source]["regions"].get(key, False) or region[4] > 0
            if region[7] == 0 and production(source, region[0], region[2]):
                key = tuple(region[:4])
                files[source]["regions"][key] = files[source]["regions"].get(key, False) or region[4] > 0
    for source, measures in mapped.items():
        for name, hits in measures.items():
            require(len(hits) == summaries[source][name]["count"],
                    f"missing/ambiguous {name} mappings: {source}")
    file_counts = {source: {name: counts(hits) for name, hits in measures.items()}
                   for source, measures in files.items()}

    def aggregate(sources: list[str]) -> dict:
        return {name: metric(sum(file_counts[s][name]["covered"] for s in sources),
                             sum(file_counts[s][name]["count"] for s in sources)) for name in METRICS}

    boundaries = {}
    failures = []
    for name, row in inventory["boundaries"].items():
        measures = aggregate(row["files"])
        # Boundary policy gates lines; function/region counts remain separate
        # evidence for the later function-risk gate, never averaged into lines.
        passed = meets_threshold(measures["lines"]["covered"], measures["lines"]["count"], threshold)
        if row["blocking"] and not passed:
            failures.append(name)
        boundaries[name] = {**measures, "blocking": row["blocking"],
                            "status": ("pass" if passed else "fail") if row["blocking"] else "informational"}
    total = aggregate([source for source, name in owners.items() if inventory["boundaries"][name]["blocking"]])
    total["status"] = "pass" if meets_threshold(total["lines"]["covered"], total["lines"]["count"], threshold) else "fail"
    if total["status"] == "fail":
        failures.append("aggregate")
    return {"schema_version": 1, "inventory_version": inventory["version"],
            "metrics_version": inventory["metrics_version"], "threshold": str(threshold),
            "gate_metric": "lines", "status": "fail" if failures else "pass", "failures": failures,
            "boundaries": boundaries, "aggregate": total, "files": file_counts,
            "exclusions": inventory["exclusions"], "external_exclusions": inventory["external_exclusions"],
            "unmapped_sources": inventory["unmapped_sources"],
            "inline_exclusions": {"rule": inventory["inline_exclusions"], "ranges": ranges},
            "source_sha256": {source: sha256(crate / source) for source in sorted(owners)},
            "raw_artifacts": {str(path): sha256(path) for path in (raw, lcov, inventory_path)}}


def run(raw: Path, lcov: Path, output: Path, threshold: Decimal = Decimal(80)) -> int:
    result = metadata(tool="production-coverage", command="coverage.py --production", candidate=True)
    try:
        result.update(summarize(raw, lcov, threshold=threshold))
    except (ValueError, OSError, KeyError, IndexError, TypeError) as error:
        result.update(status="fail", error=str(error))
        write_json(output, result)
        output.with_suffix(".md").write_text(f"# Production coverage candidate\n\nStatus: fail\n\n{error}\n")
        return 1
    write_json(output, result)
    lines = ["# Production coverage candidate", "", f"Status: {result['status']}; line threshold: {threshold}%", "",
             "| Boundary | Lines | Functions | Regions | Status |", "| --- | ---: | ---: | ---: | --- |"]
    for name, row in {**result["boundaries"], "aggregate": result["aggregate"]}.items():
        values = [f"{row[key]['covered']}/{row[key]['count']}" for key in METRICS]
        lines.append(f"| {name} | {' | '.join(values)} | {row['status']} |")
    output.with_suffix(".md").write_text("\n".join(lines) + "\n")
    return int(result["status"] != "pass")
