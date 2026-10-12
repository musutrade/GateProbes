"""Source-owned Rust complexity and LLVM source coverage; no gate verdicts."""
import argparse
from collections import defaultdict
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import subprocess

SCHEMA = 'rust-source-risk/v1'

def strict_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f'duplicate JSON key: {key}')
            result[key] = value
        return result
    def integer(value):
        result = int(value)
        if abs(result) > 2**53 - 1:
            raise ValueError('unsafe integer')
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=pairs, parse_int=integer,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))

def ratio(numerator, denominator):
    return {'numerator': numerator, 'denominator': denominator} if denominator else None

def crap(complexity, covered, total):
    if not total:
        return None
    value = complexity + complexity**2 * (1 - Fraction(covered, total))**3
    return ratio(value.numerator, value.denominator)

def point_offset(source, point):
    lines = source.splitlines(keepends=True)
    line, column = point
    if not 1 <= line <= len(lines) or not 1 <= column <= len(lines[line-1]) + 1:
        raise ValueError(f'out-of-source position: {point}')
    prefix = lines[line-1][:column-1]
    prefix.decode('utf-8')  # LLVM columns must lie at character boundaries.
    return sum(map(len, lines[:line-1])) + column - 1

def line_coverage(source, regions, excluded):
    """Sweep half-open code ranges, choosing innermost ranges over outer counts.

    Counts are merged across monomorphizations before this operation. Nested
    callable ranges are removed from their parent. Gaps never create code lines.
    """
    boundaries = sorted({p for r in regions for p in r[:2]} | {p for r in excluded for p in r})
    lines = {}
    for start, end in zip(boundaries, boundaries[1:]):
        if start == end or any(a <= start < b for a, b in excluded):
            continue
        active = [r for r in regions if r[0] <= start and end <= r[1]]
        if not active:
            continue
        inner = [r for r in active if not any(r[0] <= s[0] and s[1] <= r[1] and r[:2] != s[:2] for s in active)]
        if len(inner) != 1:
            raise ValueError('crossing source regions are ambiguous')
        covered = inner[0][2] > 0
        cursor = start
        for fragment in source[start:end].splitlines(keepends=True):
            # Whitespace between regions cannot manufacture line coverage.
            if fragment.strip():
                line = source[:cursor].count(b'\n') + 1
                lines[line] = lines.get(line, False) or covered
            cursor += len(fragment)
    return sum(lines.values()), len(lines)

def source_inventories(source_root, production_files, ast_binary):
    """Validate paths first, then report compatibility failures across all files.

    Failed inventories are never returned as an incomplete production boundary.
    Corrupt paths or unavailable tooling remain immediate infrastructure errors.
    """
    root = Path(source_root).resolve(strict=True)
    paths = {}
    for relative in production_files:
        p = Path(relative)
        if p.is_absolute() or '..' in p.parts or str(p) != relative or p.suffix != '.rs':
            raise ValueError('noncanonical production source path')
        path = root / p
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(root):
            raise ValueError('source escapes root')
        if relative in paths:
            raise ValueError('duplicate source')
        paths[relative] = path
    inventories = {}
    errors = []
    for relative, path in sorted(paths.items()):
        result = subprocess.run([str(ast_binary), str(path)], capture_output=True, text=True)
        if result.returncode == 1:
            errors.append(f'{relative}: {result.stderr.strip() or "inventory rejected source"}')
        else:
            result.check_returncode()
            inventories[relative] = json.loads(result.stdout)
    if errors:
        raise ValueError('source compatibility failed; no measurements produced:\n' + '\n'.join(errors))
    return inventories


def measure(source_root, production_files, llvm_path, ast_binary, coverage_root=None):
    root = Path(source_root).resolve(strict=True)
    native_root = Path(coverage_root or root)
    llvm = strict_json(llvm_path)
    if llvm.get('type') != 'llvm.coverage.json.export' or llvm.get('version') != '3.1.0':
        raise ValueError('unsupported LLVM source coverage format')
    inventories = source_inventories(root, production_files, ast_binary)
    paths = {str(native_root / relative): relative for relative in inventories}
    native = defaultdict(list)
    names = set()
    mapping_errors = []
    for unit in llvm['data']:
        for function in unit['functions']:
            if not function['regions']:
                raise ValueError('native function without region')
            if type(function['count']) is not int or function['count'] < 0:
                raise ValueError('invalid native entry count')
            for region in function['regions']:
                if len(region) != 8 or any(type(v) is not int or v < 0 for v in region):
                    raise ValueError('invalid native region')
                if region[5] >= len(function['filenames']):
                    raise ValueError('invalid native file index')
            first = function['regions'][0]
            filename = function['filenames'][first[5]]
            relative = paths.get(filename)
            if relative is None:
                # Dependencies are outside the signed production inventory.
                if Path(filename).is_relative_to(native_root) and '/tests/' not in filename:
                    mapping_errors.append(f'uninventoried project function: {filename}:{first[:2]}')
                continue
            key = (filename, function['name'])
            if key in names:
                raise ValueError('duplicate native function')
            names.add(key)
            matches = [i for i, f in enumerate(inventories[relative]) if first[:2] in f['anchors']]
            if len(matches) != 1:
                detail = 'missing' if not matches else 'ambiguous'
                mapping_errors.append(f'{detail} exact source anchor: {relative}:{first[:2]}')
                continue
            native[relative, matches[0]].append(function)
    missing = [f'{relative}:{f["start"]} ({f["kind"]})'
               for relative, functions in inventories.items()
               for index, f in enumerate(functions) if not native[relative, index]]
    if missing:
        mapping_errors.append('source callable missing native mapping: ' + '; '.join(missing)
                              + '; no exact LLVM entry counter; parent execution is not a substitute')
    if mapping_errors:
        # Monomorphizations may repeat the same bad source position. Retain
        # every distinct diagnostic without flooding the operator with copies.
        raise ValueError('source mapping failed; no measurements produced:\n'
                         + '\n'.join(dict.fromkeys(mapping_errors)))
    results = []
    for relative, functions in inventories.items():
        source = (root / relative).read_bytes()
        spans = [(point_offset(source, f['start']), point_offset(source, f['end'])) for f in functions]
        for index, f in enumerate(functions):
            records = native[relative, index]
            bounds = spans[index]
            excluded = [s for i, s in enumerate(spans) if i != index and bounds[0] <= s[0] and s[1] <= bounds[1]]
            regions = {}
            execution = []
            for record in records:
                first = record['regions'][0]
                if record['count'] != first[4]:
                    raise ValueError('entry count disagrees with first region')
                if f['asynchronous'] and first[:2] != f['body']:
                    # Constructing a future must not cover its source body or signature.
                    continue
                execution.append(record['count'])
                for region in record['regions']:
                    sl, sc, el, ec, count, file_id, expanded_id, kind = region
                    if record['filenames'][file_id] != str(native_root / relative):
                        raise ValueError('multi-file native expansion needs a certified mapping')
                    if count < 0 or kind != 0:
                        raise ValueError('unsupported native region kind/count')
                    a, b = point_offset(source, [sl, sc]), point_offset(source, [el, ec])
                    if not bounds[0] <= a <= b <= bounds[1]:
                        raise ValueError('region outside exact source owner')
                    if a == b or any(x <= a and b <= y for x, y in excluded):
                        continue
                    regions[a, b] = max(regions.get((a, b), 0), count)
            if not execution:
                raise ValueError('async execution body has no native counter')
            normalized = [(a, b, count) for (a, b), count in regions.items()]
            covered, total = line_coverage(source, normalized, excluded)
            results.append({
                'source': relative, 'source_sha256': hashlib.sha256(source).hexdigest(),
                **f, 'native_instances': len(records),
                'coverage.line': ratio(covered, total),
                'coverage.region': ratio(sum(n > 0 for n in regions.values()), len(regions)),
                'coverage.function': ratio(int(any(n > 0 for n in execution)), 1),
                'risk.crap': crap(f['complexity'], covered, total),
            })
    return {'schema': SCHEMA, 'functions': results}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--source', action='append', required=True)
    parser.add_argument('--llvm-json', required=True)
    parser.add_argument('--ast-binary', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = measure(args.source_root, args.source, args.llvm_json, args.ast_binary)
    Path(args.output).write_text(json.dumps(result, indent=2) + '\n')

if __name__ == '__main__':
    main()
