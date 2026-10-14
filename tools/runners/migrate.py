#!/usr/bin/env python3
"""Migrate runner v1 declarations to v2 without changing other flow values.

Writes a new file or stdout; never edits the source. Comments/formatting are
normalized. Validate the output with the target Core before replacing a flow.
"""
import argparse
import copy
import datetime
import json
import math
from pathlib import Path
import tomllib

DEFAULT_DEFINITION = Path(__file__).resolve().parents[2] / 'runners/cargo-test.toml'


def migrate(flow, definition):
    output = copy.deepcopy(flow)
    if definition.get('version') != 2 or definition.get('kind') != 'cargo-test':
        raise ValueError('expected a v2 cargo-test definition')
    if set(definition) != {'version', 'kind', 'required_program', 'threads_args', 'threads_args_after'}:
        raise ValueError('unexpected Cargo definition fields')
    for step in output.get('steps', []):
        runner = step.get('runner')
        if runner is None:
            continue
        if runner.get('version') != 1:
            raise ValueError(f"step {step.get('id')}: expected runner v1; do not migrate twice")
        if set(runner) & {'required_program', 'threads_args', 'threads_args_after'}:
            raise ValueError('v1 runner contains v2 declaration fields')
        if runner.get('kind') == 'cargo-test':
            if step.get('program') != 'cargo':
                raise ValueError('legacy cargo-test requires program cargo')
            runner['required_program'] = definition['required_program']
            if runner.get('threads') is not None:
                runner['threads_args'] = copy.deepcopy(definition['threads_args'])
                runner['threads_args_after'] = definition['threads_args_after']
        runner['version'] = 2
    return output


def literal(value):
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value) if math.isfinite(value) else ('nan' if math.isnan(value) else ('inf' if value > 0 else '-inf'))
    if isinstance(value, list):
        return '[' + ', '.join(literal(item) for item in value) + ']'
    if isinstance(value, dict):
        return '{ ' + ', '.join(literal(key) + ' = ' + literal(item) for key, item in value.items()) + ' }'
    raise ValueError(f'unsupported TOML value {type(value)}')


def render(flow):
    rows = []
    for key, value in flow.items():
        if key != 'steps':
            rows.append(literal(key) + ' = ' + literal(value))
    for step in flow.get('steps', []):
        rows.append('\n[[steps]]')
        rows.extend(literal(key) + ' = ' + literal(value) for key, value in step.items())
    source = '\n'.join(rows) + '\n'
    if tomllib.loads(source) != flow:
        raise ValueError('TOML serialization changed flow values')
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--definition', type=Path, default=DEFAULT_DEFINITION)
    parser.add_argument('--output', type=Path, help='new output file; must not already exist')
    args = parser.parse_args()
    try:
        flow = tomllib.loads(args.source.read_text())
        definition = tomllib.loads(args.definition.read_text())
        source = render(migrate(flow, definition))
        if args.output:
            with args.output.open('x') as handle:
                handle.write(source)
        else:
            print(source, end='')
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
