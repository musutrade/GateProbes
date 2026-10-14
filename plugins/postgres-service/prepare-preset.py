#!/usr/bin/env python3
"""Create a reviewed local preset catalog bound to an installed Postgres plugin.

Historical catalog/pack bytes remain unchanged. Requires Python 3 for setup only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent


def prepare(binary: Path, source: Path, output: Path) -> dict:
    binary, source, output = binary.resolve(), source.resolve(), output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('output must be a new directory; retain the old catalog')
    identity = subprocess.run([str(binary), '--version'], check=True, capture_output=True,
                              text=True).stdout.strip()
    if identity != 'gateprobes-postgres 0.1.0':
        raise ValueError('unsupported installed plugin identity')
    before = hashlib.sha256(binary.read_bytes()).hexdigest()
    catalog = json.loads((source / 'catalog.json').read_text())
    if catalog.get('schema') != 'harness-preset-catalog/v1':
        raise ValueError('unsupported catalog schema')
    entry = catalog['presets']['angular-rust-postgres']['flow']
    relative = Path(entry)
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('unsafe preset path')
    if any(path.is_symlink() for path in source.rglob('*')):
        raise ValueError('preset source must not contain symlinks')
    with tempfile.TemporaryDirectory(prefix='postgres-preset-') as tmp:
        staged = Path(tmp) / 'catalog'
        shutil.copytree(source, staged)
        (staged / relative).unlink()
        subprocess.run([str(binary), 'migrate', '--input', str(source / relative),
                        '--output', str(staged / relative), '--project', 'angular-rust-app'],
                       check=True)
        if hashlib.sha256(binary.read_bytes()).hexdigest() != before:
            raise ValueError('installed artifact changed during generation')
        receipt = {'schema': 'gateprobes-postgres-preset/v1', 'plugin': identity,
                   'executable': str(binary), 'sha256': before,
                   'source_sha256': hashlib.sha256((source / relative).read_bytes()).hexdigest()}
        (staged / 'postgres-binding.json').write_text(json.dumps(receipt, indent=2) + '\n')
        # Refuse a racing output publication; no existing project/catalog is replaced.
        output.mkdir()
        try:
            shutil.copytree(staged, output, dirs_exist_ok=True)
        except Exception:
            shutil.rmtree(output)
            raise
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    default = HERE / 'presets' if (HERE / 'presets').is_dir() else HERE.parents[1] / 'presets'
    parser.add_argument('--presets-dir', type=Path, default=default)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    prepare(args.binary, args.presets_dir, args.output)
    print('Catalog written; review binding and use harness-gate init --presets-dir with compatible Core.')


if __name__ == '__main__':
    main()
