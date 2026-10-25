#!/usr/bin/env python3
"""Build and exercise an unpublished candidate from a clean committed checkout.

No tag, version bump, network configuration change or release action. The local
manifest is externally SHA-256 pinned; the current-release pins are read only.
Run with an isolated CARGO_HOME containing the already cached registry and without
build overrides (capture deliberately rejects wrappers/flags).
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

from core_acceptance import file_digest, write

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def run(args, *, log=None, **kwargs):
    if log is None:
        return subprocess.run(list(map(str, args)), check=True, **kwargs)
    with log.open('w') as output:
        return subprocess.run(list(map(str, args)), check=True, stdout=output,
                              stderr=subprocess.STDOUT, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--core', type=Path, required=True)
    args = parser.parse_args()
    status = subprocess.check_output(['git', '-C', REPO, 'status', '--porcelain'], text=True)
    if status:
        raise RuntimeError('candidate requires a clean committed worktree: ' + status)
    head = subprocess.check_output(['git', '-C', REPO, 'rev-parse', 'HEAD'], text=True).strip()
    tree = subprocess.check_output(['git', '-C', REPO, 'rev-parse', 'HEAD^{tree}'], text=True).strip()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    run(['cargo', 'build', '--release', '--locked', '--manifest-path', HERE / 'ast/Cargo.toml',
         '--target-dir', out / 'build'], log=out / 'build.log')
    package = out / 'local-source-risk-candidate'
    package.mkdir()
    for name in ('plugin.py', 'measure.py', 'capture.py', 'plugin.json', 'README.md', 'LICENSE', 'ast/Cargo.lock'):
        dest = package / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HERE / name, dest)
    shutil.copy2(out / 'build/release/harness-gate-rust-source-inventory', package / 'inventory')
    members = {p.relative_to(package).as_posix():file_digest(p) for p in package.rglob('*') if p.is_file()}
    archive = out / 'local-source-risk-candidate.tar.gz'
    with tarfile.open(archive, 'w:gz') as stream:
        stream.add(package, arcname=package.name)
    fixture = HERE / 'fixtures/thiserror-subset'
    original = json.loads((HERE / 'core_acceptance.json').read_text())
    inputs = {p.relative_to(fixture).as_posix():file_digest(p) for p in fixture.rglob('*') if p.is_file()}
    # No generated files are permitted to silently enter the acceptance fixture.
    if set(inputs) != {'Cargo.toml', 'Cargo.lock', 'apps/server/src/lib.rs', 'tests/integration.rs'}:
        raise RuntimeError('unexpected candidate fixture inputs')
    pins = {'schema':'rust-source-risk-local-candidate/v1',
            'candidate':{'name':'rust-source-risk', 'version':'0.2.0',
                         'identity_note':'unpublished changed source; inherited development version is not a published artifact identity',
                         'source_commit':head, 'source_tree':tree,
                         'archive':archive.name,'archive_sha256':file_digest(archive),'members':members},
            'core':original['core'], 'tools':original['tools'],
            'fixture':{'target':'x86_64-unknown-linux-gnu','inputs':inputs,
                       'sources':{k:v for k,v in inputs.items() if k.startswith('apps/server/src/')},
                       'pipeline_files':{k:v for k,v in inputs.items() if k in ('Cargo.toml','Cargo.lock')}}}
    manifest = out / 'candidate-manifest.json'
    write(manifest, pins)
    manifest_sha = file_digest(manifest)
    (out / 'candidate-manifest.sha256').write_text(manifest_sha + '\n')
    # Exercise the package bytes that were just hashed, never the sibling build.
    run([sys.executable, package / 'capture.py', '--repository', fixture,
         '--output', out / 'capture', '--target-dir', out / 'capture-target',
         '--input', 'Cargo.toml', '--input', 'Cargo.lock', '--input', 'apps/server/src',
         '--input', 'tests', '--source-root', 'apps/server/src', '--test', 'integration'], log=out / 'capture.log')
    run([sys.executable, HERE / 'candidate_acceptance.py', '--pins', manifest,
         '--pins-sha256', manifest_sha, '--archive', archive,
         '--bundle', out / 'capture/bundle.json', '--core', args.core.resolve(),
         '--presets-dir', REPO / 'presets', '--output', out / 'acceptance/receipt.json'], log=out / 'acceptance.log')
    print(json.dumps({'head':head,'tree':tree,'candidate_manifest_sha256':manifest_sha,
                      'receipt':str(out/'acceptance/receipt.json')}))


if __name__ == '__main__':
    main()
