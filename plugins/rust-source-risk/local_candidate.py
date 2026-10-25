#!/usr/bin/env python3
"""Run the actual full release packaging command without publishing anything.

Requires a clean committed source and a capture-compatible CARGO_HOME. Product
identity comes from the exact release catalog/manifests/COLLECTOR/lock; no legacy
0.2 identity, lightweight archive or current-release regression substitutes for
this candidate. The dist contains only the complete archive and SBOM; evidence
is separate. No tag, push, release or post-publication certification is performed.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--core', type=Path, required=True, help='fixed published Core0.14.1 binary')
    parser.add_argument('--core-root', type=Path, required=True, help='existing pinned static-contract Core root')
    args = parser.parse_args()
    if subprocess.check_output(['git','-C',str(REPO),'status','--porcelain'],text=True):
        raise RuntimeError('full candidate requires a clean committed worktree')
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    command=[sys.executable,REPO/'tools/release/package_plugin.py','--plugin','rust-source-risk',
             '--core-root',args.core_root.resolve(),'--output',out/'dist',
             '--source-risk-core',args.core.resolve(),'--source-risk-evidence',out/'validation']
    with (out/'package.log').open('w') as log:
        subprocess.run(list(map(str,command)),stdout=log,stderr=subprocess.STDOUT,check=True)
    manifest=out/'validation/candidate/candidate-manifest.json'
    value=json.loads(manifest.read_text())
    print(json.dumps({'candidate':value['candidate'],'manifest':str(manifest),
                      'receipt':str(out/'validation/candidate/acceptance/receipt.json')}))


if __name__ == '__main__':
    main()
