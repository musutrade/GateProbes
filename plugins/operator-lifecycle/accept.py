"""Disposable installation compatibility; no live host hooks or deployment."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser(__doc__)
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--core', type=Path, required=True)
a = p.parse_args()
binary, core = a.binary.resolve(strict=True), a.core.resolve(strict=True)
pin = hashlib.sha256(core.read_bytes()).hexdigest()
with tempfile.TemporaryDirectory(prefix='operator-accept-') as tmp:
    root = Path(tmp)
    def run(args):
        return subprocess.run([str(x) for x in args], cwd=root, check=True, capture_output=True)
    run(['git', 'init', '-q'])
    run([core, '--project-root', root, 'init'])
    command = [binary, '--project-root', root, 'hooks', '--core', core, '--core-sha256', pin]
    run([*command, 'install'])
    run([*command, 'status'])
    original = (root / '.git/hooks/pre-commit').read_bytes()
    run([*command, 'install'])
    assert (root / '.git/hooks/pre-commit').read_bytes() == original
    run([*command, 'uninstall'])
    assert not (root / '.git/hooks/pre-commit').exists()
    state = root / 'canary.json'
    run([binary, 'canary', '--state', state, '--slice', 'acceptance'])
    assert json.loads(state.read_text())['enabled'] is True
    run([binary, 'rollback', '--state', state])
    assert json.loads(state.read_text())['enabled'] is False
    assert hashlib.sha256(core.read_bytes()).hexdigest() == pin
print('operator extracted compatibility PASS')
