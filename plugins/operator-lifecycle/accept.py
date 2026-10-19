"""Disposable lifecycle acceptance for the external operator; no live host state.

Ported from Core's hooks integration suite plus new canary/state/pin negatives.
Every scenario runs in a temporary directory with isolated Git configuration.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

p = argparse.ArgumentParser(__doc__)
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--core', type=Path, required=True)
a = p.parse_args()
binary, core = a.binary.resolve(strict=True), a.core.resolve(strict=True)
pin = hashlib.sha256(core.read_bytes()).hexdigest()
identity = json.loads(Path(__file__).with_name('plugin.json').read_text())


def main():
    with tempfile.TemporaryDirectory(prefix='operator-accept-') as tmp:
        base = Path(tmp)
        home = base / 'home'
        shim = base / 'bin'
        home.mkdir()
        shim.mkdir()
        shim_core = shim / 'harness-gate'
        shutil.copy2(core, shim_core)
        shim_core.chmod(0o755)
        env = dict(
            os.environ,
            HOME=str(home),
            GIT_CONFIG_GLOBAL=str(base / 'gitconfig'),
            GIT_CONFIG_NOSYSTEM='1',
            GIT_TERMINAL_PROMPT='0',
            PATH=str(shim) + os.pathsep + os.environ['PATH'],
        )
        counter = [0]

        def run(args, cwd=base, check=True):
            result = subprocess.run([str(x) for x in args], cwd=cwd, env=env,
                                    capture_output=True, text=True)
            if check and result.returncode != 0:
                raise SystemExit(
                    f'command failed: {args}\nstdout={result.stdout}\nstderr={result.stderr}')
            return result

        def git(repo, *args):
            return run(['git', '-C', repo, *args])

        def project():
            counter[0] += 1
            root = base / f'project-{counter[0]}'
            root.mkdir()
            git(root, 'init', '-q')
            run([core, '--project-root', root, 'init'])
            return root

        def operator(root, action, core_path=core, core_pin=pin):
            return run([binary, '--project-root', root, 'hooks', '--core', core_path,
                        '--core-sha256', core_pin, action], check=False)

        def ok(result):
            if result.returncode != 0:
                raise SystemExit(f'unexpected failure: {result.stdout}{result.stderr}')
            return result

        def refused(result):
            if result.returncode == 0:
                raise SystemExit(f'unexpected success: {result.stdout}{result.stderr}')
            return result

        version = run([binary, '--version']).stdout.strip()
        assert version == f"gateprobes-operator {identity['version']}", version

        # 1. Explicit, idempotent lifecycle; modified hooks block every action.
        root = project()
        ok(operator(root, 'install'))
        ok(operator(root, 'status'))
        hook = root / '.git/hooks/pre-commit'
        content = hook.read_bytes()
        ok(operator(root, 'install'))
        assert hook.read_bytes() == content
        hook.write_bytes(content + b'# custom\n')
        for action in ('status', 'install', 'uninstall'):
            refused(operator(root, action))
        assert (root / '.git/hooks/pre-push').exists()
        assert hook.read_text().endswith('# custom\n')
        hook.write_bytes(content)
        ok(operator(root, 'uninstall'))
        ok(operator(root, 'uninstall'))
        refused(operator(root, 'status'))

        # 2. Foreign hooks, custom hooksPath, stale lock and empty profile.
        root = project()
        foreign = root / '.git/hooks/pre-push'
        foreign.write_text('foreign')
        refused(operator(root, 'install'))
        assert not (root / '.git/hooks/pre-commit').exists()
        assert foreign.read_text() == 'foreign'
        foreign.unlink()
        elsewhere = root / 'elsewhere'
        elsewhere.mkdir()
        (elsewhere / 'pre-commit').write_text('foreign manager')
        git(root, 'config', 'core.hooksPath', 'elsewhere')
        refused(operator(root, 'install'))
        assert (elsewhere / 'pre-commit').read_text() == 'foreign manager'
        git(root, 'config', '--unset', 'core.hooksPath')
        lock = root / '.git/hooks/.harness-gate-hooks.lock'
        lock.write_text('unknown stale owner')
        for action in ('status', 'install', 'uninstall'):
            refused(operator(root, action))
        assert lock.read_text() == 'unknown stale owner'
        lock.unlink()
        flow = root / '.harness-gate/flow.toml'
        flow.write_text(flow.read_text().replace(
            'hook_profile = "hook"', 'hook_profile = "nonexistent"'))
        refused(operator(root, 'install'))
        assert not (root / '.git/hooks/pre-commit').exists()

        # 3. Symlinks and missing executable permission are never current.
        root = project()
        target = root / 'foreign'
        target.write_text('foreign')
        link = root / '.git/hooks/pre-commit'
        link.symlink_to(target)
        refused(operator(root, 'install'))
        refused(operator(root, 'uninstall'))
        assert target.read_text() == 'foreign'
        link.unlink()
        ok(operator(root, 'install'))
        link.chmod(0o644)
        refused(operator(root, 'status'))
        ok(operator(root, 'uninstall'))
        hooks = root / '.git/hooks'
        moved = root / 'saved-hooks'
        hooks.rename(moved)
        hooks.symlink_to(moved)
        refused(operator(root, 'install'))

        # 4. Real commit/push hooks and a linked worktree share the same files.
        root = project()
        git(root, 'config', 'user.email', 'test@example.invalid')
        git(root, 'config', 'user.name', 'Operator Acceptance')
        git(root, 'add', '.')
        ok(run(['git', '-C', root, 'commit', '-qm', 'initial']))
        linked_parent = base / 'linked-parent'
        linked_parent.mkdir()
        linked = linked_parent / 'linked project with spaces'
        ok(run(['git', '-C', root, 'worktree', 'add', '--detach', linked, 'HEAD']))
        ok(operator(linked, 'install'))
        ok(operator(root, 'status'))
        ok(operator(linked, 'uninstall'))
        ok(operator(root, 'install'))
        (root / 'sample.txt').write_text('bad trailing whitespace   \n')
        git(root, 'add', 'sample.txt')
        refused(run(['git', '-C', root, 'commit', '-qm', 'must fail'], check=False))
        assert_report(root, 'project.staged-diff-check')
        (root / 'sample.txt').write_text('clean\n')
        git(root, 'add', 'sample.txt')
        ok(run(['git', '-C', root, 'commit', '-qm', 'valid']))
        remote = base / 'remote.git'
        remote.mkdir()
        ok(run(['git', '-C', remote, 'init', '--bare', '-q']))
        (root / 'sample.txt').write_text('bad trailing whitespace   \n')
        refused(run(['git', '-C', root, 'push', remote, 'HEAD:refs/heads/test'], check=False))
        assert_report(root, 'project.diff-check')
        (root / 'sample.txt').write_text('clean\n')
        ok(run(['git', '-C', root, 'push', remote, 'HEAD:refs/heads/test']))

        # 5. Canary records keep the historical shape; state paths stay safe.
        root = project()
        state = root / 'canary.json'
        enabled = json.loads(run([binary, 'canary', '--state', state, '--slice', 'team-a']).stdout)
        assert enabled['schema_version'] == 1 and enabled['enabled'] is True
        assert enabled['slice'] == 'team-a' and enabled['updated_at']
        assert [e['action'] for e in enabled['history']] == ['enable']
        assert enabled['history'][0]['slice'] == 'team-a'
        assert json.loads(state.read_text()) == enabled
        rolled = json.loads(run([binary, 'rollback', '--state', state]).stdout)
        assert rolled['enabled'] is False
        assert [e['action'] for e in rolled['history']] == ['enable', 'rollback']
        assert [e['slice'] for e in rolled['history']] == ['team-a', 'team-a']
        again = json.loads(run([binary, 'rollback', '--state', state]).stdout)
        assert [e['action'] for e in again['history']] == ['enable', 'rollback', 'rollback']
        refused(run([binary, 'rollback', '--state', root / 'missing.json'], check=False))
        victim = root / 'victim.json'
        victim.write_text(json.dumps({'schema_version': 1, 'enabled': False, 'slice': '',
                                      'updated_at': '', 'history': []}))
        victim_bytes = victim.read_bytes()
        alias = root / 'alias.json'
        alias.symlink_to(victim)
        refused(run([binary, 'canary', '--state', alias, '--slice', 'team-a'], check=False))
        assert victim.read_bytes() == victim_bytes
        refused(run([binary, 'canary', '--state', root, '--slice', 'team-a'], check=False))
        refused(run([binary, 'canary', '--state', root / 'absent/state.json',
                     '--slice', 'team-a'], check=False))
        bad = root / 'bad.json'
        bad.write_text('{"schema_version":1,"enabled":false,"slice":"","updated_at":"",'
                       '"history":[],"unexpected":true}')
        refused(run([binary, 'canary', '--state', bad, '--slice', 'team-a'], check=False))
        bad.write_text('{not json')
        refused(run([binary, 'canary', '--state', bad, '--slice', 'team-a'], check=False))

        # 6. Pinned Core identity and readiness must fail before any file changes.
        root = project()
        refused(operator(root, 'install', core_pin='0' * 64))
        assert not (root / '.git/hooks/pre-commit').exists()
        tampered = base / 'tampered-core'
        shutil.copy2(core, tampered)
        with tampered.open('r+b') as stream:
            stream.seek(0)
            original = stream.read(1)
            stream.seek(0)
            stream.write(bytes([original[0] ^ 0xFF]))
        refused(operator(root, 'install', core_path=tampered))
        assert not (root / '.git/hooks/pre-commit').exists()
        refused(operator(root, 'install', core_path=Path('harness-gate')))
        refused(operator(root, 'install', core_path=base))
        refused(operator(root, 'install', core_path=base / 'missing-core'))
        unconfigured = base / 'unconfigured'
        unconfigured.mkdir()
        git(unconfigured, 'init', '-q')
        refused(operator(unconfigured, 'install'))
        assert not (unconfigured / '.git/hooks/pre-commit').exists()

        assert hashlib.sha256(core.read_bytes()).hexdigest() == pin
    print('operator extracted compatibility PASS')


def assert_report(root, step):
    report = json.loads((root / '.harness-gate/reports/test_result.json').read_text())
    assert report['status'] == 'FAIL', report
    assert any(s.get('step_id') == step and s.get('status') == 'FAIL'
               for s in report['steps']), report


if __name__ == '__main__':
    main()
