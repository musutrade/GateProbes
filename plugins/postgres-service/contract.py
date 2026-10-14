#!/usr/bin/env python3
"""Accept an installed Postgres artifact through an explicit Core binary.

The deterministic pg_isready fixture tests process wiring, not a live daemon.
No Core/plugin source is built or used as a runtime fallback here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv, cwd, env, success=True):
    result = subprocess.run([str(a) for a in argv], cwd=cwd, env=env,
                            text=True, capture_output=True, timeout=30)
    if (result.returncode == 0) != success:
        raise AssertionError(f'{argv}: unexpected status {result.returncode}\n{result.stdout}\n{result.stderr}')
    # Secret values must never appear in diagnostic streams.
    assert 'PRIVATE_TEST_PASSWORD' not in result.stdout + result.stderr
    return result


def accept(binary, core):
    binary, core = binary.resolve(), core.resolve()
    identity = run([binary, '--version'], HERE, os.environ).stdout.strip()
    assert identity == 'gateprobes-postgres 0.1.0', identity
    before = digest(core)
    rows = []
    with tempfile.TemporaryDirectory(prefix='postgres-contract-') as directory:
        root = Path(directory)
        installed = root / 'installed/gateprobes-postgres'
        installed.parent.mkdir()
        shutil.copy2(binary, installed)
        project = root / 'project'
        project.mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith(('HARNESS_GATE_', 'ARC_FLOW_', 'GATE_CHECK_'))}
        for name in ('TEST_DATABASE_URL', 'DATABASE_URL', 'PGHOST', 'PGPORT', 'PGDATABASE'):
            env.pop(name, None)
        run(['git', 'init', '-q', project], root, env)
        run([core, '--project-root', project, 'init', '--preset', 'generic'], root, env)
        fixture = root / 'health'
        fixture.mkdir()
        health = fixture / 'pg_isready'
        env['PATH'] = str(fixture) + os.pathsep + env.get('PATH', '')
        env['TEST_DATABASE_URL'] = 'postgres://test:PRIVATE_TEST_PASSWORD@127.0.0.1/app_test'
        config = project / '.harness-gate/flow.toml'
        marker = project / 'step-ran'
        (project / 'step.py').write_text('import os\nfrom pathlib import Path\nassert os.environ["TEST_DATABASE_URL"].endswith("/app_test")\nassert "DATABASE_URL" not in os.environ\nPath("step-ran").write_text("ran")\n')
        legacy = root / 'legacy.toml'
        legacy.write_text('''version = 2
[project]
name = "contract"
default_profile = "full"
hook_profile = "full"
[paths]
reports = ".harness-gate/reports"
audit_config = ".harness-gate/audit.toml"
secrets_config = ".harness-gate/secrets.toml"
[policy]
required_steps = ["app.check"]
[[doctor.checks]]
id = "database"
label = "database"
required = false
kind = "service"
service = "database"
[services.database]
kind = "environment"
source_env = "TEST_DATABASE_URL"
inject_env = "TEST_DATABASE_URL"
external_value_policy = "isolated-postgres"
[scope]
unmatched = "all"
rules = [{ patterns = ["**"], components = ["app"] }]
[[steps]]
id = "app.check"
label = "dependent step"
component = "app"
profiles = ["full"]
program = "python3"
args = ["{root}/step.py"]
cwd = "{root}"
input = "repository"
log = "step.log"
timeout_secs = 10
services = ["database"]
remove_env = ["DATABASE_URL"]
''')
        def migrate():
            config.unlink(missing_ok=True)
            run([installed, 'migrate', '--input', legacy, '--output', config, '--project', 'contract'], root, env)
            parsed = tomllib.loads(config.read_text())
            assert parsed['policy']['required_steps'] == ['app.check']
            assert parsed['doctor']['checks'][0]['required'] is True
            assert parsed['service_checks']['database'][0]['sha256'] == digest(installed)
            return config.read_text()
        healthy = '#!/bin/sh\n[ "$1" = -t ] || exit 3\ncase "$PGDATABASE" in postgres://*/app_test) exit 0;; *) exit 4;; esac\n'
        health.write_text(healthy)
        health.chmod(0o700)
        original = migrate()
        run([core, '--project-root', project, 'config', 'check'], root, env)
        # Overwrite and unmigrated configuration both fail; source stays unchanged.
        source_digest = digest(legacy)
        run([installed, 'migrate', '--input', legacy, '--output', config, '--project', 'contract'], root, env, False)
        assert digest(legacy) == source_digest
        config.write_text(legacy.read_text())
        result = run([core, '--project-root', project, 'config', 'check'], root, env, False)
        assert 'gateprobes-postgres migrate' in result.stdout + result.stderr
        config.write_text(original)
        run(['git', 'add', '.'], project, env)
        run(['git', '-c', 'user.name=Contract', '-c', 'user.email=contract@example.invalid', 'commit', '-qm', 'fixture'], project, env)
        commands = [('doctor', ['doctor', '--json']), ('service-step', ['step', 'app.check']), ('verify', ['verify', '--all', '--profile', 'full'])]
        def check_case(name, success):
            for command, args in commands:
                marker.unlink(missing_ok=True)
                run([core, '--project-root', project, *args], root, env, success)
                if command != 'doctor':
                    assert marker.exists() == success, (name, command, 'dependent step ran before check')
                rows.append({'case': name, 'command': command, 'expected': 'pass' if success else 'block'})
        check_case('isolated-and-healthy', True)
        for name, value in [('production-name', 'postgres://test:PRIVATE_TEST_PASSWORD@localhost/app'),
                            ('remote-without-opt-in', 'postgres://test:PRIVATE_TEST_PASSWORD@remote.invalid/app_test'),
                            ('query-override', 'postgres://test:PRIVATE_TEST_PASSWORD@localhost/app_test?dbname=production'),
                            ('wrong-scheme', 'https://localhost/app_test')]:
            env['TEST_DATABASE_URL'] = value
            check_case(name, False)
        env['TEST_DATABASE_URL'] = 'postgres://test:PRIVATE_TEST_PASSWORD@127.0.0.1/app_test'
        env['DATABASE_URL'] = 'postgresql://other:secret@localhost:5432/app_test'
        check_case('production-target-conflict', False)
        env.pop('DATABASE_URL')
        health.write_text('#!/bin/sh\nexit 2\n')
        check_case('health-failure', False)
        health.rename(fixture / 'withheld')
        check_case('health-tool-missing', False)
        (fixture / 'withheld').rename(health)
        health.write_text('#!/bin/sh\nexec /bin/sleep 5\n')
        config.write_text(original.replace('timeout_secs = 15', 'timeout_secs = 1'))
        check_case('timeout', False)
        health.write_text(healthy)
        config.write_text(original)
        installed.rename(installed.with_suffix('.withheld'))
        check_case('plugin-missing', False)
        installed.with_suffix('.withheld').rename(installed)
        saved = installed.read_bytes()
        installed.write_bytes(saved + b'changed')
        check_case('artifact-tampered', False)
        # Explicit rebinding accepts an upgraded artifact without rebuilding Core.
        migrate()
        check_case('explicit-upgrade-rebind', True)
        installed.write_bytes(saved)
        config.write_text(original.replace('version = "0.1.0"', 'version = "9.9.9"'))
        check_case('result-version-mismatch', False)
        config.write_text(original.replace('gate-service-check/v1', 'gate-service-check/v2'))
        check_case('protocol-incompatible', False)
        # v1 fixture also migrates to a schema-valid Core configuration.
        v1 = root / 'v1.toml'
        shutil.copy2(HERE / 'fixtures/v1-flow.toml', v1)
        config.unlink()
        run([installed, 'migrate', '--input', v1, '--output', config, '--project', 'v1-contract'], root, env)
        run([core, '--project-root', project, 'config', 'check'], root, env)
        rows.append({'case': 'v1-migration', 'command': 'config-check', 'expected': 'pass'})
        # The offline Arc-Flow importer must retain the installed check binding.
        imported_project = root / 'import-project'
        migrated = imported_project / '.arc-flow/migrated.toml'
        migrated.parent.mkdir(parents=True)
        run([core, '--project-root', imported_project, 'init', '--preset', 'generic'], root, env)
        (imported_project / '.harness-gate/flow.toml').unlink()
        source = HERE / 'fixtures/v2-flow.toml'
        source_digest = digest(source)
        run([installed, 'migrate', '--input', source, '--output', migrated,
             '--project', 'import-contract'], root, env)
        before_import = migrated.read_bytes()
        run([core, '--project-root', imported_project, 'config', 'import',
             '--execution-only', '--input', '.arc-flow/migrated.toml'], root, env)
        expected = tomllib.loads(migrated.read_text())
        actual = tomllib.loads((imported_project / '.harness-gate/flow.toml').read_text())
        assert actual['service_checks'] == expected['service_checks']
        assert actual['policy'] == expected['policy']
        assert len(actual['steps']) == len(expected['steps'])
        for old, new in zip(expected['steps'], actual['steps']):
            assert all(new[key] == value for key, value in old.items())
            assert new['input'] == 'repository'
        report = json.loads((imported_project / '.harness-gate/flow.import.json').read_text())
        assert report['authority_transfer'] == 'blocked'
        assert migrated.read_bytes() == before_import and digest(source) == source_digest
        run([core, '--project-root', imported_project, 'config', 'check'], root, env)
        rows.append({'case': 'migrated-offline-import', 'command': 'config-import', 'expected': 'pass'})
    assert digest(core) == before, 'Core binary changed during acceptance'
    return {'status': 'pass', 'plugin_sha256': digest(binary), 'core_sha256': before,
            'health': 'deterministic pg_isready fixture; live daemon acceptance pending', 'cases': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--core-binary', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = accept(args.binary, args.core_binary)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
