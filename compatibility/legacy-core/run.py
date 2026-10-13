#!/usr/bin/env python3
"""Execute original compatibility tests with an exact, audited ownership inventory."""
import argparse
import hashlib
import importlib
import json
import os
import subprocess
from pathlib import Path
import sys
import time
import unittest

HERE = Path(__file__).resolve().parent
SNAPSHOT = HERE / 'snapshot'


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


def verify():
    inventory = json.loads((HERE / 'inventory.json').read_text())
    require(inventory['schema'] == 'legacy-core-compatibility/v1', 'invalid compatibility inventory')
    for name, row in inventory['files'].items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'unsafe compatibility input')
        path = SNAPSHOT / relative
        require(path.is_file() and not path.is_symlink() and digest(path) == row['sha256'],
                'changed frozen compatibility input: ' + name)
    # New methods/modules must be classified, never silently disappear.
    expected = {name for name in inventory['files'] if name.startswith('tools/quality/tests/')}
    actual = {p.relative_to(SNAPSHOT).as_posix() for p in (SNAPSHOT / 'tools/quality/tests').glob('*.py')}
    require(actual == expected, 'compatibility test inventory changed')
    return inventory


def parity():
    from test_typescript_policy import TypeScriptPolicyTests
    import typescript_semantics as ts
    test = TypeScriptPolicyTests()
    test.setUpClass(); test.setUp()
    try:
        expected = json.loads((HERE / 'expected-core-typescript-policy.json').read_text())
        require(test.records == expected['head']['records'], 'Core head facts differ from original producer')
        require(test.base == expected['base']['records'], 'Core base facts differ from original producer')
        require(test.context['project'] == expected['project'], 'Core project differs from original producer')
        for label, context in [('head', test.context), ('base', test.base_context)]:
            require(context['expected'] == expected[label]['context'], 'Core replay context changed')
            for record in expected[label]['records']:
                for artifact in record['artifacts']:
                    payload = (context['artifact_root'] / artifact['path']).read_bytes()
                    require(hashlib.sha256(payload).hexdigest() == artifact['sha256'] and len(payload) == artifact['bytes'],
                            'Core replay artifact differs from original producer')
                    if Path(artifact['path']).name == 'receipt.json':
                        require(payload == expected[label]['receipt'].encode(), 'Core replay receipt changed')
        bundle = test.fixture.bundle
        require(expected['preset_reference'] == {
            'series': ts.measurement_series(bundle.toolchain, 'node-jsdom', 'production-ts'),
            'native': bundle.measure('src/app/pricing.ts')[0]}, 'Core preset facts differ from original producer')
    finally:
        test.doCleanups()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic()
    inventory = verify()
    sys.path[:0] = [str(SNAPSHOT / 'tools/quality/tests'), str(SNAPSHOT / 'tools/quality')]
    parity()
    suite, ownership = unittest.TestSuite(), []
    held_classes = inventory['held_classes']
    for module in inventory['modules']:
        names = [module]
        if module == 'test_preset_packs':
            names = [module + '.PresetPackTests.test_typescript_uses_native_series_and_unsupported_crap']
        for test in flatten(unittest.defaultTestLoader.loadTestsFromNames(names)):
            identity = test.id()
            held = next((reason for prefix, reason in held_classes.items() if identity.startswith(prefix + '.')), None)
            ownership.append({'method': identity, 'owner': 'Core' if module in ('test_typescript_policy', 'test_preset_packs') else 'GateProbes',
                              'scope': 'Linux retained replay / original compiler 1.97.1; no new platform certification',
                              'execution': 'held' if held else 'required', 'reason': held or 'Original test body and fixtures preserved.'})
            if not held:
                suite.addTest(test)
    require(all(any(row['method'].startswith(prefix + '.') for row in ownership) for prefix in held_classes), 'unknown held class')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    passed = result.wasSuccessful() and not result.skipped
    report = {'schema': 'legacy-core-compatibility-result/v1', 'status': 'pass' if passed else 'fail',
              'revision': os.environ.get('HANDOFF_REVISION') or subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=HERE, text=True).strip(),
              'ci_run': 'https://github.com/musutrade/GateProbes/actions/runs/' + os.environ.get('GITHUB_RUN_ID', 'local'),
              'source_commit': inventory['source_commit'], 'inventory_sha256': digest(HERE / 'inventory.json'),
              'core_fixture_sha256': digest(HERE / 'expected-core-typescript-policy.json'),
              'producer_parity': 'pass', 'methods': ownership, 'tests_run': result.testsRun,
              'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
              'held': sum(row['execution'] == 'held' for row in ownership),
              'wall_seconds': round(time.monotonic() - started, 3)}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'tests_run', 'skipped', 'held', 'wall_seconds')}))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
