#!/usr/bin/env python3
"""Verify immutable published0.3 bytes BEFORE execution, then fresh signed acceptance.

The unchanged fixed-source candidate validator is an inner implementation detail;
only this outer receipt asserts separately verified public release identity.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import time

from core_acceptance import (AcceptanceError, digest, file_digest, read_json, require,
                             verify_archive, verify_candidate_sbom, verify_cargo_environment,
                             verify_toolchain, write)

ROOT = Path(__file__).resolve().parents[2]
PINS = Path(__file__).with_suffix('.json')


def load_pins(path=PINS):
    pins = read_json(path)
    require(pins['schema'] == 'rust-source-risk-published-regression/v1', 'published pins schema mismatch')
    manifest = pins['validator_manifest']
    encoded = (json.dumps(manifest, indent=2) + '\n').encode()
    require(digest(encoded) == pins['validator_manifest_sha256'], 'validator manifest digest mismatch')
    product = manifest['candidate']
    require(product['name'] == 'rust-source-risk' and product['version'] == '0.3.0', 'published version mismatch')
    require(pins['tag'] == 'rust-source-risk-v0.3.0', 'published tag mismatch')
    require(product['source_commit'] == pins['source_commit'] and product['source_tree'] == pins['source_tree'],
            'published source mismatch')
    identity = f"https://github.com/{pins['repository']}/.github/workflows/collector-release.yml@refs/tags/{pins['tag']}"
    require(pins['certificate_identity'] == identity and pins['oidc_issuer'] == 'https://token.actions.githubusercontent.com',
            'published signature identity mismatch')
    require(pins['assets'][product['archive']] == product['archive_sha256'] and
            pins['assets'][product['sbom']] == product['sbom_sha256'], 'published artifact pins disagree')
    require(len(product['members']) == 9, 'published nine-member contract missing')
    return pins


def checked_digest(path, expected):
    require(path.is_file() and not path.is_symlink(), f'expected regular file: {path}')
    require(file_digest(path) == expected, f'digest mismatch: {path.name}')


def verify_metadata(pins, release, ref, tag):
    require(release['id'] == pins['release_id'] and release['tag_name'] == pins['tag'] and
            release.get('immutable') is True and not release['draft'] and not release['prerelease'],
            'published release identity/immutability mismatch')
    require(ref['object']['type'] == 'tag' and ref['object']['sha'] == pins['tag_object'], 'annotated tag mismatch')
    require(tag['tag'] == pins['tag'] and tag['object']['type'] == 'commit' and
            tag['object']['sha'] == pins['source_commit'], 'published tag source mismatch')
    names = [a['name'] for a in release['assets']]
    require(len(names) == len(set(names)) and set(names) == set(pins['assets']), 'published asset set mismatch')
    for asset in release['assets']:
        require(asset['digest'] == 'sha256:' + pins['assets'][asset['name']], 'GitHub asset digest mismatch')


def verify_local_bytes(pins, dist, unpack, inventory_module):
    for name, expected in pins['assets'].items():
        require(Path(name).name == name, 'unsafe published asset name')
        checked_digest(dist / name, expected)
    inv = inventory_module.load(dist / 'release-inventory.json')
    require(inv['tag'] == pins['tag'] and inv['source'] == {
        'repository': 'https://github.com/' + pins['repository'], 'commit': pins['source_commit']},
        'inventory source/tag mismatch')
    require(set(inventory_module.expected_upload_names(inv)) == set(pins['assets']), 'inventory upload set mismatch')
    inventory_module.verify(dist, dist / 'release-inventory.json', inv['integrity_subjects'])
    manifest = pins['validator_manifest']
    verify_candidate_sbom(dist / manifest['candidate']['sbom'], manifest)
    archive = dist / manifest['candidate']['archive']
    with tarfile.open(archive) as stream:
        names = [m.name for m in stream.getmembers()]
        require(len(names) == len(set(names)), 'duplicate archive member')
    plugin = verify_archive(archive, manifest, unpack)
    identity = read_json(plugin / 'plugin.json')
    require((identity['name'], identity['version']) == ('rust-source-risk', '0.3.0'), 'archived product version mismatch')
    return plugin, inv


def verify_fresh_result(pins, receipt, bundle, host):
    manifest = pins['validator_manifest']
    require(receipt['schema'] == 'rust-source-risk-local-candidate-acceptance/v1' and
            receipt['scope'] == 'local-unpublished-candidate', 'inner validator schema/scope mismatch')
    require(receipt['candidate'] == manifest['candidate'] and
            receipt['candidate_manifest_sha256'] == pins['validator_manifest_sha256'], 'inner manifest mismatch')
    require(receipt['fixture']['bundle_sha256'] == file_digest(bundle), 'fresh bundle receipt mismatch')
    collection = read_json(host / 'accepted-collection.json')['evidence']
    require(len(collection) == receipt['positive']['evidence_records'] == 4, 'missing measured records')
    require(all(x['collector'] == {'name': 'rust-source-risk', 'version': '0.3.0'} for x in collection),
            'measured collector version mismatch')
    require(receipt['positive']['collect_exit'] == receipt['positive']['evaluate_exit'] == 0 and
            read_json(host / 'evaluate-report.json')['aggregate']['state'] == 'pass', 'positive acceptance failed')
    from core_acceptance import NEGATIVE_LAYERS
    negatives = receipt['negatives']
    require(len(negatives) == 10 and {n['case'] for n in negatives} == set(NEGATIVE_LAYERS), 'ten negatives missing')
    for n in negatives:
        require(n['passed'] and n['exit'] != 0 and n['layer'] == NEGATIVE_LAYERS[n['case']] and
                n['expected_reason'] in n['observed_reason'], 'negative rejection reason mismatch')
        if n['layer'] == 'collect':
            require(n['expected_reason'] in (host / (n['case'] + '.stderr')).read_text(), 'negative stderr mismatch')
        else:
            report = read_json(host / (n['case'] + '-report.json'))
            require(report['aggregate']['state'] == 'measurement_error' and
                    n['expected_reason'] in json.dumps(report), 'negative evaluation mismatch')
    require(read_json(host / 'policy-fail-evidence.json') == read_json(host / 'evaluate-evidence.json'),
            'policy failure must use identical real evidence')
    report = read_json(host / 'policy-fail-report.json')
    require(receipt['policy_fail']['transport'] == 'PASS' and receipt['policy_fail']['evaluate_exit'] == 1 and
            report['aggregate']['state'] == 'fail' and any(
                g.get('reason') == 'policy limit violated' and
                g['record']['head'] == {'type': 'rational', 'numerator': 2, 'denominator': 1} and
                g['record']['policy']['limit'] == {'type': 'rational', 'numerator': 1, 'denominator': 1}
                for g in report['gates'].values()), 'real CRAP policy failure missing')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='must not exist')
    parser.add_argument('--tool-cache', type=Path, required=True, help='cosign cache, always digest checked')
    args = parser.parse_args(argv)
    pins = load_pins()
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'Linux x86_64 only')
    checked_digest(ROOT / 'plugins/rust-source-risk/core_acceptance.py',
                   pins['fixed_source_files']['plugins/rust-source-risk/core_acceptance.py'])
    out = args.output.absolute()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    logs = out / 'logs'; logs.mkdir()
    commands = []

    def run(label, argv):
        argv = list(map(str, argv))
        result = subprocess.run(argv, text=True, capture_output=True, timeout=600)
        (logs / (label + '.stdout')).write_text(result.stdout)
        (logs / (label + '.stderr')).write_text(result.stderr)
        commands.append({'label': label, 'argv': argv, 'exit': result.returncode})
        require(result.returncode == 0, f'{label} failed: {result.stderr[-1500:]}')
        return result.stdout

    def api(label, path):
        return json.loads(run(label, ['gh', 'api', f"repos/{pins['repository']}/{path}"]))

    head = run('runner-head-start', ['git', '-C', ROOT, 'rev-parse', 'HEAD']).strip()
    runner_sha256 = file_digest(Path(__file__))
    require(not run('runner-clean-start', ['git', '-C', ROOT, 'status', '--porcelain']).strip(),
            'published regression requires a clean committed worktree')
    before = api('release-before', 'releases/tags/' + pins['tag'])
    ref = api('tag-ref', 'git/ref/tags/' + pins['tag'])
    tag = api('tag-object', 'git/tags/' + pins['tag_object'])
    verify_metadata(pins, before, ref, tag)
    dist = out / 'download'; dist.mkdir()
    run('download', ['gh', 'release', 'download', pins['tag'], '--repo', pins['repository'], '--dir', dist])
    # Resolve the exact reviewed source object locally, never substitute current fixture/harness.
    fixed = out / 'fixed-source'
    run('fixed-source', ['git', '-C', ROOT, 'worktree', 'add', '--detach', fixed, pins['source_commit']])
    require(run('fixed-tree', ['git', '-C', fixed, 'rev-parse', 'HEAD^{tree}']).strip() == pins['source_tree'],
            'fixed source tree mismatch')
    for name, expected in pins['fixed_source_files'].items():
        checked_digest(fixed / name, expected)
    spec = importlib.util.spec_from_file_location('published03_inventory', fixed / 'tools/release/release_inventory.py')
    inventory_module = importlib.util.module_from_spec(spec); spec.loader.exec_module(inventory_module)
    unpack = out / 'runtime'; unpack.mkdir()
    plugin, inventory = verify_local_bytes(pins, dist, unpack, inventory_module)
    for asset in before['assets']:
        require((dist / asset['name']).stat().st_size == asset['size'], 'asset size mismatch')
    tool_pin = pins['cosign']
    cache = args.tool_cache.absolute(); cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    cosign = cache / tool_pin['asset']
    if not cosign.exists():
        run('cosign-download', ['gh', 'release', 'download', tool_pin['tag'], '--repo', tool_pin['repository'],
                                '--pattern', tool_pin['asset'], '--dir', cache])
    checked_digest(cosign, tool_pin['sha256'])  # includes cache hits; never redownload on mismatch
    cosign.chmod(0o700)
    run('cosign-version', [cosign, 'version'])
    for index, name in enumerate(inventory['integrity_subjects']):
        file = dist / name
        run(f'cosign-{index}', [cosign, 'verify-blob', '--signature', str(file) + '.sig',
            '--certificate', str(file) + '.crt', '--certificate-oidc-issuer', pins['oidc_issuer'],
            '--certificate-identity', pins['certificate_identity'], file])
        run(f'provenance-{index}', ['gh', 'attestation', 'verify', file, '--repo', pins['repository'],
            '--cert-identity', pins['certificate_identity'], '--cert-oidc-issuer', pins['oidc_issuer'], '--source-ref', 'refs/tags/' + pins['tag'],
            '--source-digest', pins['source_commit'], '--signer-digest', pins['source_commit'], '--format', 'json'])
    core_pin = pins['validator_manifest']['core']
    core_dir = out / 'core'; core_dir.mkdir()
    run('core-download', ['gh', 'release', 'download', core_pin['release'], '--repo', 'musutrade/GateHouse',
                         '--pattern', core_pin['binary'], '--pattern', core_pin['binary'] + '.sig',
                         '--pattern', core_pin['binary'] + '.crt', '--dir', core_dir])
    for name, expected in pins['core_assets'].items():
        checked_digest(core_dir / name, expected)
    core = core_dir / core_pin['binary']; checked_digest(core, core_pin['sha256'])
    core_identity = pins['core_certificate_identity']
    run('core-cosign', [cosign, 'verify-blob', '--signature', str(core) + '.sig',
        '--certificate', str(core) + '.crt', '--certificate-oidc-issuer', pins['oidc_issuer'],
        '--certificate-identity', core_identity, core])
    run('core-provenance', ['gh', 'attestation', 'verify', core, '--repo', 'musutrade/GateHouse',
        '--cert-identity', core_identity, '--cert-oidc-issuer', pins['oidc_issuer'], '--source-ref', 'refs/tags/' + core_pin['release'],
        '--source-digest', core_pin['source_commit'], '--signer-digest', core_pin['source_commit'], '--format', 'json'])
    # All received runtime bytes verified before the first downloaded executable runs.
    after = api('release-after', 'releases/tags/' + pins['tag'])
    verify_metadata(pins, after, api('tag-ref-after', 'git/ref/tags/' + pins['tag']), tag)
    core.chmod(0o700); (plugin / 'inventory').chmod(0o700)
    tools = verify_toolchain(pins['validator_manifest'])
    cargo = verify_cargo_environment(fixed)
    source = fixed / 'plugins/rust-source-risk'
    manifest = out / 'validator-manifest.json'; write(manifest, pins['validator_manifest'])
    checked_digest(manifest, pins['validator_manifest_sha256'])
    started_ns = time.time_ns()
    run('fresh-capture', [sys.executable, plugin / 'capture.py', '--repository', source / 'fixtures/thiserror-subset',
        '--output', out / 'capture', '--target-dir', out / 'target', '--manifest', 'Cargo.toml',
        '--source-root', 'apps/server/src', '--input', 'Cargo.toml', '--input', 'Cargo.lock',
        '--input', 'apps/server/src', '--input', 'tests', '--test', 'integration'])
    bundle = out / 'capture/bundle.json'
    raw = read_json(bundle)['request']['parameters']['receipt']
    require(bundle.stat().st_mtime_ns >= started_ns and all(
        (Path(raw['raw_root']) / name).stat().st_mtime_ns >= started_ns for name in raw['raw']), 'capture is not fresh')
    inner_path = out / 'acceptance/receipt.json'
    run('signed-core', [sys.executable, source / 'candidate_acceptance.py', '--pins', manifest,
        '--pins-sha256', pins['validator_manifest_sha256'], '--archive', dist / pins['validator_manifest']['candidate']['archive'],
        '--sbom', dist / pins['validator_manifest']['candidate']['sbom'], '--bundle', bundle, '--core', core,
        '--presets-dir', fixed / 'presets', '--output', inner_path])
    inner = read_json(inner_path); host = inner_path.parent / 'host'
    verify_fresh_result(pins, inner, bundle, host)
    run('request-signature', ['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', host / 'public.der',
        '-keyform', 'DER', '-rawin', '-in', host / 'valid-sign-input.json', '-sigfile', host / 'valid-signature.bin'])
    require(run('runner-head-end', ['git', '-C', ROOT, 'rev-parse', 'HEAD']).strip() == head and
            file_digest(Path(__file__)) == runner_sha256 and
            not run('runner-clean-end', ['git', '-C', ROOT, 'status', '--porcelain']).strip(),
            'runner source changed during acceptance')
    receipt = {'schema': 'rust-source-risk-published-download-acceptance/v1', 'status': 'pass',
        'scope': 'immutable published0.3 downloaded bytes; fresh fixture capture and signed Core chain',
        'release': {k: pins[k] for k in ['repository', 'release_id', 'tag', 'tag_object', 'source_commit', 'source_tree',
                                        'certificate_identity', 'oidc_issuer', 'assets']},
        'core_assets': pins['core_assets'], 'core_certificate_identity': core_identity,
        'cosign': tool_pin, 'pins_sha256': file_digest(PINS),
        'runner': {'head': head, 'sha256': runner_sha256, 'fixed_source_files': pins['fixed_source_files']},
        'fresh_started_ns': started_ns, 'fresh_finished_ns': time.time_ns(), 'bundle_sha256': file_digest(bundle),
        'validator_manifest_sha256': file_digest(manifest), 'inner_receipt_sha256': file_digest(inner_path),
        'inner_schema': inner['schema'], 'inner_scope': inner['scope'],
        'harness_note': 'Fixed release-source candidate validator reused on NEW downloaded bytes. '
                        'Inner candidate schema retained; outer public identity separately verified; no historical receipt relabeled.',
        'positive': inner['positive'], 'negatives': inner['negatives'], 'policy_fail': inner['policy_fail'],
        'core': inner['core'], 'toolchain': tools, 'cargo_environment': cargo, 'commands': commands,
        'limitations': ['Linux x86_64 fixed fixture only; not full Core-project or real-user deployment',
            'No Rust name resolution or macro-origin proof; aliases/re-exports unsupported',
            'Core project capture rejects build.rs/config; secrets/verify macros remain unsupported by source-risk',
            'No Core production pin, policy/threshold/baseline/MIR change; not production trust provisioning']}
    write(out / 'receipt.json', receipt)
    print(json.dumps({'status': 'pass', 'receipt': str(out / 'receipt.json'), 'records': 4, 'negatives': 10}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (AcceptanceError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f'PUBLISHED03 ACCEPTANCE FAILED: {error}', file=sys.stderr)
        raise SystemExit(1)
