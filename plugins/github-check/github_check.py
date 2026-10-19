#!/usr/bin/env python3
"""Optional existing-Check consumer. Never imported or invoked by Rust Core."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import urllib.error
import urllib.request


class Rejected(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=strict_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(Rejected('nonfinite JSON')))


def load(path):
    require(path.stat().st_size <= 16 * 1024 * 1024, 'JSON input too large')
    return decode(path.read_bytes())


def saved_result(core, core_sha256, index):
    require(core.is_absolute() and core.is_file(), 'absolute trusted Core executable required')
    with core.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    require(actual == core_sha256, 'Core executable digest differs from consumer configuration')
    # The verifier receives no publisher credentials or inherited developer env.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        completed = subprocess.run(
            [str(core), 'report-verify', '--input', str(index.resolve())],
            env={'PATH': os.defpath, 'LANG': 'C.UTF-8'}, stdin=subprocess.DEVNULL,
            stdout=output, stderr=errors, timeout=60, check=False)
        require(completed.returncode == 0, 'Core rejected saved evidence')
        require(output.tell() <= 16 * 1024 * 1024, 'Core result too large')
        output.seek(0)
        verified = decode(output.read())
    require(verified['historical_integrity'] == 'verified', 'historical evidence not verified')
    return verified


def target(config, now=None):
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', config['repository']), 'repository')
    require(re.fullmatch(r'[a-f0-9]{40}', config['target_sha']), 'target SHA')
    for key in ('check_id', 'app_id', 'generation'):
        require(type(config[key]) is int and config[key] > 0, key)
    require(isinstance(config['check_name'], str) and 0 < len(config['check_name']) <= 100,
            'check name')
    expiry = dt.datetime.fromisoformat(config['expires_at'].replace('Z', '+00:00'))
    require(expiry.tzinfo is not None and expiry > (now or dt.datetime.now(dt.timezone.utc)),
            'current-use approval expired')


def mapping(config, verified, now=None):
    """Compare operator-pinned current use to verified history; never evaluate quality."""
    target(config, now)
    # These pins must come from the consumer's trusted current-use review, not
    # from an event or candidate. The machine pin also binds baseline and coverage.
    for key in ('machine_sha256', 'manifest_sha256'):
        require(re.fullmatch(r'[a-f0-9]{64}', config[key]), key)
        require(verified[key] == config[key], key + ' differs from current-use approval')
    result = verified['result']
    require(verified['invocation_id'] == config['invocation_id'] == result['invocation_id'],
            'invocation mismatch')
    identities = result['identities']
    for key in ('source_identity', 'configuration_digest', 'profile'):
        require(result[key] == config[key], key + ' mismatch')
    for key in ('verification_policy_identity', 'quality_policy_identity', 'runtime_bundle_digest'):
        require(identities[key] == config[key] and isinstance(config[key], str) and config[key],
                key + ' mismatch or missing')
    require(identities['policy_binding_complete'] is True, 'compiled policy binding missing')
    require(result['evidence_complete'] is True, 'incomplete evidence')
    require(result['status'] in ('PASS', 'WAIVED', 'FAIL', 'CANCELLED'), 'unexecuted result')
    require(type(result['passed']) is bool, 'missing Core decision')
    require(result['passed'] == (result['status'] in ('PASS', 'WAIVED')), 'inconsistent Core decision')
    if result['passed']:
        quality = result['quality']
        require(quality['phase'] == 'complete' and quality['status'] == 'pass'
                and quality['full_quality_status'] == 'pass', 'full quality result required')
    # A current-use approval is an independently reviewed exact result pin, not
    # a claim that Core's not_proven field magically became an attestation.
    require(config['current_use_review'] == 'approved-exact-result', 'current use not approved')
    conclusion = 'success' if result['passed'] else ('cancelled' if result['status'] == 'CANCELLED' else 'failure')
    external_id = 'gate-result:' + config['machine_sha256'] + ':' + str(config['generation'])
    return {'name': config['check_name'], 'status': 'completed', 'conclusion': conclusion,
            'external_id': external_id,
            'output': {'title': 'GateHouse ' + result['status'],
                       'summary': 'Core invocation ' + config['invocation_id'] + '\nMachine SHA256: '
                                  + config['machine_sha256'] + '\nMapped from independently reviewed current-use pins.'}}


def withdrawal(config):
    """Withdraw platform applicability, without modifying historical quality."""
    target(config)
    require(config['current_use_review'] == 'withdrawn', 'withdrawal review required')
    reason = config['withdrawal_reason']
    require(isinstance(reason, str) and 0 < len(reason) <= 1000, 'withdrawal reason')
    return {'name': config['check_name'], 'status': 'completed', 'conclusion': 'failure',
            'external_id': 'gate-withdrawal:' + str(config['generation']),
            'output': {'title': 'GateHouse result applicability withdrawn',
                       'summary': reason + '\nHistorical Core conclusions are unchanged.'}}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise Rejected('GitHub redirect rejected')


class GitHub:
    def __init__(self, token):
        require(bool(token), 'consumer token missing')
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, method, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request('https://api.github.com' + path, data=body, method=method,
            headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                     'Content-Type': 'application/json', 'X-GitHub-Api-Version': '2022-11-28',
                     'User-Agent': 'GateHouse-independent-result-consumer'})
        with self.opener.open(request, timeout=30) as response:
            data = response.read(16 * 1024 * 1024 + 1)
            require(len(data) <= 16 * 1024 * 1024, 'API response too large')
            return decode(data)


def identity(remote, config):
    require(remote['id'] == config['check_id'] and remote['head_sha'] == config['target_sha']
            and remote['name'] == config['check_name'] and remote['app']['id'] == config['app_id'],
            'remote Check identity mismatch')


def deliver(config, payload, state, api):
    """Single writer per protected state DB; uncertain writes block later generations."""
    key = config['repository'] + ':' + str(config['check_id'])
    operation = digest(json.dumps({'config': config, 'payload': payload}, sort_keys=True).encode())
    with sqlite3.connect(state, timeout=30) as db:
        db.execute('PRAGMA synchronous=FULL')
        db.execute('CREATE TABLE IF NOT EXISTS deliveries (identity TEXT PRIMARY KEY, generation INTEGER, operation TEXT, phase TEXT, remote TEXT)')
        db.commit()
        db.execute('BEGIN IMMEDIATE')
        previous = db.execute('SELECT generation,operation,phase,remote FROM deliveries WHERE identity=?', (key,)).fetchone()
        if previous:
            generation, old_operation, phase, remote = previous
            require(config['generation'] >= generation, 'stale generation')
            if config['generation'] == generation:
                require(operation == old_operation, 'conflicting duplicate generation')
                if phase == 'confirmed':
                    return decode(remote)
            require(phase == 'confirmed', 'uncertain prior API operation; operator reconciliation required')
        path = '/repos/' + config['repository'] + '/check-runs/' + str(config['check_id'])
        remote = api.request('GET', path)
        identity(remote, config)
        target(config)  # A slow preflight must not outlive the approval.
        # Persist intent BEFORE mutation. A crash or ambiguous transport failure
        # leaves intent, and no later invocation can write through that fence.
        db.execute('INSERT OR REPLACE INTO deliveries VALUES (?,?,?,?,?)',
                   (key, config['generation'], operation, 'intent', None))
        db.commit()
        try:
            remote = api.request('PATCH', path, payload)
            identity(remote, config)
            require(remote['external_id'] == payload['external_id']
                    and remote['status'] == 'completed'
                    and remote['conclusion'] == payload['conclusion'], 'API did not confirm mapping')
        except Exception:
            # Intent intentionally remains durable. Never invent a remote success.
            raise Rejected('API update unconfirmed; preserved intent blocks subsequent updates') from None
        db.execute('BEGIN IMMEDIATE')
        db.execute('UPDATE deliveries SET phase=?,remote=? WHERE identity=? AND operation=?',
                   ('confirmed', json.dumps(remote), key, operation))
        db.commit()
        return remote


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--index', type=Path)
    parser.add_argument('--core', type=Path)
    parser.add_argument('--withdraw', action='store_true')
    parser.add_argument('--state', type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    config = load(args.config)
    if args.withdraw:
        require(args.core is None and args.index is None, 'withdrawal does not read or rewrite historical evidence')
        payload = withdrawal(config)
    else:
        require(args.core is not None and args.index is not None, 'Core and saved index required')
        verified = saved_result(args.core, config['verifier_sha256'], args.index)
        payload = mapping(config, verified)
    if args.apply:
        require(args.state is not None, 'protected consumer state database required')
        remote = deliver(config, payload, args.state, GitHub(os.environ.get('GATEHOUSE_CHECK_TOKEN')))
        print(json.dumps({'delivery': 'confirmed', 'check_id': remote['id'], 'conclusion': remote['conclusion']}))
    else:
        print(json.dumps({'delivery': 'not-sent', 'target_sha': config['target_sha'], 'payload': payload}))


if __name__ == '__main__':
    try:
        main()
    except (Rejected, KeyError, ValueError, TypeError, AttributeError, OSError,
            subprocess.SubprocessError, sqlite3.Error) as error:
        # Avoid echoing configuration, candidate strings, API bodies or credentials.
        print(json.dumps({'delivery': 'failed', 'error_type': type(error).__name__}))
        raise SystemExit(1)
