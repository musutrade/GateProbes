#!/usr/bin/env python3
"""Standalone disposable signer helper; no old release-chain import."""
import base64
import json
import shutil

def write(path, value):
    path.write_text(json.dumps(value, indent=2))



def sign(test, output, request):
    openssl = shutil.which('openssl')
    if not openssl:
        test.skipTest('openssl required for the disposable configured-request signer')
    key = output / 'disposable-test-key.pem'
    public = output / 'disposable-test-key.der'
    for name, args in (
        ('generate', ['genpkey', '-algorithm', 'ED25519', '-out', str(key)]),
        ('public', ['pkey', '-in', str(key), '-pubout', '-outform', 'DER', '-out', str(public)]),
    ):
        result = test.command('configured-key-' + name, [openssl, *args])
        test.assertEqual(result.returncode, 0, result.stderr)
    public_bytes = public.read_bytes()
    test.assertEqual(public_bytes[:12], bytes.fromhex('302a300506032b6570032100'))
    test.assertEqual(len(public_bytes), 44)
    trusted = output / 'trusted-keys.json'
    write(trusted, [{'key_id': 'configured-test',
                    'public_key': base64.b64encode(public_bytes[12:]).decode()}])
    declaration = request['adapter']
    payload = {'domain': 'harness-gate/adapter-request/v2', 'protocol_version': 2,
               'result_schema_version': '1', 'adapter': {key: declaration[key] for key in
               ('name', 'version', 'executable', 'source_digest')}}
    payload['adapter']['signature'] = {'algorithm': 'ed25519', 'key_id': 'configured-test'}
    for name in ('invocation_id', 'step_id', 'timeout_ms', 'config_digest', 'artifact_root',
                 'nonce', 'issued_at_ms', 'expires_at_ms', 'args', 'environment', 'capabilities', 'input'):
        payload[name] = request[name]
    # Match Core's BTreeMap serialization regardless of request insertion order.
    payload['environment'] = dict(sorted(payload['environment'].items()))
    payload['input'] = json.loads(json.dumps(payload['input'], sort_keys=True))
    payload_path = output / 'signed-payload.json'
    payload_path.write_bytes(json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode('utf-8'))
    signature = output / 'signature.bin'
    result = test.command('configured-key-sign', [openssl, 'pkeyutl', '-sign', '-rawin',
        '-inkey', str(key), '-in', str(payload_path), '-out', str(signature)])
    test.assertEqual(result.returncode, 0, result.stderr)
    test.assertEqual(len(signature.read_bytes()), 64)
    declaration['signature']['value'] = base64.b64encode(signature.read_bytes()).decode()
    return trusted
