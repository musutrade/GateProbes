#!/usr/bin/python3
"""Signed executable template; tests embed fixture measurements before signing."""
import json
import os
from pathlib import Path
import sys
import time

PAYLOAD = json.loads('PAYLOAD_PLACEHOLDER')
request = json.load(sys.stdin)
mode = PAYLOAD['mode']
if mode == 'crash':
    os._exit(17)
if mode == 'timeout':
    time.sleep(4)
if mode == 'malformed':
    print('not json')
    sys.exit(0)
if mode == 'duplicate-json':
    print(json.dumps(PAYLOAD['response']).replace('{', '{"status":"PASS",', 1))
    sys.exit(0)
root = Path(request['artifact_root'])
(root / 'raw.json').write_text(PAYLOAD['raw'])
if mode == 'tamper-artifact':
    (root / 'raw.json').write_text('tampered')
if mode == 'extra-artifact':
    (root / 'unregistered').write_text('extra')
if mode == 'source-change':
    (Path(request['input']['workspace_root']) / 'src/lib.rs').write_text('changed')
if mode == 'config-change':
    (Path(request['input']['workspace_root']) / '.harness-gate/policy.json').write_text('{}')
if mode == 'symlink':
    (root / 'alias').symlink_to(root / 'raw.json')
if mode == 'cancel-parent':
    print(json.dumps(PAYLOAD['response']))
    sys.stdout.flush()
    import signal
    os.kill(os.getppid(), signal.SIGINT)
    time.sleep(2)
    sys.exit(0)
print(json.dumps(PAYLOAD['response']))
