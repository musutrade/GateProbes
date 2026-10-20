"""Linux acceptance entry only. Immutable fd3=config, fd4=expected, stdin=actual.

The launching harness, not this script, authenticates its executable+version and
creates expected identities. No installed/bootstrap authority is implied.
"""
import json
import os
import re
import sys

import config
import observation

LIMIT = 65536
BINDING = {'protocol', 'adapter_sha256', 'adapter_version', 'invocation',
           'operation_key', 'generation', 'adapter_config_sha256', 'engine',
           'transport', 'socket_path', 'socket_uid', 'principal_uid', 'rootless',
           'api_version', 'server_version', 'daemon_id', 'scope'}


def require(condition):
    if not condition:
        raise ValueError('runtime fixture input rejected')


def shape(value, fields):
    require(type(value) is dict and set(value) == fields)


def request(raw):
    require(len(raw) <= LIMIT)
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=observation.pairs,
                       parse_constant=observation.invalid_constant)
    shape(value, {'binding', 'operation'})
    binding = value['binding']
    shape(binding, BINDING)
    require(binding['protocol'] == 'gate-runtime/v2')
    require(binding['engine'] == 'docker' and binding['transport'] == 'unix-http')
    for key in BINDING - {'socket_uid', 'principal_uid', 'rootless'}:
        observation.text(binding[key])
    for key in ('adapter_sha256', 'adapter_config_sha256'):
        require(re.fullmatch('[0-9a-f]{64}', binding[key]) is not None)
    for key in ('socket_uid', 'principal_uid'):
        require(type(binding[key]) is int and 0 <= binding[key] <= 4294967295)
    require(type(binding['rootless']) is bool)
    observation.version(binding['api_version'])
    path = binding['socket_path']
    require(path.startswith('/') and all(x not in ('', '.', '..') for x in path[1:].split('/')))
    operation = value['operation']
    if operation != 'capabilities':
        require(type(operation) is dict and len(operation) == 1)
        name = next(iter(operation))
        require(name in ('inspect', 'remove'))
        shape(operation[name], {'object_id'})
        object_id = operation[name]['object_id']
        require(type(object_id) is str and re.fullmatch('[0-9a-f]{64}', object_id) is not None)
    return value


def descriptor_boundary():
    require(sys.platform == 'linux' and len(sys.argv) == 1)
    # listdir's own transient fd may be present in its listing; only live fds
    # matter. Never close unrelated descriptors to make a bad launch look valid.
    for name in os.listdir('/proc/self/fd'):
        number = int(name)
        try:
            os.fstat(number)
        except OSError:
            continue
        require(number in (0, 1, 2, 3, 4))


def respond(actual_bytes):
    descriptor_boundary()
    expected_bytes, _ = config.sealed_bytes(4)
    expected = request(expected_bytes)
    actual = request(actual_bytes)
    require(actual == expected)
    binding = expected['binding']
    loaded = config.load_sealed(3, binding['adapter_config_sha256'])
    for key in config.FIELDS - {'schema', 'engine', 'transport'}:
        require(getattr(loaded, key) == binding[key])
    operation = expected['operation']
    if operation == 'capabilities':
        result = {'outcome': {'capabilities': {'supported': ['inspect']}}, 'observations': None}
    else:
        require('inspect' in operation)  # Remove: static failure, never a result.
        result = observation.inspect(loaded, operation['inspect']['object_id'])
    response = dict(binding=binding, operation=operation, **result)
    output = json.dumps(response, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    require(len(output) <= LIMIT)
    return output


def main():
    try:
        output = respond(sys.stdin.buffer.read(LIMIT + 1))
    except (OSError, ValueError, TypeError, AttributeError, RecursionError, OverflowError):
        sys.stderr.write('runtime fixture input or execution rejected\n')
        return 1
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
