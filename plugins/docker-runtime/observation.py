"""Conservative read-only engine observations, not a v2 wire/absence producer."""
import json
import re
import time

import unix_http


class InvalidObservation(ValueError):
    pass


def require(condition):
    if not condition:
        raise InvalidObservation('runtime observation unavailable')


def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value)
        value[key] = item
    return value


def invalid_constant(_value):
    raise InvalidObservation('runtime observation unavailable')


def document(reply):
    require(reply.status == 200)
    value = json.loads(reply.body.decode('utf-8'), object_pairs_hook=pairs,
                       parse_constant=invalid_constant)
    require(type(value) is dict)
    return value


def version(value):
    require(type(value) is str and
            re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value) is not None)
    parts = tuple(int(part) for part in value.split('.'))
    require(all(part <= 65535 for part in parts))
    return parts


def text(value):
    require(type(value) is str and bool(value.strip()) and
            not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value))
    return value


def identity(config, fetch):
    server = document(fetch('/version'))
    require(server.get('Version') == config.server_version)
    maximum = version(server.get('ApiVersion'))
    minimum = version(server.get('MinAPIVersion'))
    require(minimum <= version(config.api_version) <= maximum)
    info = document(fetch(f'/v{config.api_version}/info'))
    require(info.get('ID') == config.daemon_id)
    return {'api_version': config.api_version, 'server_version': config.server_version,
            'daemon_id': config.daemon_id}


def present(value, object_id):
    require(value.get('Id') == object_id)
    configuration = value.get('Config')
    require(type(configuration) is dict)
    labels = configuration.get('Labels')
    require(type(labels) is dict and bool(labels))
    return {'object_id': object_id,
            'labels': [{'key': text(key), 'value': text(item)}
                       for key, item in sorted(labels.items())]}


def inspect(config, object_id, *, timeout=5.0, cancelled=lambda: False):
    """Present only with exact ID and matching pre/post observations.

    Every other result, including 404, is unavailable. This intentionally does
    not implement absence, full v2 request validation, persistence or mutation.
    """
    unavailable = {'outcome': 'unavailable', 'observations': None}
    try:
        require(type(object_id) is str and re.fullmatch('[0-9a-f]{64}', object_id) is not None)
        require(type(timeout) in (int, float) and 0 < timeout <= 30)
        deadline = time.monotonic() + timeout

        def fetch(path):
            require(not cancelled())
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            return unix_http.get(config, path, timeout=remaining, cancelled=cancelled)

        before = identity(config, fetch)
        value = document(fetch(f'/v{config.api_version}/containers/{object_id}/json'))
        result = present(value, object_id)
        after = identity(config, fetch)
        require(before == after and not cancelled() and time.monotonic() < deadline)
        return {'outcome': {'present': {'object': result}},
                'observations': {'observed_before': before, 'observed_after': after}}
    except (OSError, ValueError, TypeError, AttributeError, RecursionError, OverflowError):
        return unavailable
