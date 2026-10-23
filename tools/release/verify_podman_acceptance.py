"""Verify the exact Podman 0.3.0 capture and mutation package reports."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

from package_podman import BINARY, MEMBERS_0_2, MEMBERS_0_3

VERSION = '0.3.0'
CORE_VERSION = '0.13.0'
CORE_SHA = '1800325ea2f541dd9b011c03dc93c3dac341e839ece6289ebe778275dcaacf75'
CORE_SHA_0_2 = '6890e4465c9d86f53cffe8c58103a650babd03db895e27ae99928659c4f1d1d6'
CAPTURE_CASES = ['normal', 'no-persist', 'missing-trust', 'missing-mapped-host-with-valid-host-elsewhere',
                 'host-digest', 'host-mode', 'host-symlink', 'installation-product-or-version',
                 'installation-protocol-or-config-schema', 'config-digest-or-schema',
                 'config-principal-or-socket-identity', 'executable-digest', 'executable-mode',
                 'docker-or-mixed-profile', 'invalid-image-id', 'duplicate-label', 'incomplete-port-pair',
                 'timeout-out-of-range', 'override-host', 'override-output', 'override-socket']
CAPTURE_PARSE_ERRORS = {'missing-trust', 'incomplete-port-pair', 'timeout-out-of-range', 'override-host',
                        'override-output', 'override-socket'}
MUTATION_CASES = ['capture-config-refuses-mutation', 'resolve-image', 'create', 'status', 'start',
                  'stop', 'remove', 'health']
MUTATIONS = {'capture-config-refuses-mutation': 0, 'resolve-image': 0, 'create': 1, 'status': 0,
             'start': 1, 'stop': 1, 'remove': 1, 'health': 2}
CONNECTIONS = {'capture-config-refuses-mutation': 0, 'resolve-image': 3, 'create': 4, 'status': 3,
               'start': 5, 'stop': 5, 'remove': 4, 'health': 7}


def archive_binary(archive, members):
    with tarfile.open(archive) as stream:
        prefix = archive.name.removesuffix('.tar.gz')
        actual = stream.getmembers()
        if len(actual) != len(members) or {m.name for m in actual} != {prefix + '/' + n for n in members}:
            raise ValueError('Podman archive members mismatch')
        for member in actual:
            name = member.name.removeprefix(prefix + '/')
            if (not member.isfile() or member.pax_headers or member.uid or member.gid
                    or member.mtime or member.size <= 0
                    or member.mode != (0o755 if name == BINARY else 0o644)):
                raise ValueError('Podman archive metadata mismatch')
        return hashlib.sha256(stream.extractfile(prefix + '/' + BINARY).read()).hexdigest()


def common(value, archive, schema, passed, members, version, core_sha):
    if (value.get('schema'), value.get('product'), value.get('version'), value.get('core_sha256'),
            value.get('archive_sha256'), value.get('passed')) != (
            schema, 'podman-lifecycle', version, core_sha,
            hashlib.sha256(archive.read_bytes()).hexdigest(), passed):
        raise ValueError('Podman acceptance identity mismatch')
    if value.get('executable_sha256') != archive_binary(archive, members):
        raise ValueError('Podman executable binding mismatch')
    if value.get('files_created') != []:
        raise ValueError('Podman acceptance created files')


def verify(report, archive):
    value = json.loads(report.read_text())
    common(value, archive, 'gateprobes-podman-lifecycle-acceptance/v1', len(CAPTURE_CASES), MEMBERS_0_2, '0.2.0', CORE_SHA_0_2)
    if value.get('core_version') != '0.12.0':
        raise ValueError('Podman Core version mismatch')
    rows = value.get('cases', [])
    if [r.get('case') for r in rows] != CAPTURE_CASES:
        raise ValueError('Podman capture case inventory mismatch')
    for i, row in enumerate(rows):
        expected_exit = 0 if i < 2 else 2 if row['case'] in CAPTURE_PARSE_ERRORS else 1
        if (row.get('passed') is not True or row.get('exit') != expected_exit
                or row.get('connections') != (3 if i < 2 else 0) or row.get('files_created') != []):
            raise ValueError('Podman capture case failed or incomplete')
        expected_routes = ([['GET', '/v6.1.4/libpod/info'],
                            ['GET', '/v6.1.4/libpod/images/' + 'b' * 64 + '/json'],
                            ['GET', '/v6.1.4/libpod/info']] if i < 2 else [])
        if row.get('routes') != expected_routes or (i < 2 and row.get('stderr_empty') is not True):
            raise ValueError('Podman capture route/stderr mismatch')
        if i >= 2 and row.get('stdout_sha256') != hashlib.sha256(b'').hexdigest():
            raise ValueError('Podman capture negative output not empty')
    if value.get('socket_connections_total') != 6 or value.get('mutation_attempts') != 0:
        raise ValueError('Podman capture effects mismatch')
    return value


def verify_mutation(report, archive):
    value = json.loads(report.read_text())
    common(value, archive, 'gateprobes-podman-lifecycle-mutation-acceptance/v1', len(MUTATION_CASES), MEMBERS_0_3, VERSION, CORE_SHA)
    rows = value.get('cases', [])
    if [r.get('case') for r in rows] != MUTATION_CASES:
        raise ValueError('Podman mutation case inventory mismatch')
    for row in rows:
        name = row['case']
        if (row.get('passed') is not True or row.get('exit') != (1 if name == 'capture-config-refuses-mutation' else 0)
                or row.get('connections') != CONNECTIONS[name]
                or row.get('mutation_attempts') != MUTATIONS[name]):
            raise ValueError('Podman mutation case failed or incomplete')
        if name == 'capture-config-refuses-mutation':
            if row.get('routes') != [] or row.get('stdout_sha256') != hashlib.sha256(b'').hexdigest():
                raise ValueError('Podman capture boundary was not inert')
    if (value.get('socket_connections_total'), value.get('mutation_attempts')) != (31, 6):
        raise ValueError('Podman mutation effects mismatch')
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--mutation-report', type=Path)
    args = parser.parse_args()
    verify(args.report, args.archive)
    if args.mutation_report:
        verify_mutation(args.mutation_report, args.archive)
