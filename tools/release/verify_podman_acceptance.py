"""Verify the exact read-only package acceptance report against archive bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

from package_podman import BINARY, MEMBERS
from podman_core import EXPECTED

CASES = ['normal', 'no-persist', 'missing-trust', 'missing-mapped-host-with-valid-host-elsewhere',
         'host-digest', 'host-mode', 'host-symlink', 'installation-product-or-version',
         'installation-protocol-or-config-schema', 'config-digest-or-schema',
         'config-principal-or-socket-identity', 'executable-digest', 'executable-mode',
         'docker-or-mixed-profile', 'invalid-image-id', 'duplicate-label', 'incomplete-port-pair',
         'timeout-out-of-range', 'override-host', 'override-output', 'override-socket']
PARSE_ERRORS = {'missing-trust', 'incomplete-port-pair', 'timeout-out-of-range', 'override-host', 'override-output', 'override-socket'}


def verify(report, archive):
    value = json.loads(report.read_text())
    if (value.get('schema'), value.get('product'), value.get('version'), value.get('core_version'),
        value.get('core_sha256'), value.get('archive_sha256'), value.get('passed')) != (
            'gateprobes-podman-lifecycle-acceptance/v1', 'podman-lifecycle', '0.1.0', '0.11.0',
            EXPECTED['sha256'], hashlib.sha256(archive.read_bytes()).hexdigest(), len(CASES)):
        raise ValueError('Podman acceptance identity mismatch')
    rows = value.get('cases', [])
    if [r.get('case') for r in rows] != CASES:
        raise ValueError('Podman acceptance case inventory mismatch')
    for i, row in enumerate(rows):
        expected_exit = 0 if i < 2 else 2 if row['case'] in PARSE_ERRORS else 1
        if (row.get('passed') is not True or row.get('exit') != expected_exit
                or row.get('connections') != (3 if i < 2 else 0) or row.get('files_created') != []):
            raise ValueError('Podman case failed or incomplete')
        expected_routes = [['GET', '/v6.1.4/libpod/info'], ['GET', '/v6.1.4/libpod/images/' + 'b' * 64 + '/json'], ['GET', '/v6.1.4/libpod/info']] if i < 2 else []
        if row.get('routes') != expected_routes or (i < 2 and row.get('stderr_empty') is not True):
            raise ValueError('Podman route/stderr mismatch')
        if i >= 2 and row.get('stdout_sha256') != hashlib.sha256(b'').hexdigest():
            raise ValueError('Podman negative output not empty')
    if value.get('socket_connections_total') != 6 or value.get('mutation_attempts') != 0 or value.get('files_created') != []:
        raise ValueError('Podman acceptance effects mismatch')
    with tarfile.open(archive) as stream:
        prefix = archive.name.removesuffix('.tar.gz')
        members = stream.getmembers()
        if len(members) != len(MEMBERS) or {m.name for m in members} != {prefix + '/' + n for n in MEMBERS}:
            raise ValueError('Podman archive members mismatch')
        for member in members:
            name = member.name.removeprefix(prefix + '/')
            if (not member.isfile() or member.pax_headers or member.uid or member.gid
                    or member.mtime or member.size <= 0
                    or member.mode != (0o755 if name == BINARY else 0o644)):
                raise ValueError('Podman archive metadata mismatch')
        binary = stream.extractfile(prefix + '/' + BINARY).read()
    if value.get('executable_sha256') != hashlib.sha256(binary).hexdigest():
        raise ValueError('Podman executable binding mismatch')
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    args = parser.parse_args()
    verify(args.report, args.archive)
