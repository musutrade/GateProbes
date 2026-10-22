"""Verify the extracted-package lifecycle report against its exact archive."""
import argparse
import hashlib
import json
from pathlib import Path

from package_lifecycle import BINARY, extract
from lifecycle_core import EXPECTED
import tempfile


def verify(report, archive):
    value = json.loads(report.read_text())
    data = archive.read_bytes()
    with tempfile.TemporaryDirectory(prefix='verify-lifecycle-') as temp:
        installed = extract(data, Path(temp), archive.name.removesuffix('.tar.gz'))
        binary = hashlib.sha256((installed / BINARY).read_bytes()).hexdigest()
    expected = ['normal', 'health-failure', 'host-digest', 'host-symlink', 'host-mode',
                'installation-product', 'installation-version', 'installation-protocol', 'config-schema',
                'config-principal', 'config-engine', 'executable-digest', 'executable-mode', 'descriptor-symlink']
    if (value.get('passed') != 14 or value.get('source') != 'extracted-package'
            or value.get('core_sha256') != EXPECTED['sha256'] or value.get('adapter_sha256') != binary
            or value.get('archive_sha256') != hashlib.sha256(data).hexdigest()
            or [c.get('case') for c in value.get('cases', [])] != expected
            or not all(c.get('passed') for c in value['cases'])
            or any(c['requests'] for c in value['cases'][2:])
            or any([command['exit'] for command in c['commands']] != ([0] if c['case'] == 'normal' else
                [1, 0, 1] if c['case'] == 'health-failure' else [1]) for c in value['cases'])):
        raise ValueError('lifecycle acceptance identity or case mismatch')
    return value


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    args = parser.parse_args()
    verify(args.report, args.archive)
