"""Offline byte validation against an independently reviewed release pin.

No paths, writes, network, subprocesses, signature verification or Core execution.
The caller must establish pin authority separately; archive data cannot supply it.
"""
import gzip
import hashlib
import io
import json
import re
import tarfile
import zlib

BINARY = 'gateprobes-docker-runtime'
MEMBERS = {BINARY, 'Cargo.lock', 'LICENSE', 'README.md', 'THIRD_PARTY_NOTICES.txt',
           'accept.py', 'build-inputs.json', 'plugin.json', 'rust-toolchain.toml'}
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_TAR = 32 * 1024 * 1024


class InvalidRelease(ValueError):
    pass


def require(condition):
    if not condition:
        raise InvalidRelease('runtime release rejected')


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def decode(data):
    require(isinstance(data, bytes) and len(data) <= 1024 * 1024)
    return json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def profile(expected):
    """Select only from an externally trusted tag; archive content cannot select."""
    version = expected['version']
    tag = expected['tag']
    if tag == 'docker-runtime-v' + version:
        return 'docker-runtime', BINARY, 'gate-runtime/v2'
    if tag == 'docker-readiness-v' + version and version == '0.2.0':
        return 'docker-readiness', 'gateprobes-docker-readiness', 'gate-runtime/v3'
    if tag == 'docker-lifecycle-v0.1.0' and version == '0.1.0':
        return 'docker-lifecycle', 'gateprobes-docker-lifecycle', 'gate-runtime/lifecycle-v1'
    if tag == 'podman-lifecycle-v0.2.0' and version == '0.2.0':
        return 'podman-lifecycle', 'gateprobes-podman-lifecycle', 'gate-runtime/lifecycle-v2'
    if tag == 'podman-lifecycle-v0.3.0' and version == '0.3.0':
        return 'podman-lifecycle', 'gateprobes-podman-lifecycle', 'gate-runtime/lifecycle-v1'
    raise InvalidRelease('runtime release rejected')


def archive_name(expected):
    _, binary, _ = profile(expected)
    return binary + '-' + expected['version'] + '-linux-amd64.tar.gz'


def pin(data):
    value = decode(data)
    require(type(value) is dict and set(value) == {
        'schema', 'repository', 'tag', 'source_commit', 'version',
        'archive_sha256', 'sbom_sha256', 'inventory_sha256',
        'checksums_sha256', 'executable_sha256'})
    require(value['schema'] == 'gateprobes-runtime-release-pin/v1')
    require(value['repository'] == 'https://github.com/musutrade/GateProbes')
    version = value['version']
    require(isinstance(version, str) and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version))
    profile(value)
    for key, size in [('source_commit', 40)] + [(k, 64) for k in value if k.endswith('_sha256')]:
        require(isinstance(value[key], str) and re.fullmatch('[0-9a-f]{' + str(size) + '}', value[key]))
    return value


def unpack(data, prefix, binary=BINARY):
    members = (MEMBERS - {BINARY}) | {binary}
    if binary == 'gateprobes-docker-lifecycle':
        members |= {'Cargo.toml', 'core-pin.json', 'protocol-LICENSE', 'protocol-license.json'}
    if binary == 'gateprobes-podman-lifecycle':
        members |= {'Cargo.toml', 'core-pin.json', 'protocol-LICENSE'}
    require(len(data) <= MAX_ARCHIVE)
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as zipped:
        raw = zipped.read(MAX_TAR + 1)
    require(len(raw) <= MAX_TAR)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as stream:
        for member in stream:
            require(len(files) < len(members))
            name = member.name
            require(name.startswith(prefix + '/'))
            relative = name[len(prefix) + 1:]
            require(relative in members and relative not in files)
            require(member.isfile() and not member.linkname and not member.pax_headers)
            require(member.mode == (0o755 if relative == binary else 0o644))
            require(0 < member.size <= MAX_TAR)
            content = stream.extractfile(member).read(member.size + 1)
            require(len(content) == member.size)
            files[relative] = content
    require(set(files) == members)
    return files


def validate_inventory(inventory, expected, assets):
    require(type(inventory) is dict and type(inventory.get('schema_version')) is int)
    require(inventory['schema_version'] == 1)
    require(inventory['source'] == {'repository': expected['repository'], 'commit': expected['source_commit']})
    require(inventory['tag'] == expected['tag'])
    require(inventory['checksum_file'] == 'SHA256SUMS')
    require(inventory['inventory_file'] == 'release-inventory.json')
    require(sorted(inventory['checksum_subjects']) == sorted([*assets, 'release-inventory.json']))
    rows = inventory['assets']
    require(type(rows) is list and len(rows) == 2)
    require({row['name'] for row in rows} == set(assets))
    for row in rows:
        content = assets[row['name']]
        require(type(row['size_bytes']) is int and row['size_bytes'] == len(content))
        require(row['sha256'] == digest(content))
        require(row['kind'] == ('package' if row['name'].endswith('.tar.gz') else 'sbom'))


def validate_sbom(sbom, expected, files):
    require(sbom['bomFormat'] == 'CycloneDX' and sbom['specVersion'] == '1.5')
    require(sbom['metadata']['component'] == {'type': 'application', 'name': profile(expected)[0], 'version': expected['version']})
    rows = [row for row in sbom['components'] if row['type'] == 'file']
    require(len(rows) == len(files) and {row['name'] for row in rows} == set(files))
    for row in rows:
        require(row['hashes'] == [{'alg': 'SHA-256', 'content': digest(files[row['name']])}])


def validate(pin_bytes, archive, sbom, inventory, checksums):
    """Return validated member bytes. This does not install or authenticate a pin."""
    try:
        expected = pin(pin_bytes)
        for key, data in [('archive', archive), ('sbom', sbom), ('inventory', inventory), ('checksums', checksums)]:
            require(isinstance(data, bytes))
            require(digest(data) == expected[key + '_sha256'])
        require(len(checksums) <= 4096)
        product, binary, protocol = profile(expected)
        name = archive_name(expected)
        assets = {name: archive, name + '.sbom.cdx.json': sbom}
        subjects = {**assets, 'release-inventory.json': inventory}
        lines = checksums.decode('ascii').splitlines()
        require(len(lines) == len(subjects))
        require(set(lines) == {digest(data) + '  ' + name for name, data in subjects.items()})
        validate_inventory(decode(inventory), expected, assets)
        files = unpack(archive, name.removesuffix('.tar.gz'), binary)
        require(digest(files[binary]) == expected['executable_sha256'])
        manifest = decode(files['plugin.json'])
        require(manifest['name'] == product and manifest['version'] == expected['version'])
        require(manifest['executable'] == binary and manifest['protocol'] == protocol)
        if product == 'docker-lifecycle':
            require(manifest['core_versions'] == ['0.10.0'])
        if product == 'podman-lifecycle':
            if expected['version'] == '0.2.0':
                require(manifest['core_versions'] == ['0.12.0'])
                require(manifest['authority'] == 'read-only-runtime-facts')
                require(manifest['capabilities'] == ['capture'])
            elif expected['version'] == '0.3.0':
                require(manifest['core_versions'] == ['0.13.0'])
                require(manifest['authority'] == 'container-lifecycle/mutate')
                require(manifest['capabilities'][:1] == ['capture'])
                require({'create', 'status', 'start', 'stop', 'remove', 'health'}
                        <= set(manifest['capabilities']))
        validate_sbom(decode(sbom), expected, files)
        return files
    except (ValueError, TypeError, KeyError, AttributeError, OSError, EOFError, OverflowError, RecursionError, tarfile.TarError, zlib.error):
        raise InvalidRelease('runtime release rejected') from None
