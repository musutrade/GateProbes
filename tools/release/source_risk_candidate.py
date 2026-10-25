"""Mandatory pre-publication acceptance of the actual source-risk package/SBOM.

This does not download or certify a future release. Manifests describe exact
candidate bytes; the independent published0.2 consumer pins remain read-only.
"""
import ast
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tomllib
import hashlib
import importlib.util


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def identity(source, expected_version):
    manifest = json.loads((source / 'plugin.json').read_text())
    cargo = tomllib.loads((source / 'ast/Cargo.toml').read_text())['package']
    lock = tomllib.loads((source / 'ast/Cargo.lock').read_text())['package']
    roots = [p for p in lock if p['name'] == cargo['name'] and 'source' not in p]
    values = [ast.literal_eval(n.value) for n in ast.parse((source / 'plugin.py').read_text()).body
              if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id=='COLLECTOR' for t in n.targets)]
    expected = {'name':'rust-source-risk','version':expected_version}
    if ({k:manifest[k] for k in expected} != expected or values != [expected]
            or cargo['version'] != expected_version or len(roots)!=1 or roots[0]['version']!=expected_version):
        raise ValueError('source-risk exact product/Cargo/lock/COLLECTOR identity mismatch')
    return expected


def environment(source, core):
    spec = importlib.util.spec_from_file_location('source_risk_core_gate', source / 'core_acceptance.py')
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    pins = json.loads((source / 'core_acceptance.json').read_text())
    return {'core':gate.verify_core(core, pins), 'tools':gate.verify_toolchain(pins),
            'cargo_environment':gate.verify_cargo_environment(source)}


def accept(source, archive, sbom, core, evidence, expected_version):
    expected = identity(source, expected_version)
    evidence.mkdir(parents=True, exist_ok=False)
    head = subprocess.check_output(['git','-C',source,'rev-parse','HEAD'],text=True).strip()
    tree = subprocess.check_output(['git','-C',source,'rev-parse','HEAD^{tree}'],text=True).strip()
    pins = json.loads((source / 'core_acceptance.json').read_text())
    members = {}
    with tarfile.open(archive, 'r:gz') as stream:
        for member in stream.getmembers():
            if not member.isfile():
                continue
            name = member.name.split('/',1)[1]
            if name in members:
                raise ValueError('duplicate candidate package member')
            members[name] = hashlib.sha256(stream.extractfile(member).read()).hexdigest()
    required = {'plugin.py','measure.py','capture.py','plugin.json','README.md','LICENSE',
                'inventory','ast/Cargo.lock','THIRD_PARTY_NOTICES.txt'}
    if set(members) != required:
        raise ValueError('candidate must be the complete nine-member release package')
    fixture = source / 'fixtures/thiserror-subset'
    inputs = {p.relative_to(fixture).as_posix():sha(p) for p in fixture.rglob('*') if p.is_file()}
    if set(inputs) != {'Cargo.toml','Cargo.lock','apps/server/src/lib.rs','tests/integration.rs'}:
        raise ValueError('unexpected candidate fixture inputs')
    candidate = {**expected, 'scope':'unpublished-release-candidate', 'source_commit':head,'source_tree':tree,
                 'archive':archive.name,'archive_sha256':sha(archive),'members':members,
                 'sbom':sbom.name,'sbom_sha256':sha(sbom)}
    manifest = {'schema':'rust-source-risk-local-candidate/v1','candidate':candidate,
                'core':pins['core'],'tools':pins['tools'],
                'fixture':{'target':'x86_64-unknown-linux-gnu','inputs':inputs,
                    'sources':{k:v for k,v in inputs.items() if k.startswith('apps/server/src/')},
                    'pipeline_files':{k:v for k,v in inputs.items() if k in ('Cargo.toml','Cargo.lock')}}}
    path=evidence/'candidate-manifest.json';path.write_text(json.dumps(manifest,indent=2)+'\n')
    (evidence/'candidate-manifest.sha256').write_text(sha(path)+'\n')
    unpack=evidence/'unpack';unpack.mkdir()
    with tarfile.open(archive,'r:gz') as stream:
        stream.extractall(unpack,filter='data')
    package=unpack/archive.name.removesuffix('.tar.gz')
    archived=json.loads((package/'plugin.json').read_text())
    if {k:archived[k] for k in expected}!=expected:
        raise ValueError('archived product identity mismatch')
    for label,args in [
        ('capture',[sys.executable,package/'capture.py','--repository',fixture,'--output',evidence/'capture',
                    '--target-dir',evidence/'capture-target','--input','Cargo.toml','--input','Cargo.lock',
                    '--input','apps/server/src','--input','tests','--source-root','apps/server/src','--test','integration']),
        ('signed-core',[sys.executable,source/'candidate_acceptance.py','--pins',path,'--pins-sha256',sha(path),
                        '--archive',archive,'--sbom',sbom,'--bundle',evidence/'capture/bundle.json',
                        '--core',core,'--presets-dir',source.parents[1]/'presets',
                        '--output',evidence/'acceptance/receipt.json'])]:
        with (evidence/(label+'.log')).open('w') as log:
            subprocess.run(list(map(str,args)),stdout=log,stderr=subprocess.STDOUT,check=True)
    return manifest
