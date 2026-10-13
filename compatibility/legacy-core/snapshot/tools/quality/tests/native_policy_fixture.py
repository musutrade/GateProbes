"""Project-owned policy inputs for real native/Core acceptance."""
import copy
import json
from pathlib import Path
import shutil

import rust_native_policy as policy

QUALITY = Path(__file__).resolve().parents[1]
CRAP_RULE = {'id': 'rust.crap', 'scope': {'kind': 'component', 'component': 'rust'},
             'metric': 'risk.crap', 'operator': 'le',
             'limit': {'type': 'rational', 'numerator': 30, 'denominator': 1},
             'required': True, 'on_violation': 'fail',
             'ratchet': {'deny_regression': True, 'allow_legacy_debt': True},
             'remediation_classes': ['review_native_production_evidence']}


def prepare(root, report, capture, context, project_id='native-fixture', hotspots=(), component='rust'):
    config = root / '.harness-gate'
    config.mkdir(parents=True)
    shutil.copyfile(QUALITY.parent / 'harness-gate/fixtures/preset-compat/rust-api.flow.toml', config / 'flow.toml')
    shutil.copyfile(QUALITY.parent / 'harness-gate/presets/empty.audit.toml', config / 'audit.toml')
    shutil.copyfile(QUALITY.parent / 'harness-gate/presets/default.secrets.toml', config / 'secrets.toml')
    shutil.copyfile(capture / 'fixture.rs', root / 'fixture.rs')
    sources = root / 'target/projection-sources'
    sources.mkdir(parents=True)
    projected = policy.project(report, root / 'target/projection', sources, context, project_id, hotspots, component)
    series = projected['evidence'][0]['series']['id']
    rule = copy.deepcopy(CRAP_RULE)
    rule['scope']['component'] = component
    (config / 'policy.json').write_text(json.dumps({'schema': 'harness-policy/v1', 'rules': [rule]}), encoding='utf-8')
    (config / 'quality.toml').write_text(f'''version = 1
[project]
id = {json.dumps(project_id)}
name = "rust-api"
[components.{component}]
flow_components = ["app"]
source_roots = ["."]
artifact_root = "target/evidence"
[collectors.native]
protocol = "harness-collector-request/v1"
request = ".harness-gate/native-request.json"
produces = [{{ target = {{ kind = "component", id = "{component}" }}, capability = "risk.crap", series = "{series}" }}]
[policies.crap]
policy_file = ".harness-gate/policy.json"
rule = "rust.crap"
expectation = {{ target = {{ kind = "component", id = "{component}" }}, capability = "risk.crap", series = "{series}" }}
[profiles.full]
collectors = ["native"]
policies = ["crap"]
[profiles.hook]
assurance = "partial"
collectors = []
policies = []
[baseline]
required = true
provider = {{ kind = "git", reference = "origin/main", merge_base = true }}
[reporting]
output = "target/quality"
formats = ["human", "json"]
''', encoding='utf-8')
    return {'repository_root': root, 'policy_binding': 'crap'}


def set_limit(root, numerator, denominator=1, **changes):
    path = root / '.harness-gate/policy.json'
    document = json.loads(path.read_text(encoding='utf-8'))
    document['rules'][0].update(limit={'type': 'rational', 'numerator': numerator, 'denominator': denominator}, **changes)
    path.write_text(json.dumps(document), encoding='utf-8')
