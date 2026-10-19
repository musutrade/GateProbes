'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {deliver, safe, sha} = require('./feedback.cjs');
const commit = 'a'.repeat(40), tree = 'b'.repeat(40);
function setup(count = 1) {
  const text = Buffer.from('first\nsecond\n');
  const blobSha = crypto.createHash('sha1').update(`blob ${text.length}\0`).update(text).digest('hex');
  const report = {schema_version: 'harness-findings/1', context: {repository: 'owner/repo', commit, tree},
    source_identity: `git-tree:${tree}`, report_sha256: 'd'.repeat(64), invocation_id: 'run-1', core_status: 'FAIL',
    previous_sha256: 'e'.repeat(64),
    findings: Array.from({length: count}, (_, i) => ({id: sha(String(i)), severity: 'warning', message: 'password=secret-value', locations: [{path: 'src/a.rs', line: 1, end_line: 2}]}))};
  const calls = [];
  const state = {head: commit, pages: null, failPatch: false};
  const api = async (method, path, body) => {
    calls.push({method, path, body});
    if (path.endsWith('/pulls/1')) return {state: 'open', head: {sha: state.head, repo: {full_name: 'owner/repo'}}, base: {repo: {full_name: 'owner/repo'}}};
    if (path.includes('/git/commits/')) return {tree: {sha: tree}};
    if (path.includes('/git/trees/')) return {truncated: false, tree: [{path: 'src/a.rs', type: 'blob', mode: '100644', size: text.length, sha: blobSha}]};
    if (path.includes('/git/blobs/')) return {encoding: 'base64', size: text.length, content: text.toString('base64')};
    if (path.includes('/commits/') && path.includes('/check-runs?')) return {check_runs: state.pages ? state.pages(path) : []};
    if (method === 'POST') return {id: 9};
    if (method === 'PATCH') { if (state.failPatch && body.output.annotations) throw new Error('API failure'); return {}; }
    throw new Error(`unexpected API: ${method} ${path}`);
  };
  const options = () => {const bytes = Buffer.from(JSON.stringify(report)); return {bytes, expectedDigest: sha(bytes), repository: 'owner/repo', expectedCommit: commit, pr: 1, publish: true, api, expectedPrevious: 'e'.repeat(64)};};
  return {report, calls, state, options};
}
test('dry-run is local and gate failure remains gate failure', async () => {
  const f = setup(); const output = await deliver({...f.options(), publish: false});
  assert.equal(output.published, false); assert.equal(output.core_status, 'FAIL'); assert.equal(f.calls.length, 0);
});
test('publication binds commit, batches 50, deduplicates and redacts', async () => {
  const f = setup(101); f.report.findings.push(f.report.findings[0]);
  const result = await deliver(f.options());
  assert.equal(result.count, 101);
  assert.deepEqual(f.calls.filter(c => c.body?.output?.annotations).map(c => c.body.output.annotations.length), [50,50,1]);
  assert.equal(f.calls.find(c => c.method === 'POST').body.head_sha, commit);
  assert(!JSON.stringify(f.calls).includes('secret-value'));
  assert.equal(f.calls.at(-1).body.conclusion, 'neutral');
});
test('digest, repository, commit, traversal and line mismatches fail before writes', async () => {
  for (const mutate of [f => f.report.context.repository = 'other/repo', f => f.report.context.commit = 'c'.repeat(40), f => f.report.findings[0].locations[0].path = '../escape', f => f.report.findings[0].locations[0].end_line = 30, f => f.report.core_status = 'UNKNOWN']) {
    const f = setup(); mutate(f); await assert.rejects(deliver(f.options())); assert(!f.calls.some(c => c.method !== 'GET'));
  }
  const f = setup(); await assert.rejects(deliver({...f.options(), expectedDigest: '0'.repeat(64)})); assert.equal(f.calls.length, 0);
});
test('overflow rejects without writes', async () => {
  const f = setup(51); await assert.rejects(deliver({...f.options(), maxAnnotations: 50})); assert.equal(f.calls.length, 0);
});
test('old PR head and fork fail before writes', async () => {
  const f = setup(); f.state.head = 'c'.repeat(40); await assert.rejects(deliver(f.options())); assert(!f.calls.some(c => c.method !== 'GET'));
  const g = setup(); const options = g.options(); const api = options.api;
  options.api = async (...args) => {const result = await api(...args); if (args[1].endsWith('/pulls/1')) result.head.repo.full_name = 'fork/repo'; return result;};
  await assert.rejects(deliver(options)); assert(!g.calls.some(c => c.method !== 'GET'));
});
test('paginated identical completed delivery is reused', async () => {
  const f = setup(); const options = f.options();
  f.state.pages = path => /[?&]page=1(?:&|$)/.test(path) ? Array.from({length: 100}, (_, id) => ({id})) : [{id: 7, name: 'Harness-Gate findings (advisory)', external_id: `harness-findings/1:1:${options.expectedDigest}`, head_sha: commit, status: 'completed', conclusion: 'neutral', output: {annotations_count: 1}}];
  const result = await deliver(options); assert(result.reused); assert.equal(result.check_id, 7); assert(!f.calls.some(c => c.method !== 'GET'));
});
test('partial publication cancels delivery without claiming Core success', async () => {
  const f = setup(51); f.state.failPatch = true;
  await assert.rejects(deliver(f.options())); assert.equal(f.calls.at(-1).body.conclusion, 'cancelled'); assert.equal(f.report.core_status, 'FAIL');
});
test('PR changes during delivery cancel historical feedback', async () => {
  const f = setup(51); const options = f.options(); const api = options.api;
  options.api = async (...args) => {const result = await api(...args); if (args[0] === 'PATCH' && args[2]?.output?.annotations) f.state.head = 'c'.repeat(40); return result;};
  await assert.rejects(deliver(options)); assert.equal(f.calls.at(-1).body.conclusion, 'cancelled');
  assert.equal(f.calls.filter(c => c.body?.output?.annotations).length, 1);
});
test('redaction covers credentials and active publishing token', () => {
  const text = safe('Authorization: Bearer credential\npassword="another value"\nghp_opaque123\nEXACT_TOKEN', 'EXACT_TOKEN');
  for (const secret of ['credential', 'another value', 'ghp_opaque123', 'EXACT_TOKEN']) assert(!text.includes(secret));
});
test('history pin cannot silently be replaced with a fresh baseline', async () => {
  const f = setup(); f.report.previous_sha256 = null;
  await assert.rejects(deliver(f.options())); assert.equal(f.calls.length, 0);
  await deliver({...f.options(), expectedPrevious: '', initializeHistory: true});
});
test('duplicate identity uses the strongest observed annotation severity', async () => {
  const f = setup(); f.report.findings.push({...f.report.findings[0], severity: 'error'});
  const result = await deliver(f.options()); assert.equal(result.count, 1);
  assert.equal(f.calls.find(c => c.body?.output?.annotations).body.output.annotations[0].annotation_level, 'failure');
});
