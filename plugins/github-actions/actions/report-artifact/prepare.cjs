'use strict';
// Transport only: no project commands, HTML execution, policy or GitHub API calls.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const requireThat = (ok, message) => { if (!ok) throw new Error(message); };
const hex = (v, lengths) => typeof v === 'string' && lengths.includes(v.length) && /^[0-9a-f]+$/.test(v);
function regular(file, limit) {
  file = path.resolve(file);
  for (let p = file; ; p = path.dirname(p)) {
    requireThat(!fs.lstatSync(p).isSymbolicLink(), 'symbolic link in export path');
    if (path.dirname(p) === p) break;
  }
  const stat = fs.statSync(file);
  requireThat(stat.isFile() && stat.size <= limit, 'export file is not bounded and regular');
  const fd = fs.openSync(file, 'r');
  try {
    const bytes = Buffer.alloc(limit + 1);
    let size = 0, count;
    do { count = fs.readSync(fd, bytes, size, bytes.length - size, null); size += count; }
    while (count && size < bytes.length);
    requireThat(size <= limit, 'export file grew beyond limit');
    return bytes.subarray(0, size);
  } finally { fs.closeSync(fd); }
}
function validate(options) {
  const {directory, digest, commit, upload, retention} = options;
  requireThat(['true', 'false'].includes(upload), 'upload must explicitly be true or false');
  requireThat(/^(?:[1-9]|[12][0-9]|30)$/.test(retention), 'retention must be 1 to 30 days');
  requireThat(hex(digest, [64]) && hex(commit, [40, 64]), 'explicit digest and commit required');
  const provenance = regular(path.join(directory, 'provenance.json'), 65536);
  requireThat(sha(provenance) === digest, 'provenance pin mismatch');
  const p = JSON.parse(provenance.toString('utf8'));
  // This is the exact serde_json pretty export format, with ASCII scalar fields.
  // Re-serialization also rejects duplicate JSON keys and invalid UTF-8 replacements.
  requireThat(provenance.toString('utf8') === JSON.stringify(p, null, 2), 'noncanonical export provenance');
  requireThat(Object.keys(p).sort().join(',') === 'commit,core_status,evidence_complete,html,index_sha256,invocation_id,machine_sha256,manifest_sha256,schema', 'unknown export fields');
  requireThat(p.schema === 'harness-html-export/v1' && p.commit === commit && p.evidence_complete === true, 'export identity or completeness mismatch');
  requireThat(['PASS', 'FAIL'].includes(p.core_status), 'unknown Core status');
  requireThat(typeof p.invocation_id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(p.invocation_id), 'invalid invocation identity');
  for (const field of ['machine_sha256', 'manifest_sha256', 'index_sha256']) requireThat(hex(p[field], [64]), 'invalid source digest');
  requireThat(p.html && Object.keys(p.html).sort().join(',') === 'path,sha256,size_bytes' && p.html.path === 'test_result.html' && hex(p.html.sha256, [64]), 'invalid HTML identity');
  const html = regular(path.join(directory, 'test_result.html'), 2 * 1024 * 1024);
  requireThat(Number.isSafeInteger(p.html.size_bytes) && html.length === p.html.size_bytes && sha(html) === p.html.sha256, 'HTML digest or size mismatch');
  return {html, provenance, status: p.core_status};
}
function prepare(options) {
  const verified = validate(options);
  if (options.upload === 'false') return {validated: true, status: verified.status};
  requireThat(/^[1-9][0-9]*$/.test(options.runId) && /^[1-9][0-9]*$/.test(options.attempt), 'invalid Actions run identity');
  const temp = fs.realpathSync(options.temp);
  requireThat(!/[\r\n*?\[\]{}!]/.test(temp), 'unsafe upload staging path');
  const directory = fs.mkdtempSync(path.join(temp, 'gatehouse-html-'));
  // Write the verified in-memory bytes; never upload an input directory or glob.
  for (const [name, bytes] of [['test_result.html', verified.html], ['provenance.json', verified.provenance]]) {
    fs.writeFileSync(path.join(directory, name), bytes, {flag: 'wx', mode: 0o600});
  }
  return {validated: true, status: verified.status, directory,
    name: `gatehouse-html-${options.commit}-${options.runId}-${options.attempt}`};
}
function main(env = process.env) {
  const result = prepare({directory: env.REPORT_DIRECTORY, digest: env.REPORT_PROVENANCE_SHA256,
    commit: env.REPORT_COMMIT, upload: env.REPORT_UPLOAD, retention: env.REPORT_RETENTION_DAYS,
    temp: env.RUNNER_TEMP, runId: env.GITHUB_RUN_ID, attempt: env.GITHUB_RUN_ATTEMPT});
  if (result.directory) {
    requireThat(env.GITHUB_OUTPUT, 'missing Actions output file');
    fs.appendFileSync(env.GITHUB_OUTPUT, `directory=${result.directory}\nname=${result.name}\n`);
  }
  console.log(`HTML export validated; recorded Core status ${result.status}; upload ${result.directory ? 'authorized' : 'disabled'}.`);
}
module.exports = {sha, validate, prepare};
if (require.main === module) {
  try { main(); } catch { console.error('HTML artifact validation failed; nothing authorized for upload. Check trusted pins, commit, export files and integration inputs.'); process.exitCode = 1; }
}
