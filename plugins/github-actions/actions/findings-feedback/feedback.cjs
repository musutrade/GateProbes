'use strict';
// No project code, artifact scripts, SARIF fixes, or report commands are executed.
const crypto = require('node:crypto');
const fs = require('node:fs');
const CHECK_NAME = 'Harness-Gate findings (advisory)';
const sha = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const requireThat = (condition, message) => { if (!condition) throw new Error(message); };
const isHex = (value, length) => typeof value === 'string' && new RegExp(`^[a-f0-9]{${length}}$`).test(value);
function safe(value, token = '') {
  let text = String(value).replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '');
  if (token) text = text.split(token).join('[REDACTED]');
  return text.replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g, '[REDACTED]')
    .replace(/\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+/gi, '[REDACTED]')
    .replace(/\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*(?:"[^"\n]*"|'[^'\n]*'|[^\s`,;}]+)/gi, '[REDACTED]')
    .replace(/\b(?:gh[pousr]_[a-zA-Z0-9_]+|github_pat_[a-zA-Z0-9_]+)\b/g, '[REDACTED]')
    .replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s/@]+:[^\s/@]+@[^\s]+/gi, '[REDACTED]').slice(0, 2000);
}
function annotations(report, token, limit) {
  const output = new Map();
  const rank = {notice: 0, warning: 1, failure: 2};
  for (const finding of report.findings) {
    requireThat(isHex(finding.id, 64), 'invalid finding identity');
    requireThat(['error', 'warning', 'note', 'none'].includes(finding.severity), 'unknown severity');
    requireThat(typeof finding.message === 'string' && Array.isArray(finding.locations) && finding.locations.length > 0, 'incomplete finding');
    const message = safe(finding.message, token);
    for (const location of finding.locations) {
      const {path, line, end_line: endLine} = location;
      requireThat(typeof path === 'string' && path.length > 0 && path.length <= 4096 && !/[\\:%?#\x00-\x1f\x7f]/.test(path) && path.split('/').every(p => p && p !== '.' && p !== '..'), 'unsafe annotation path');
      requireThat(Number.isSafeInteger(line) && Number.isSafeInteger(endLine) && line > 0 && endLine >= line, 'invalid annotation lines');
      if (finding.severity === 'none') continue;
      const key = JSON.stringify([finding.id, path, line, endLine]);
      const item = {path, start_line: line, end_line: endLine,
        annotation_level: {error: 'failure', warning: 'warning', note: 'notice'}[finding.severity],
        title: `Finding ${finding.id.slice(0, 12)}`, message};
      if (!output.has(key) || rank[item.annotation_level] > rank[output.get(key).annotation_level]) output.set(key, item);
      requireThat(output.size <= limit, 'annotation limit exceeded; nothing published; retain complete local report');
    }
  }
  return [...output.values()];
}
async function deliver(options) {
  const {bytes, expectedDigest, repository, expectedCommit, pr, publish, api, token = '', maxAnnotations = 1000} = options;
  requireThat(Buffer.byteLength(bytes) <= 16 * 1024 * 1024, 'feedback report exceeds 16 MiB');
  requireThat(isHex(expectedDigest, 64) && sha(bytes) === expectedDigest, 'feedback report digest mismatch');
  const report = JSON.parse(bytes);
  requireThat(report.schema_version === 'harness-findings/1' && report.context.repository === repository, 'feedback repository/schema mismatch');
  requireThat(isHex(expectedCommit, 40) && report.context.commit === expectedCommit && isHex(report.context.tree, 40), 'feedback commit/tree mismatch');
  requireThat(report.source_identity === `git-tree:${report.context.tree}` && isHex(report.report_sha256, 64) && typeof report.invocation_id === 'string' && report.invocation_id.length > 0, 'missing immutable Core binding');
  requireThat(['PASS', 'FAIL'].includes(report.core_status) && Array.isArray(report.findings) && report.findings.length <= 10000, 'invalid completed Core report');
  requireThat(Number.isInteger(maxAnnotations) && maxAnnotations >= 1 && maxAnnotations <= 1000, 'annotation limit must be 1..1000');
  requireThat(Number.isSafeInteger(pr) && pr > 0, 'explicit PR number required');
  const items = annotations(report, token, maxAnnotations);
  requireThat(items.length <= maxAnnotations, 'annotation limit exceeded; nothing published; retain complete local report');
  if (!publish) return {published: false, count: items.length, core_status: report.core_status};
  requireThat((isHex(options.expectedPrevious, 64) && report.previous_sha256 === options.expectedPrevious && !options.initializeHistory) || (options.initializeHistory === true && !options.expectedPrevious && report.previous_sha256 === null), 'trusted previous history pin required; initial enrollment must be explicit');
  const prefix = `/repos/${repository}`;
  async function currentHead() {
    const pull = await api('GET', `${prefix}/pulls/${pr}`);
    requireThat(pull.state === 'open' && pull.head.sha === expectedCommit && pull.head.repo.full_name === repository && pull.base.repo.full_name === repository, 'stale, closed or fork PR; feedback withheld');
  }
  await currentHead();
  const commit = await api('GET', `${prefix}/git/commits/${expectedCommit}`);
  requireThat(commit.tree.sha === report.context.tree, 'Core tree differs from PR commit');
  const tree = await api('GET', `${prefix}/git/trees/${report.context.tree}?recursive=1`);
  requireThat(tree.truncated === false && Array.isArray(tree.tree), 'incomplete repository tree');
  const paths = new Map(tree.tree.map(entry => [entry.path, entry]));
  const lineCounts = new Map();
  for (const item of items) {
    const entry = paths.get(item.path);
    requireThat(entry && entry.type === 'blob' && ['100644', '100755'].includes(entry.mode), 'annotation path is not a regular committed file');
    if (!lineCounts.has(item.path)) {
      requireThat(entry.size <= 1024 * 1024, 'annotation source exceeds 1 MiB');
      const blob = await api('GET', `${prefix}/git/blobs/${entry.sha}`);
      requireThat(blob.encoding === 'base64' && blob.size <= 1024 * 1024, 'unsupported annotation source');
      const data = Buffer.from(blob.content, 'base64');
      const gitSha = crypto.createHash('sha1').update(`blob ${data.length}\0`).update(data).digest('hex');
      requireThat(gitSha === entry.sha && !data.includes(0), 'source blob integrity/binary check failed');
      lineCounts.set(item.path, data.length === 0 ? 0 : data.toString('utf8').split('\n').length - (data[data.length - 1] === 10 ? 1 : 0));
    }
    requireThat(item.end_line <= lineCounts.get(item.path), 'annotation exceeds committed source lines');
  }
  const externalId = `harness-findings/1:${pr}:${expectedDigest}`;
  for (let page = 1; page <= 100; page++) {
    const data = await api('GET', `${prefix}/commits/${expectedCommit}/check-runs?filter=all&per_page=100&page=${page}`);
    requireThat(Array.isArray(data.check_runs), 'invalid check-run listing');
    const previous = data.check_runs.find(c => c.name === CHECK_NAME && c.external_id === externalId && c.head_sha === expectedCommit);
    if (previous) {
      requireThat(previous.status === 'completed' && previous.conclusion === 'neutral' && previous.output.annotations_count === items.length, 'previous feedback delivery incomplete; inspect retained check before retry');
      await currentHead();
      return {published: true, reused: true, count: items.length, check_id: previous.id, core_status: report.core_status};
    }
    if (data.check_runs.length < 100) break;
    requireThat(page < 100, 'check-run pagination limit exceeded');
  }
  await currentHead();
  const summary = `Core decision: ${report.core_status}. ${items.length} diagnostic annotations. Feedback is advisory; the original Core report and required gates retain authority.`;
  const created = await api('POST', `${prefix}/check-runs`, {name: CHECK_NAME, head_sha: expectedCommit, external_id: externalId, status: 'in_progress', output: {title: CHECK_NAME, summary}});
  try {
    for (let offset = 0; offset < items.length; offset += 50) {
      await currentHead();
      await api('PATCH', `${prefix}/check-runs/${created.id}`, {output: {title: CHECK_NAME, summary, annotations: items.slice(offset, offset + 50)}});
    }
    await currentHead();
    await api('PATCH', `${prefix}/check-runs/${created.id}`, {status: 'completed', conclusion: 'neutral', output: {title: CHECK_NAME, summary}});
  } catch (error) {
    // Partial delivery remains visibly incomplete. Never rewrite Core's result.
    await api('PATCH', `${prefix}/check-runs/${created.id}`, {status: 'completed', conclusion: 'cancelled', output: {title: CHECK_NAME, summary: 'Feedback delivery incomplete or stale; retained annotations are historical. Core decision is unchanged.'}}).catch(() => {});
    throw error;
  }
  return {published: true, reused: false, count: items.length, check_id: created.id, core_status: report.core_status};
}
async function main() {
  const token = process.env.FEEDBACK_TOKEN || '';
  const api = async (method, path, body) => {
    const response = await fetch(`https://api.github.com${path}`, {method, redirect: 'error', headers: {
      Accept: 'application/vnd.github+json', Authorization: `Bearer ${token}`, 'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json', 'User-Agent': 'harness-gate-findings/1'
    }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(30000)});
    if (!response.ok) throw new Error(`GitHub feedback request failed (${response.status}); Core decision unchanged`);
    const text = await response.text();
    requireThat(Buffer.byteLength(text) <= 16 * 1024 * 1024, 'GitHub response exceeds 16 MiB');
    return JSON.parse(text);
  };
  const path = process.env.FEEDBACK_REPORT;
  requireThat(fs.statSync(path).size <= 16 * 1024 * 1024, 'feedback report exceeds 16 MiB');
  const result = await deliver({bytes: fs.readFileSync(path), expectedDigest: process.env.FEEDBACK_DIGEST,
    repository: process.env.GITHUB_REPOSITORY, expectedCommit: process.env.FEEDBACK_COMMIT,
    pr: Number(process.env.FEEDBACK_PR), publish: process.env.FEEDBACK_PUBLISH === 'true', api, token,
    maxAnnotations: Number(process.env.FEEDBACK_LIMIT || 1000), expectedPrevious: process.env.FEEDBACK_PREVIOUS || '', initializeHistory: process.env.FEEDBACK_INITIALIZE === 'true'});
  console.log(JSON.stringify(result));
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `published=${result.published}\ncount=${result.count}\n`);
}
module.exports = {deliver, safe, sha};
if (require.main === module) main().catch(() => { console.error('Findings feedback failed; Core decision unchanged. Check report binding, limits, PR freshness and integration permissions.'); process.exitCode = 1; });
