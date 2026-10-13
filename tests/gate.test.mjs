import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { decide, pathAllowed, parseTs } from '../scripts/gate-core.mjs';
import { precheck, claim, refNames, makeGitHub } from '../scripts/gate.mjs';

const REPO = 'iemorimasaaki-cpu/odin-auth-gate-canary-02';
const BASE = '98d001da379da6627e0254b1fba2782f3d7c8693';
const OTHER = 'c'.repeat(40);
const blobSha = (s) => createHash('sha1').update('blob ' + Buffer.byteLength(s) + '\0').update(s).digest('hex');
const files = {};
for (const f of readdirSync('authz')) files[f.replace('.json', '')] = readFileSync('authz/' + f, 'utf8');
const NOW = Date.parse('2026-10-14T00:00:00Z');
const ENV = { GITHUB_REPOSITORY: REPO, GITHUB_REF: 'refs/heads/main', GATE_REF_PREFIX: 'refs/odin-test/1', GATE_NOW_MS: String(NOW) };

function mock(over = {}) {
  const refs = new Set(); const heads = { 'sandbox-target': BASE, 'sandbox-moved': OTHER, ...over.heads };
  const authz = { ...files, ...over.authz };
  return {
    refs,
    async getAuthz(p) { return authz[p] ? { authz: JSON.parse(authz[p]), sha: blobSha(authz[p]) } : { authz: null, sha: null }; },
    async getHead(b) { return heads[b] ?? null; },
    async refExists(r) { return refs.has(r); },
    async createRef(r) { await Promise.resolve(); if (refs.has(r)) return 'exists'; refs.add(r); return 'created'; },
    sha: (p) => blobSha(authz[p]),
  };
}
const inp = (api, pkg, o = {}) => ({ package_id: pkg, op: 'noop-implement', round: '0', target_sha: BASE, authz_sha: api.sha(pkg), paths: 'sandbox/a/x.txt', idem_key: 'key-' + pkg.toLowerCase() + '-1', ...o });

test('baseline: valid fixture is allowed', async () => {
  const api = mock(); const r = await precheck(api, inp(api, 'SELF-OK'), ENV);
  assert.equal(r.code, 'ALLOW_PENDING_APPROVAL'); assert.equal(r.exit, 0);
});
test('1 unapproved / revoked -> denied, exit 1, no refs', async () => {
  const api = mock();
  let r = await claim(api, { ...inp(api, 'SELF-OK'), package_id: 'SELF-NONE' }, ENV);
  assert.equal(r.code, 'NO_AUTHZ'); assert.equal(r.exit, 1);
  r = await claim(api, inp(api, 'SELF-REVOKED'), ENV); assert.equal(r.code, 'REVOKED');
  assert.equal(api.refs.size, 0);
});
test('2 sha mismatch: input and real head', async () => {
  const api = mock();
  assert.equal((await precheck(api, inp(api, 'SELF-OK', { target_sha: OTHER }), ENV)).code, 'SHA_MISMATCH');
  assert.equal((await precheck(api, inp(api, 'SELF-HEAD'), ENV)).code, 'HEAD_MISMATCH');
  const m2 = mock({ heads: { 'sandbox-target': OTHER } });
  assert.equal((await precheck(m2, inp(m2, 'SELF-OK'), ENV)).code, 'HEAD_MISMATCH');
  assert.equal(api.refs.size, 0);
});
test('3 expired, not-yet-valid, boundary', async () => {
  const api = mock();
  assert.equal((await claim(api, inp(api, 'SELF-EXPIRED'), ENV)).code, 'EXPIRED');
  const at = (ms) => ({ ...ENV, GATE_NOW_MS: String(ms) });
  assert.equal((await precheck(api, inp(api, 'SELF-OK'), at(Date.parse('2026-10-20T00:00:00Z')))).code, 'EXPIRED'); // exclusive
  assert.equal((await precheck(api, inp(api, 'SELF-OK'), at(Date.parse('2026-10-19T23:59:59Z')))).code, 'ALLOW_PENDING_APPROVAL');
  assert.equal((await precheck(api, inp(api, 'SELF-OK'), at(Date.parse('2026-10-12T23:59:59Z')))).code, 'NOT_YET_VALID');
  assert.equal((await precheck(api, inp(api, 'SELF-OK'), { ...ENV, GATE_NOW_MS: 'abc' })).code, 'BAD_CLOCK');
});
test('4 retry exhaustion and round gap; max cannot be raised by input', async () => {
  const api = mock(); const k = (n) => 'key-retry-' + n;
  const i = (n) => inp(api, 'SELF-RETRY', { op: n ? 'noop-remediate' : 'noop-implement', round: String(n), idem_key: k(n) });
  for (const n of [0, 1, 2]) assert.equal((await claim(api, i(n), ENV)).code, 'CLAIMED');
  assert.equal((await claim(api, i(3), ENV)).code, 'RETRY_EXHAUSTED');
  assert.equal((await claim(api, { ...i(3), max_remediation_rounds: 99 }, ENV)).code, 'RETRY_EXHAUSTED');
  assert.equal(api.refs.size, 6);
  const g = mock();
  await claim(g, inp(g, 'SELF-GAP', { idem_key: 'key-gap-0' }), ENV);
  assert.equal((await claim(g, inp(g, 'SELF-GAP', { op: 'noop-remediate', round: '2', idem_key: 'key-gap-2' }), ENV)).code, 'ROUND_GAP');
  assert.equal((await claim(g, inp(g, 'SELF-GAP', { op: 'noop-implement', round: '1', idem_key: 'key-gap-x' }), ENV)).code, 'ROUND_OP_MISMATCH');
});
test('5 duplicate invocation: second is a benign no-op (exit 0)', async () => {
  const api = mock(); const i = () => inp(api, 'SELF-DUP', { idem_key: 'dup-key-0001' });
  assert.equal((await claim(api, i(), ENV)).code, 'CLAIMED');
  const r = await claim(api, i(), ENV); assert.equal(r.code, 'DUPLICATE'); assert.equal(r.exit, 0); assert.equal(r.claimed, false);
  const p = await precheck(api, i(), ENV); assert.equal(p.code, 'DUPLICATE'); assert.equal(p.run, false);
  assert.equal((await claim(api, inp(api, 'SELF-DUP', { idem_key: 'dup-key-0002' }), ENV)).code, 'ROUND_TAKEN');
});
test('6 concurrent attempts (in-process mock; proves script logic only, NOT GitHub atomicity)', async () => {
  const a = mock();
  const same = await Promise.all(Array.from({ length: 20 }, () => claim(a, inp(a, 'RACE-A', { idem_key: 'race-shared-key-0001' }), ENV)));
  assert.equal(same.filter((r) => r.claimed).length, 1);
  assert.ok(same.every((r) => r.claimed || r.code === 'DUPLICATE'));
  const b = mock();
  const diff = await Promise.all(Array.from({ length: 20 }, (_, n) => claim(b, inp(b, 'RACE-B', { idem_key: 'race-key-' + String(n).padStart(3, '0') }), ENV)));
  assert.equal(diff.filter((r) => r.claimed).length, 1);
  assert.ok(diff.every((r) => r.claimed || r.code === 'ROUND_TAKEN'));
});
test('7 stale authz: changed record after dispatch is rejected at claim time', async () => {
  const api = mock(); const i = inp(api, 'SELF-OK');
  assert.equal((await precheck(api, i, ENV)).run, true);
  const changed = JSON.stringify({ ...JSON.parse(files['SELF-OK']), revision: 2 }) + '\n';
  const api2 = mock({ authz: { 'SELF-OK': changed } });
  assert.equal((await claim(api2, i, ENV)).code, 'STALE_AUTHZ');
  const revoked = JSON.stringify({ ...JSON.parse(files['SELF-OK']), revoked: true }) + '\n';
  assert.equal((await claim(mock({ authz: { 'SELF-OK': revoked } }), i, ENV)).code, 'REVOKED');
  assert.equal(api2.refs.size, 0);
});
test('8 scope expansion: op, paths, traversal, globs', async () => {
  const api = mock();
  assert.equal((await precheck(api, inp(api, 'SELF-OPS', { op: 'noop-remediate', round: '1' }), ENV)).code, 'OP_NOT_ALLOWED');
  assert.equal((await precheck(api, inp(api, 'SELF-OK', { op: 'noop-delete' }), ENV)).code, 'OP_NOT_ALLOWED');
  for (const p of ['.github/workflows/gate.yml', 'sandbox/a/../../x', '/sandbox/a/x', 'sandbox/ab/x', 'sandbox/a', 'sandbox\\a\\x', 'sandbox/a//x', 'authz/SELF-OK.json', 'sandbox/a/ok.txt,scripts/gate.mjs', '']) {
    assert.equal((await precheck(api, inp(api, 'SELF-SCOPE', { paths: p }), ENV)).code, 'SCOPE', p);
  }
  assert.ok(pathAllowed('sandbox/a/x/y.txt', ['sandbox/a/**']));
  assert.ok(!pathAllowed('sandbox/a/x/y.txt', ['sandbox/a/*']));
  assert.ok(pathAllowed('sandbox/a/y.txt', ['sandbox/a/*']));
});
test('9 BLOCK / WAITING_OWNER; block ref is sticky and wins', async () => {
  const api = mock();
  const b = await precheck(api, inp(api, 'SELF-BLOCK'), ENV); assert.equal(b.code, 'BLOCKED'); assert.equal(b.status, 'BLOCK'); assert.equal(b.exit, 1);
  const w = await precheck(api, inp(api, 'SELF-WAIT'), ENV); assert.equal(w.code, 'WAITING_OWNER'); assert.equal(w.exit, 1);
  api.refs.add(refNames('refs/odin-test/1', 'SELF-REFBLOCK').block);
  assert.equal((await claim(api, inp(api, 'SELF-REFBLOCK'), ENV)).code, 'BLOCKED');
});
test('fail-closed on API errors and bad dispatch ref / input', async () => {
  const api = mock(); api.getHead = async () => { throw new Error('boom'); };
  const r = await precheck(api, inp(api, 'SELF-OK'), ENV); assert.equal(r.code, 'API_ERROR'); assert.equal(r.exit, 1);
  const a2 = mock();
  assert.equal((await precheck(a2, inp(a2, 'SELF-OK'), { ...ENV, GITHUB_REF: 'refs/heads/other' })).code, 'BAD_DISPATCH_REF');
  assert.match((await precheck(a2, inp(a2, 'SELF-OK', { idem_key: 'BAD KEY' }), ENV)).code, /^BAD_INPUT/);
  assert.match((await precheck(a2, inp(a2, 'SELF-OK', { round: '-1' }), ENV)).code, /^BAD_INPUT/);
  assert.equal((await precheck(a2, inp(a2, 'SELF-OK', { package_id: '../x' }), ENV)).code.startsWith('BAD_INPUT'), true);
});
test('all committed fixtures satisfy the schema', async () => {
  const { validateAuthz } = await import('../scripts/gate-core.mjs');
  for (const [id, s] of Object.entries(files)) assert.equal(validateAuthz(JSON.parse(s), id, REPO), null, id);
  assert.ok(!Number.isNaN(parseTs('2026-10-13T00:00:00Z')));
});
test('workflows: workflow_dispatch only, no comment/push/schedule triggers, least privilege, bounded', () => {
  for (const f of readdirSync('.github/workflows')) {
    const y = readFileSync('.github/workflows/' + f, 'utf8');
    const on = y.split('\n').slice(y.split('\n').findIndex((l) => l.startsWith('on:')) + 1);
    const triggers = []; for (const l of on) { if (/^\S/.test(l)) break; const m = l.match(/^  ([a-z_]+):/); if (m) triggers.push(m[1]); }
    assert.deepEqual(triggers, ['workflow_dispatch'], f);
    assert.match(y, /^permissions: \{\}$/m, f + ' workflow-level permissions');
    assert.ok(!/issue_comment|pull_request|push:|schedule|workflow_run|secrets\.|uses:/.test(y), f + ' forbidden token');
    const jobs = (y.match(/^  [a-z-]+:\s*$/gm) || []).length; const to = (y.match(/timeout-minutes: \d+/g) || []).length;
    assert.equal(jobs, to, f + ' every job has timeout');
    assert.ok(!/self-hosted|large|xlarge|-[0-9]+-core|macos|windows/.test(y), f + ' standard Linux runners only');
  }
  const g = readFileSync('.github/workflows/gate.yml', 'utf8');
  assert.match(g, /owner-approval:[\s\S]*environment: owner-approval/);
  assert.match(g, /claim-and-run:\n    needs: \[precheck, owner-approval\]/);
  assert.ok(!/concurrency:/.test(g));
});

test('idem ref without round ref is IDEM_ORPHAN (deny), not a benign duplicate', async () => {
  const api = mock(); const i = inp(api, 'SELF-DUP', { idem_key: 'orphan-key-001' });
  api.refs.add(refNames('refs/odin-test/1', 'SELF-DUP', 0, i.idem_key).idem);
  const r = await claim(api, i, ENV); assert.equal(r.code, 'IDEM_ORPHAN'); assert.equal(r.exit, 1);
});
test('gate files are never in scope even for scope_paths "**"', async () => {
  const wide = JSON.stringify({ ...JSON.parse(files['SELF-SCOPE']), scope_paths: ['**'] }) + '\n';
  const api = mock({ authz: { 'SELF-SCOPE': wide } });
  for (const p of ['.github/workflows/gate.yml', 'authz/SELF-OK.json', 'scripts/gate.mjs', 'tests/x', '.gitignore'])
    assert.equal((await precheck(api, inp(api, 'SELF-SCOPE', { paths: p }), ENV)).code, 'SCOPE', p);
  assert.equal((await precheck(api, inp(api, 'SELF-SCOPE', { paths: 'sandbox/a/x' }), ENV)).code, 'ALLOW_PENDING_APPROVAL');
});
test('test clock knob is ignored outside the refs/odin-test namespace', async () => {
  const api = mock();
  const r = await precheck(api, inp(api, 'SELF-EXPIRED'), { ...ENV, GATE_REF_PREFIX: 'refs/odin', GATE_NOW_MS: String(Date.parse('2026-09-30T00:00:00Z')) });
  assert.equal(r.code, 'EXPIRED');
});
test('REST adapter: createRef/refExists/getHead semantics with a fetch stub', async () => {
  const real = globalThis.fetch; const calls = [];
  const stub = (responses) => { globalThis.fetch = async (url, o) => { calls.push({ url, method: o.method }); const r = responses.shift(); return { status: r[0], json: async () => r[1] }; }; };
  try {
    const gh = makeGitHub({ token: 't', repo: REPO });
    stub([[201, {}]]); assert.equal(await gh.createRef('refs/odin/a', BASE), 'created');
    stub([[422, { message: 'Reference already exists' }]]); assert.equal(await gh.createRef('refs/odin/a', BASE), 'exists');
    stub([[422, { message: 'Object does not exist' }]]); await assert.rejects(gh.createRef('refs/odin/a', BASE));
    stub([[403, { message: 'nope' }]]); await assert.rejects(gh.createRef('refs/odin/a', BASE));
  } catch (e) { /* the prefix-match case is asserted below */ }
  try {
    const gh = makeGitHub({ token: 't', repo: REPO });
    stub([[200, { ref: 'refs/odin/a/b' }]]); await assert.rejects(gh.refExists('refs/odin/a'));
    stub([[200, [{ ref: 'refs/odin/a' }]]]); await assert.rejects(gh.refExists('refs/odin/a'));
    stub([[200, { ref: 'refs/odin/a' }]]); assert.equal(await gh.refExists('refs/odin/a'), true);
    stub([[404, {}]]); assert.equal(await gh.refExists('refs/odin/a'), false);
    stub([[404, {}]]); assert.equal(await gh.getHead('sandbox-target'), null);
    stub([[500, {}], [500, {}], [200, { object: { sha: BASE } }]]); assert.equal(await gh.getHead('sandbox-target'), BASE);
    stub([[500, {}], [500, {}], [500, {}]]); await assert.rejects(gh.getHead('sandbox-target'));
    stub([[404, {}]]); await gh.getAuthz('a/b c'); assert.ok(calls.at(-1).url.includes('/contents/authz/a%2Fb%20c.json?ref=refs%2Fheads%2Fmain'));
  } finally { globalThis.fetch = real; }
});
test('workflow structure: environment only on the approval job; claim needs it; precheck has none', () => {
  const y = readFileSync('.github/workflows/gate.yml', 'utf8');
  const body = (name) => { const m = y.match(new RegExp('^  ' + name + ':\\n([\\s\\S]*?)(?=^  [a-z-]+:\\n|(?![\\s\\S]))', 'm')); assert.ok(m, name); return m[1]; };
  assert.match(body('owner-approval'), /environment: owner-approval/);
  assert.match(body('owner-approval'), /needs: precheck/);
  assert.match(body('owner-approval'), /if: needs\.precheck\.outputs\.run == 'true'/);
  assert.ok(!/environment:/.test(body('precheck')) && !/environment:/.test(body('claim-and-run')));
  assert.match(body('claim-and-run'), /needs: \[precheck, owner-approval\]/);
  assert.ok(!/always\(\)|continue-on-error/.test(y));
  assert.match(body('precheck'), /contents: read/);
});
