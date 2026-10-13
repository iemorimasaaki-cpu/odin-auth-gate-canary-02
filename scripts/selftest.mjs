// Live self-test against the real GitHub API in an isolated ref namespace (refs/odin-test/<run_id>).
import { makeGitHub, precheck, claim, refNames } from './gate.mjs';

const env = { ...process.env };
const BASE = '98d001da379da6627e0254b1fba2782f3d7c8693';
const prefix = env.GATE_REF_PREFIX;
if (!/^refs\/odin-test\/\d+$/.test(prefix || '')) { console.error('selftest requires GATE_REF_PREFIX=refs/odin-test/<run_id>'); process.exit(2); }
const api = makeGitHub({ token: env.GITHUB_TOKEN, repo: env.GITHUB_REPOSITORY });
const results = [];

async function input(pkg, o = {}) {
  const { sha } = await api.getAuthz(pkg);
  return { package_id: pkg, op: 'noop-implement', round: '0', target_sha: BASE, authz_sha: sha || '0'.repeat(40), paths: 'sandbox/a/x.txt', idem_key: 'key-' + pkg.toLowerCase() + '-0001', ...o };
}
async function check(id, label, fn, expect) {
  const r = await fn();
  const got = r.code;
  const ok = got === expect;
  results.push({ id, label, expect, got, ok });
  console.log((ok ? 'PASS ' : 'FAIL ') + id + ' ' + label + ' -> ' + got + (ok ? '' : ' (expected ' + expect + ')'));
  return r;
}
const noRefs = async (pkg, key) => !(await api.refExists(refNames(prefix, pkg, 0, key).idem));
const rec = (id, label, ok) => { results.push({ id, label, expect: true, got: ok, ok }); console.log((ok ? 'PASS ' : 'FAIL ') + id + ' ' + label); };

// 1. unapproved
let i = await input('SELF-NONE');
await check('1a', 'no authz record', () => precheck(api, i, env), 'NO_AUTHZ');
await check('1a2', 'no authz record (claim)', () => claim(api, i, env), 'NO_AUTHZ');
rec('1a3', 'no refs created for unapproved', await noRefs('SELF-NONE', i.idem_key));
i = await input('SELF-REVOKED');
await check('1b', 'revoked record', () => precheck(api, i, env), 'REVOKED');
// 2. SHA mismatch
i = await input('SELF-OK', { target_sha: 'a'.repeat(40) });
await check('2a', 'input sha != baseline', () => precheck(api, i, env), 'SHA_MISMATCH');
i = await input('SELF-HEAD');
await check('2b', 'input==baseline but real head differs', () => precheck(api, i, env), 'HEAD_MISMATCH');
await check('2b2', 'same (claim)', () => claim(api, i, env), 'HEAD_MISMATCH');
rec('2c', 'no refs created on sha mismatch', await noRefs('SELF-HEAD', i.idem_key));
// 3. expired
i = await input('SELF-EXPIRED');
await check('3a', 'expired (precheck)', () => precheck(api, i, env), 'EXPIRED');
await check('3b', 'expired (claim)', () => claim(api, i, env), 'EXPIRED');
// 4. retry exhaustion / gap
const r = (n, k) => input('SELF-RETRY', { op: n === 0 ? 'noop-implement' : 'noop-remediate', round: String(n), idem_key: 'key-retry-' + k });
await check('4a', 'r0 claim', async () => claim(api, await r(0, 'a0'), env), 'CLAIMED');
await check('4b', 'r1 claim', async () => claim(api, await r(1, 'a1'), env), 'CLAIMED');
await check('4c', 'r2 claim', async () => claim(api, await r(2, 'a2'), env), 'CLAIMED');
await check('4d', 'r3 exhausted', async () => claim(api, await r(3, 'a3'), env), 'RETRY_EXHAUSTED');
await check('4e', 'r3 exhausted (precheck)', async () => precheck(api, await r(3, 'a3'), env), 'RETRY_EXHAUSTED');
rec('4f', 'no r3 ref', !(await api.refExists(refNames(prefix, 'SELF-RETRY', 3, 'x').claim(3))));
await check('4g', 'round gap (r0 done, jump to r2)', async () => {
  await claim(api, await input('SELF-GAP', { idem_key: 'key-gap-a0' }), env);
  return claim(api, await input('SELF-GAP', { op: 'noop-remediate', round: '2', idem_key: 'key-gap-a2' }), env);
}, 'ROUND_GAP');
// 5. duplicate invocation
const d = () => input('SELF-DUP', { idem_key: 'key-dup-same-1' });
await check('5a', 'first invocation', async () => claim(api, await d(), env), 'CLAIMED');
await check('5b', 'same key again (claim)', async () => claim(api, await d(), env), 'DUPLICATE');
await check('5c', 'same key again (precheck)', async () => precheck(api, await d(), env), 'DUPLICATE');
await check('5d', 'new key same round', async () => claim(api, await input('SELF-DUP', { idem_key: 'key-dup-other-2' }), env), 'ROUND_TAKEN');
// 7. stale authz
i = await input('SELF-OK', { authz_sha: 'b'.repeat(40) });
await check('7a', 'stale authz blob sha', () => precheck(api, i, env), 'STALE_AUTHZ');
// 8. scope expansion
await check('8a', 'op not allowed for package', async () => precheck(api, await input('SELF-OPS', { op: 'noop-remediate', round: '1' }), env), 'OP_NOT_ALLOWED');
await check('8b', 'unknown op', async () => precheck(api, await input('SELF-OK', { op: 'noop-delete' }), env), 'OP_NOT_ALLOWED');
await check('8c', 'path outside scope', async () => precheck(api, await input('SELF-SCOPE', { paths: 'sandbox/a/ok.txt,.github/workflows/gate.yml' }), env), 'SCOPE');
await check('8d', 'path traversal', async () => precheck(api, await input('SELF-SCOPE', { paths: 'sandbox/a/../../.github/x' }), env), 'SCOPE');
// 9. BLOCK / WAITING_OWNER
await check('9a', 'authz status BLOCK', async () => precheck(api, await input('SELF-BLOCK'), env), 'BLOCKED');
await check('9b', 'authz status WAITING_OWNER', async () => precheck(api, await input('SELF-WAIT'), env), 'WAITING_OWNER');
const names = refNames(prefix, 'SELF-REFBLOCK', 0, 'x');
await check('9c', 'before block ref: allowed', async () => precheck(api, await input('SELF-REFBLOCK'), env), 'ALLOW_PENDING_APPROVAL');
rec('9d', 'block ref created', (await api.createRef(names.block, BASE)) === 'created');
await check('9e', 'block ref present: denied', async () => claim(api, await input('SELF-REFBLOCK'), env), 'BLOCKED');
// extra: dispatch from non-main ref
await check('X1', 'dispatch ref not main', async () => precheck(api, await input('SELF-OK'), { ...env, GITHUB_REF: 'refs/heads/sandbox-target' }), 'BAD_DISPATCH_REF');
await check('X2', 'malformed input', async () => precheck(api, await input('SELF-OK', { idem_key: 'BAD KEY' }), env), 'BAD_INPUT:idem_key');

const fails = results.filter((x) => !x.ok);
console.log('SELFTEST-SUMMARY ' + JSON.stringify({ total: results.length, failed: fails.length, prefix }));
process.exit(fails.length ? 1 : 0);
