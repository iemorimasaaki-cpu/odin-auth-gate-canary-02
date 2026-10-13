// Synchronized concurrent claim attempts. Each matrix job fires N attempts at the same instant.
import { makeGitHub, claim } from './gate.mjs';
const env = process.env;
const BASE = '98d001da379da6627e0254b1fba2782f3d7c8693';
const scenario = env.RACE_SCENARIO, worker = env.RACE_WORKER, N = 4;
const pkg = scenario === 'same-key' ? 'RACE-A' : scenario === 'same-round' ? 'RACE-B' : null;
if (!pkg || !/^refs\/odin-test\/\d+$/.test(env.GATE_REF_PREFIX || '')) { console.error('bad scenario/prefix'); process.exit(2); }
const api = makeGitHub({ token: env.GITHUB_TOKEN, repo: env.GITHUB_REPOSITORY });
const { sha } = await api.getAuthz(pkg);
const mk = (a) => ({ package_id: pkg, op: 'noop-implement', round: '0', target_sha: BASE, authz_sha: sha, paths: 'sandbox/a/x.txt',
  idem_key: scenario === 'same-key' ? 'race-shared-key-0001' : 'race-key-w' + worker + '-a' + a });
const wait = Number(env.RACE_FIRE_AT) - Date.now();
console.log('RACE-INFO ' + JSON.stringify({ scenario, worker, wait_ms: wait, fire_at: Number(env.RACE_FIRE_AT) }));
if (wait > 0 && wait < 120000) await new Promise((r) => setTimeout(r, wait));
const t0 = Date.now();
const out = await Promise.all(Array.from({ length: N }, async (_, a) => { const res = await claim(api, mk(a), env); return { worker, attempt: a, code: res.code, t_start_ms: t0 }; }));
for (const o of out) console.log('RACE-RESULT ' + JSON.stringify(o));
