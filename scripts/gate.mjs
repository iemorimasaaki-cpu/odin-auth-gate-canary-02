// Gate runtime: GitHub REST adapter + precheck/claim. Node >= 20, no dependencies.
// The only trusted inputs are: authz file on main, real branch head, create-only refs, runner clock.
import { appendFileSync } from 'node:fs';
import { decide } from './gate-core.mjs';

const PREFIX_RE = /^refs\/odin(-test\/\d{1,20})?$/;

export function makeGitHub({ token, repo, apiBase = 'https://api.github.com' }) {
  async function call(method, path, body) {
    const res = await fetch(apiBase + '/repos/' + repo + path, {
      method,
      headers: {
        Authorization: 'Bearer ' + token,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'application/json',
        'User-Agent': 'odin-auth-gate-canary-02',
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    let json = null;
    try { json = await res.json(); } catch { /* empty body */ }
    return { status: res.status, json };
  }
  async function read(path) {
    for (let i = 0; i < 3; i++) {
      const r = await call('GET', path);
      if (r.status < 500) return r;
    }
    throw new Error('GET ' + path + ' failed (5xx)');
  }
  return {
    async getAuthz(pkg) {
      const r = await read('/contents/authz/' + encodeURIComponent(pkg) + '.json?ref=main');
      if (r.status === 404) return { authz: null, sha: null };
      if (r.status !== 200 || r.json.type !== 'file') throw new Error('authz read status ' + r.status);
      let authz = null;
      try { authz = JSON.parse(Buffer.from(r.json.content, 'base64').toString('utf8')); } catch { authz = { schema: 'unparseable' }; }
      return { authz, sha: r.json.sha };
    },
    async getHead(branch) {
      const r = await read('/git/ref/heads/' + branch.split('/').map(encodeURIComponent).join('/'));
      if (r.status === 404) return null;
      if (r.status !== 200) throw new Error('head read status ' + r.status);
      return r.json.object.sha;
    },
    async refExists(full) {
      const r = await read('/git/ref/' + full.replace(/^refs\//, ''));
      if (r.status === 200 && r.json && r.json.ref === full) return true; // exact match only
      if (r.status === 404) return false;
      throw new Error('ref read status ' + r.status);
    },
    // create-only: 'created' | 'exists'. Never retried blindly.
    async createRef(full, sha) {
      const r = await call('POST', '/git/refs', { ref: full, sha });
      if (r.status === 201) return 'created';
      if (r.status === 422 && /already exists/i.test(JSON.stringify(r.json))) return 'exists';
      throw new Error('createRef status ' + r.status + ' ' + JSON.stringify(r.json).slice(0, 200));
    },
  };
}

export function refNames(prefix, pkg, round, key) {
  return {
    idem: prefix + '/idem/' + pkg + '/' + key,
    claim: (n) => prefix + '/claim/' + pkg + '/r' + n,
    block: prefix + '/block/' + pkg,
  };
}

async function gather(api, input, env) {
  const prefix = env.GATE_REF_PREFIX || 'refs/odin';
  if (!PREFIX_RE.test(prefix)) throw new Error('bad GATE_REF_PREFIX');
  const { authz, sha } = await api.getAuthz(input.package_id);
  const names = refNames(prefix, input.package_id, input.round, input.idem_key);
  const state = { blocked: false, idemExists: false, claimed: new Set() };
  let head = null;
  if (authz && authz.package_id === input.package_id) {
    if (typeof authz.target_ref === 'string' && /^[A-Za-z0-9][A-Za-z0-9._\/-]{0,100}$/.test(authz.target_ref)) head = await api.getHead(authz.target_ref);
    state.blocked = await api.refExists(names.block);
    state.idemExists = await api.refExists(names.idem);
    const max = Number.isInteger(authz.max_remediation_rounds) ? Math.min(authz.max_remediation_rounds, 10) : 0;
    for (let n = 0; n <= max; n++) if (await api.refExists(names.claim(n))) state.claimed.add(n);
  }
  return { authz, authzBlobSha: sha, head, state, names };
}

export function inputFromEnv(env) {
  return {
    package_id: env.IN_PACKAGE_ID, op: env.IN_OP, round: env.IN_ROUND, target_sha: env.IN_TARGET_SHA,
    authz_sha: env.IN_AUTHZ_SHA, paths: env.IN_PATHS, idem_key: env.IN_IDEM_KEY,
  };
}

async function evaluate(api, input, env) {
  const g = await gather(api, input, env);
  const d = decide({
    authz: g.authz, authzBlobSha: g.authzBlobSha, input, head: g.head, state: g.state,
    now: env.GATE_NOW_MS ? Number(env.GATE_NOW_MS) : Date.now(), repo: env.GITHUB_REPOSITORY,
    dispatchRef: env.GITHUB_REF,
  });
  return { d, g };
}

// Read-only. exit: 0 = proceed (run=true) or benign no-op duplicate (run=false); 1 = denied/error.
export async function precheck(api, input, env) {
  try {
    const { d } = await evaluate(api, input, env);
    if (d.ok) return { exit: 0, run: true, code: 'ALLOW_PENDING_APPROVAL', status: 'OK' };
    return { exit: d.status === 'NOOP' ? 0 : 1, run: false, code: d.code, status: d.status };
  } catch (e) {
    return { exit: 1, run: false, code: 'API_ERROR', status: 'DENIED', error: String(e.message || e) };
  }
}

// Re-verifies everything, then consumes the idem ref and the round ref (create-only).
export async function claim(api, input, env) {
  try {
    const { d, g } = await evaluate(api, input, env);
    if (!d.ok) return { exit: d.status === 'NOOP' ? 0 : 1, claimed: false, code: d.code, status: d.status };
    const sha = g.authz.baseline_sha;
    const idem = await api.createRef(g.names.idem, sha);
    if (idem === 'exists') return { exit: 0, claimed: false, code: 'DUPLICATE', status: 'NOOP' };
    const rd = await api.createRef(g.names.claim(Number(input.round)), sha);
    if (rd === 'exists') return { exit: 1, claimed: false, code: 'ROUND_TAKEN', status: 'DENIED', note: 'idem key consumed without a run' };
    return { exit: 0, claimed: true, code: 'CLAIMED', status: 'OK' };
  } catch (e) {
    return { exit: 1, claimed: false, code: 'API_ERROR', status: 'DENIED', error: String(e.message || e) };
  }
}

function emit(env, res, extra = {}) {
  const lines = Object.entries({ ...res, ...extra }).filter(([k]) => k !== 'exit').map(([k, v]) => k + '=' + String(v));
  if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, lines.join('\n') + '\n');
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, '### gate: ' + res.code + ' (' + res.status + ')\n```\n' + lines.join('\n') + '\n```\n');
  console.log('GATE-RESULT ' + JSON.stringify(res));
}

if (import.meta.url === 'file://' + process.argv[1]) {
  const env = process.env;
  const cmd = process.argv[2];
  const api = makeGitHub({ token: env.GITHUB_TOKEN, repo: env.GITHUB_REPOSITORY });
  const input = inputFromEnv(env);
  const fn = cmd === 'precheck' ? precheck : cmd === 'claim' ? claim : null;
  if (!fn) { console.error('usage: gate.mjs precheck|claim'); process.exit(2); }
  const res = await fn(api, input, env);
  emit(env, res);
  process.exit(res.exit);
}
