// Pure authorization decision logic for the synthetic Canary-02 gate. No I/O here.
// Fail-closed: anything unexpected is a DENY.

export const OPS = ['noop-implement', 'noop-remediate'];
export const STATUSES = ['APPROVED', 'BLOCK', 'WAITING_OWNER'];
const RE_PKG = /^[A-Za-z0-9][A-Za-z0-9-]{2,63}$/;
const RE_SHA = /^[0-9a-f]{40}$/;
const RE_KEY = /^[a-z0-9][a-z0-9-]{7,63}$/;
const RE_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const RE_REF = /^[A-Za-z0-9][A-Za-z0-9._\/-]{0,100}$/;

export function parseTs(s) {
  if (typeof s !== 'string' || !RE_TS.test(s)) return NaN;
  return Date.parse(s);
}

// Declared-path scope check. Globs: `**` = any depth, `*` = one segment (no '/').
export function normalizePath(p) {
  if (typeof p !== 'string' || p.length === 0 || p.length > 200) return null;
  if (p.startsWith('/') || p.includes('\\') || p.includes('\0') || p.includes('//')) return null;
  const segs = p.split('/');
  if (segs.some((s) => s === '' || s === '.' || s === '..')) return null;
  return segs.join('/');
}

export function globToRegExp(g) {
  let re = '';
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === '*' && g[i + 1] === '*') { re += '.*'; i++; }
    else if (c === '*') re += '[^/]*';
    else re += c.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp('^' + re + '$');
}

export function pathAllowed(p, globs) {
  const n = normalizePath(p);
  if (n === null) return false;
  return globs.some((g) => globToRegExp(g).test(n));
}

export function validateInput(i) {
  if (!i || typeof i !== 'object') return 'no input';
  if (!RE_PKG.test(i.package_id ?? '')) return 'package_id';
  if (typeof i.op !== 'string' || i.op.length > 40) return 'op';
  if (!/^\d{1,3}$/.test(String(i.round ?? ''))) return 'round';
  if (!RE_SHA.test(i.target_sha ?? '')) return 'target_sha';
  if (!RE_SHA.test(i.authz_sha ?? '')) return 'authz_sha';
  if (!RE_KEY.test(i.idem_key ?? '')) return 'idem_key';
  if (typeof i.paths !== 'string' || i.paths.length > 1000) return 'paths';
  return null;
}

export function parsePaths(s) {
  return s.split(',').map((x) => x.trim()).filter((x) => x.length > 0);
}

export function validateAuthz(a, pkg, repo) {
  if (!a || typeof a !== 'object' || Array.isArray(a)) return 'not an object';
  if (a.schema !== 'odin-authz/1') return 'schema';
  if (a.package_id !== pkg) return 'package_id mismatch';
  if (!Number.isInteger(a.revision) || a.revision < 1) return 'revision';
  if (typeof a.approval_ref !== 'string' || a.approval_ref.length === 0) return 'approval_ref';
  if (a.repo !== repo) return 'repo mismatch';
  if (!RE_SHA.test(a.baseline_sha ?? '')) return 'baseline_sha';
  if (!RE_REF.test(a.target_ref ?? '')) return 'target_ref';
  if (!Array.isArray(a.allowed_ops) || !a.allowed_ops.every((o) => OPS.includes(o))) return 'allowed_ops';
  if (!Array.isArray(a.scope_paths) || a.scope_paths.length === 0 || !a.scope_paths.every((g) => typeof g === 'string' && g.length > 0 && !g.startsWith('/') && !g.includes('..'))) return 'scope_paths';
  if (Number.isNaN(parseTs(a.issued_at)) || Number.isNaN(parseTs(a.expires_at))) return 'timestamps';
  if (!Number.isInteger(a.max_remediation_rounds) || a.max_remediation_rounds < 0 || a.max_remediation_rounds > 10) return 'max_remediation_rounds';
  if (typeof a.revoked !== 'boolean') return 'revoked';
  if (!STATUSES.includes(a.status)) return 'status';
  return null;
}

// ctx: { authz, authzBlobSha, input, head, now (ms), state:{blocked, idemExists, claimed:Set<int>}, repo, dispatchRef }
// returns { ok:true } | { ok:false, code, status } ; status in DENIED | BLOCK | WAITING_OWNER | NOOP
export function decide(ctx) {
  const { authz, authzBlobSha, input, head, now, state, repo, dispatchRef } = ctx;
  const deny = (code, status = 'DENIED') => ({ ok: false, code, status });
  if (dispatchRef !== 'refs/heads/main') return deny('BAD_DISPATCH_REF');
  const iv = validateInput(input);
  if (iv) return deny('BAD_INPUT:' + iv);
  const round = Number(input.round);
  if (!authz) return deny('NO_AUTHZ');
  const av = validateAuthz(authz, input.package_id, repo);
  if (av) return deny('BAD_AUTHZ:' + av);
  if (authz.revoked) return deny('REVOKED');
  if (authz.status === 'BLOCK' || state.blocked) return deny('BLOCKED', 'BLOCK');
  if (authz.status === 'WAITING_OWNER') return deny('WAITING_OWNER', 'WAITING_OWNER');
  if (!Number.isFinite(now)) return deny('BAD_CLOCK');
  if (now < parseTs(authz.issued_at)) return deny('NOT_YET_VALID');
  if (now >= parseTs(authz.expires_at)) return deny('EXPIRED');
  if (input.authz_sha !== authzBlobSha) return deny('STALE_AUTHZ', 'WAITING_OWNER');
  if (!authz.allowed_ops.includes(input.op)) return deny('OP_NOT_ALLOWED');
  if ((input.op === 'noop-implement') !== (round === 0)) return deny('ROUND_OP_MISMATCH');
  if (round > authz.max_remediation_rounds) return deny('RETRY_EXHAUSTED');
  if (input.target_sha !== authz.baseline_sha) return deny('SHA_MISMATCH', 'WAITING_OWNER');
  if (head !== authz.baseline_sha) return deny('HEAD_MISMATCH', 'WAITING_OWNER');
  const paths = parsePaths(input.paths);
  if (paths.length === 0 || !paths.every((p) => pathAllowed(p, authz.scope_paths))) return deny('SCOPE');
  if (state.idemExists) return deny('DUPLICATE', 'NOOP');
  if (round > 0 && !state.claimed.has(round - 1)) return deny('ROUND_GAP');
  if (state.claimed.has(round)) return deny('ROUND_TAKEN');
  return { ok: true };
}
