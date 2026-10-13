// Generates the synthetic authz fixtures under authz/. Run once; output is committed.
import { writeFileSync } from 'node:fs';
const BASE = '98d001da379da6627e0254b1fba2782f3d7c8693';
const mk = (id, o = {}) => ({
  schema: 'odin-authz/1', package_id: id, revision: 1,
  approval_ref: 'OWNER-EXECUTION-APPROVAL cmsg_01PXYeYfQNJpGFcsQBQdnsXj53VR9q7T7GJ5RDTUyKX8e4 (declarative; not machine-verified)',
  repo: 'iemorimasaaki-cpu/odin-auth-gate-canary-02', baseline_sha: BASE, target_ref: 'sandbox-target',
  allowed_ops: ['noop-implement', 'noop-remediate'], scope_paths: ['sandbox/a/**'],
  issued_at: '2026-10-13T00:00:00Z', expires_at: '2026-10-20T00:00:00Z',
  max_remediation_rounds: 2, revoked: false, status: 'APPROVED', ...o,
});
const F = {
  'CANARY-02-OK': mk('CANARY-02-OK'),
  'CANARY-02-STALE': mk('CANARY-02-STALE'),
  'SELF-OK': mk('SELF-OK'),
  'SELF-EXPIRED': mk('SELF-EXPIRED', { expires_at: '2026-10-01T00:00:00Z', issued_at: '2026-09-25T00:00:00Z' }),
  'SELF-REVOKED': mk('SELF-REVOKED', { revoked: true }),
  'SELF-BLOCK': mk('SELF-BLOCK', { status: 'BLOCK' }),
  'SELF-WAIT': mk('SELF-WAIT', { status: 'WAITING_OWNER' }),
  'SELF-REFBLOCK': mk('SELF-REFBLOCK'),
  'SELF-RETRY': mk('SELF-RETRY'),
  'SELF-GAP': mk('SELF-GAP'),
  'SELF-HEAD': mk('SELF-HEAD', { target_ref: 'sandbox-moved' }),
  'SELF-SCOPE': mk('SELF-SCOPE'),
  'SELF-OPS': mk('SELF-OPS', { allowed_ops: ['noop-implement'] }),
  'SELF-DUP': mk('SELF-DUP'),
  'RACE-A': mk('RACE-A'),
  'RACE-B': mk('RACE-B'),
};
for (const [id, v] of Object.entries(F)) writeFileSync('authz/' + id + '.json', JSON.stringify(v, null, 2) + '\n');
console.log(Object.keys(F).length + ' fixtures');
