# odin-auth-gate-canary-02
## Synthetic authorization-gate canary (ODIN-GITHUB-AUTH-GATE-CANARY-02-IMPL-01)

Public, synthetic-only sandbox. Worker = `echo`. No secrets, no APIs, no third-party actions.
- `scripts/gate-core.mjs` pure decision logic; `scripts/gate.mjs` GitHub adapter + precheck/claim.
- `.github/workflows/gate.yml` (precheck -> Environment `owner-approval` -> re-verify + claim -> echo), `selftest.yml`, `race.yml`; all `workflow_dispatch` only.
- `authz/*.json` synthetic authorization records. Locks = create-only Git refs under `refs/odin/*` (atomicity is measured, not assumed).
- Tests: `node --test tests/gate.test.mjs`.
This does not secure Claude Projects direct worker launches.
