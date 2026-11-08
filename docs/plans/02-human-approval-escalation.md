# Feature 2: Human approval + escalation

## Goal

Tools that need a clinician/operator sign-off pause at `awaiting_approval` until Approve,
Deny, or timeout. Security revocations create escalations that page CareTeam and show a
console banner. Works for chat master **and** MCP callers.

## Current baseline

- Leases: `active` → `used` / `failed` / `expired` / `revoked` / `unused`. No approval state.
- `consult` runs straight through after lease checks; watchdog ticks every ~0.25s and
  revokes masters with no progress.
- `page_clinician` exists as a normal specialist tool; gateway does not call it internally.
- Console has no Approvals panel.
- Old trial dashboard has an "escalations" list for read disagreements — unrelated; do not reuse.

## Files to add

| Path | Purpose |
|------|---------|
| (none required) | Prefer extending gateway + UI; optional `ward/approvals.py` only if gateway file gets too large. |

## Files to change

| Path | Change |
|------|--------|
| `config/hospital.yaml` | `approvals:` block — per-tool rules + `approval_timeout_seconds`. Rules: always / when arg matches / when piped evidence matches (tier ≥ 3). Escalation: which revoke reasons create escalations. |
| `ward/config.py` | Parse approval rules into typed structs; validate tool names exist. |
| `ward/gateway.py` | Schema: `approvals` + `escalations` tables (or columns on leases). Lease status `awaiting_approval`. Before handshake in `consult`, if rule matches → create approval record, set status, audit, release lock, poll until decided. Pause watchdog for that run while waiting. Timeout → `DENY_APPROVAL_TIMEOUT`. Approve/deny operator APIs. On security revoke → escalation record + internal CareTeam `page_clinician` under gateway identity (audited). |
| `server/ward_app.py` | `POST /api/approvals/{id}/approve`, `.../deny` (reason), `POST /api/escalations/{id}/ack`; include pending approvals + escalations in `/api/state`. |
| `server/ward_ui/*` | Approvals panel (evidence + Approve/Deny+reason); masthead badge counter; escalation banner + Acknowledge. |
| `tests/ward/test_approvals.py` | Approve, deny, timeout, watchdog paused, MCP waiter, escalation on each security revoke reason. |

## Data model

### Policy

```yaml
approvals:
  timeout_seconds: 120
  rules:
    - tool: draft_order
      when: always
    - tool: page_clinician
      when: { arg: urgency, equals: stat }
    - tool: request_prior_auth
      when: always
    - tool: draft_order
      when: { evidence: tier, from_tool: check_coverage, field: tier, gte: 3 }
      # Prefer: if check_coverage already ran in-run with matching patient/drug and tier>=3;
      # also always-approve rule already covers all draft_order — keep explicit tier rule
      # only if we drop "always" for draft_order. Prompt lists both "always" and tier>=3;
      # implement as: draft_order always requires approval (tier rule is redundant but
      # documented for demos). Prefer single always rule for draft_order to avoid double
      # records.

escalation:
  on_reasons:
    - stolen_badge          # PoP failure revoke
    - role_violation        # DENY_ROLE_FORBIDDEN / DENY_NOT_CALLABLE / DENY_NOT_MASTER
    - attestation_failure
    - watchdog
    - repeated_denials
  page:
    tool: page_clinician
    urgency: stat
    # patient_id / clinician resolved from run context or demo defaults in config
```

**Decision needed:** Prompt lists `draft_order` (always) **and** `draft_order` for tier ≥ 3.
Plan: implement **always** for `draft_order` (covers tier ≥ 3). Keep tier rule as optional
second example using `request_prior_auth` or document tier as a future filter — see risks.

### Schema additions

```sql
CREATE TABLE approvals (
  approval_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  lease_id TEXT NOT NULL,
  tool TEXT NOT NULL,
  args_json TEXT NOT NULL,
  evidence_json TEXT NOT NULL,  -- typed inputs already gathered
  status TEXT NOT NULL,         -- pending | approved | denied | timed_out
  created_ms INTEGER NOT NULL,
  decided_ms INTEGER,
  operator TEXT,
  reason TEXT
);
CREATE TABLE escalations (
  escalation_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  run_id TEXT,
  trigger_reason TEXT NOT NULL,
  summary TEXT NOT NULL,
  page_id TEXT,                 -- from page_clinician if succeeded
  status TEXT NOT NULL,         -- open | acknowledged
  created_ms INTEGER NOT NULL,
  acked_ms INTEGER,
  acked_by TEXT
);
```

Lease statuses: add `awaiting_approval` to CHECK (migration: recreate schema in tests;
Gateway currently creates fresh in-memory/file DB each reset — update `STATE_SCHEMA`).

### `consult` flow change

Phase A (under lock): existing lease/precondition checks → gather inputs → **if approval
required and no decision yet**: insert approval, set lease `awaiting_approval`, audit
`APPROVAL_REQUIRED`, set run flag `approval_paused=1` (or track set of paused run_ids),
release lock.

Poll loop (no lock held between sleeps): sleep short intervals; re-acquire lock; if
approved → set lease back to `active` (or proceed with a one-shot "approved" path);
if denied → fail lease `DENY_APPROVAL_DENIED`; if past timeout → `DENY_APPROVAL_TIMEOUT`.
Clear pause flag. Then continue Phase B handshake as today.

MCP callers: `tools/call` blocks in the same poll (HTTP request stays open) or returns a
pending MCP error that badge_agent retries — **prefer blocking poll** so Cursor sees one
call that eventually returns (demo-friendly; timeout capped by config).

### Watchdog

`watchdog_tick` skips runs with `approval_paused` (or any lease `awaiting_approval`).
Progress clock does **not** advance during wait (idle time frozen) so timeout is purely
the approval timer.

### Escalation on security revoke

Extend `revoke()`: if `why` / mapped reason is in escalation set, create escalation and
call internal helper `_page_on_call(run_id, summary)` that provisions CareTeam under a
gateway-owned short run or uses existing instance, audits `ESCALATION_PAGED`. Failures
in paging still leave the escalation record (fail closed on security; paging is best-effort
but must be audited either way).

Map:
- PoP revoke → stolen_badge
- DENY_ROLE_FORBIDDEN / NOT_CALLABLE / NOT_MASTER → role_violation
- attestation quarantine revoke → attestation_failure
- watchdog actor → watchdog
- max denied calls → repeated_denials

## API

- `POST /api/approvals/{id}/approve` `{ }` — operator
- `POST /api/approvals/{id}/deny` `{ "reason": "..." }`
- `POST /api/escalations/{id}/ack`
- `/api/state` adds `approvals: [...]`, `escalations: [...]`, `approval_count`

## Security analysis

| Risk | Mitigation |
|------|------------|
| LLM approves | Only operator endpoints; CSRF + session. |
| Timeout = allow | Timeout = deny (`DENY_APPROVAL_TIMEOUT`). |
| Watchdog kills waiting run | Pause watchdog while awaiting. |
| Approval bypass by MCP | Same `consult` path; no parallel tool runner. |
| Secrets in evidence UI | Show typed args/inputs only; never badge/keys. |
| Gateway paging as privilege escalation | Fixed CareTeam tool + audited gateway actor; no free-form tools. |

## Test list

1. Approve path: `draft_order` waits → operator approve → typed result delivered.
2. Deny path: deny with reason → `DENY_APPROVAL_DENIED`, audited.
3. Timeout path: short timeout in test config → `DENY_APPROVAL_TIMEOUT`.
4. Watchdog does not trip while awaiting (freeze time / short watchdog, long wait).
5. MCP caller waits for approval then succeeds.
6. Escalation created on: stolen badge, role violation, attestation failure, watchdog,
   repeated denials; each has open escalation; ack clears banner state.
7. Existing suite green.

## Risks / open decisions

1. **draft_order always vs tier≥3** — recommend always-only to avoid duplicate approvals;
   confirm.
2. **Blocking HTTP for MCP approval** vs async pending — recommend blocking with timeout.
3. **Which patient/clinician for escalation page** — use config demo defaults
   (`escalation.page.patient_id`, `clinician`) when run has no patient context.
4. Schema CHECK change for lease status — update all tests that assume status set.
