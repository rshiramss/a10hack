# Feature 1: MCP front door + bring-your-own agent

> **Historical plan** (pre-implementation notes). Live behavior: MCP exposes **only
> `ask_ward`**; OrchestratorAgent wires specialists. See `docs/MCP_DEMO.md`.

## Goal

Ward serves an MCP front door on the **Ward** server. An external MCP client (Cursor via
`scripts/badge_agent.py`) authenticates as an identity; `tools/list` shows `ask_ward` only;
`ask_ward` runs the existing lease → delegation → sealed handshake → typed output path via
the orchestrator; the operator can revoke mid-task and the next call is blocked.

## Current baseline

- Ward has no `/mcp`, no agent token HTTP API, no external roles.
- `Gateway._master` hard-requires `master_role` for `declare_plan` / `consult` / etc.
- Specialists refuse any delegation whose `sub_role` is not the master role
  (`specialist.py` line ~116).
- Attestation registry is built at Gateway init from specialist tool source + master
  functions only (`expected_measurements`).
- Old trial MCP (`badge/mcp.py` + `server/app.py`) is **reference only** — patterns, not
  code paths. Dev dep `mcp` already present.

## Files to add

| Path | Purpose |
|------|---------|
| `ward/mcp.py` | Stateless Streamable-HTTP JSON-RPC handler (`initialize`, `tools/list`, `tools/call`, `ping`, notifications → 202). Maps MCP auth → gateway ops. |
| `scripts/badge_agent.py` | Stdio MCP proxy: env `WARD_URL` / `WARD_CLIENT_ID` / `WARD_CLIENT_SECRET`; generates `AgentKey`; attests (SHA-256 of own source); gets badge; rotates every 45s; signs every request; proxies list/call to `POST /mcp`. |
| `tests/ward/test_mcp.py` | Acceptance tests per CURSOR_PROMPT (SDK client + in-process uvicorn). |
| `docs/MCP_DEMO.md` | Copy-paste Cursor `.cursor/mcp.json` and Claude Code configs. |

## Files to change

| Path | Change |
|------|--------|
| `config/hospital.yaml` | Add `clinician_assistant` and `scheduling_assistant` external roles; add `may_delegate: true` (or equivalent) + tool allowlists; extend specialists' `callable_by` to include those roles that may consult them; add `external:` / attestation knobs if needed; drug tier table if not already present for Feature 2 reuse is out of scope here. |
| `ward/config.py` | Parse new role flags: `external`, `may_delegate`, tool list for external roles (roles that own no tools but may call others' tools via MCP). External roles are not specialists and not master. |
| `ward/gateway.py` | Replace `_master`-only gate with `_delegator(cred, op)` that allows master **or** roles with `may_delegate`. Per-role tool allowlist for plan validation. MCP session runs: `start_mcp_run` / one-step plan + consult. Register expected measurement for badge-agent binary. Snapshot includes external agents. On role overreach → deny + revoke (existing `REVOKE_NOW` + `DENY_ROLE_FORBIDDEN`). |
| `ward/specialist.py` | Accept `sub_role` if it is in this specialist's `callable_by` (not only master). Keep Ed25519 / seal / tool ownership checks. |
| `ward/attestation.py` | Helper to measure external agent source file(s). |
| `server/ward_app.py` | `POST /mcp` (+ GET/DELETE → 405); `POST /api/agent/token`; `POST /api/agent/rotate`; `POST /api/mcp/issue` (operator: role picker → provision + return client_id/secret once). |
| `server/ward_ui/{index.html,app.js,styles.css}` | "Issue MCP credential" button + role picker; show secret once; agent cards for external agents with Revoke. |
| `pyproject.toml` | Ensure `scripts/badge_agent.py` runnable; hatch packages already include `ward`? (today packages are `badge, server, agents` — verify `uv run` path works via pythonpath). |

## Data model / API

### Policy (`hospital.yaml`)

```yaml
roles:
  clinician_assistant:
    display_name: CursorAgent   # instance numbers: CursorAgent1, ...
    external: true
    may_delegate: true
    description: External MCP client; may call all specialist tools.
    tools_allowed: ["*"]          # or explicit list of every specialist tool
  scheduling_assistant:
    display_name: SchedulingBot
    external: true
    may_delegate: true
    description: External MCP client limited to scheduling + profile.
    tools_allowed:
      - find_appointment_slots
      - book_appointment
      - get_patient_profile

# Every specialist that MCP may hit adds the external roles to callable_by, e.g.:
# registration.callable_by: [orchestrator, clinician_assistant, scheduling_assistant]
# med_history.callable_by: [orchestrator, clinician_assistant]
# ...
```

Orchestrator keeps `master: true` and current powers. External roles never get `master`.

### Gateway behavior for MCP `tools/call`

1. Verify badge + proof with op `mcp:tools/call:<tool_name>` (or `mcp:tools/call` + tool in body — pick one and stick to it; prefer including tool name for tighter PoP binding).
2. Ensure a durable MCP session run exists for this `agent_id` (create on first call / initialize): status `running`, not tied to chat prompt; watchdog applies unless Feature 2 pauses it.
3. Build a **one-step** plan: agent = owning specialist's `display_name`, tool + args from MCP params.
4. Validate like `declare_plan`: schema, `tools_allowed` for caller role, prerequisites from earlier **used** leases in the same MCP run (`needs_earlier_steps`). Missing prereq → MCP tool error naming the tools to call first (clear text; do not revoke for honest prereq miss).
5. Mint single-use lease → `consult` path unchanged (delegation, seal, handshake, typed output).
6. Return typed result as MCP `structuredContent` + text JSON. Denials → `isError` + reason code; audited.

`tools/list`: verify op `mcp:tools/list`; return only tools in caller's `tools_allowed` with JSON Schema derived from typed config (same field types as today).

### HTTP

- `POST /mcp` — Streamable HTTP, JSON body responses; notifications → 202; GET/DELETE → 405.
- Auth: `Authorization: Bearer <badge>` + `X-Badge-Proof: <proof JWT>`.
- `POST /api/agent/token` — `{client_id, secret, public_pem, key_proof, measurement}` → badge session (same fields as `Gateway.authenticate`).
- `POST /api/agent/rotate` — badge + proof + new key proof → new session.
- `POST /api/mcp/issue` — operator CSRF + session; `{role}` → provision external agent; response shows `client_id` + `secret` **once**.

### `badge_agent.py`

- Stdio newline-delimited JSON-RPC (hand-rolled or `mcp` SDK — prefer SDK if it keeps the script thin).
- On start: load source bytes of itself → SHA-256 measurement; authenticate; background rotate when `rotate_due`.
- Never print secret/badge/full keys. LLM only sees tool schemas/results via stdio MCP.

## Security analysis

| Risk | Mitigation |
|------|------------|
| External agent acts as master | Never set `master: true`; chat/start_run stay master-only. |
| Scheduling bot drafts orders | `tools_allowed` filter on list **and** call; overreach → `DENY_ROLE_FORBIDDEN` + revoke. |
| Stolen badge without key | Existing PoP + `revoke_on_pop_failure`. |
| Pre-rotation badge | `DENY_BADGE_SUPERSEDED`. |
| Revoke then re-auth | Agent status `revoked` → `DENY_REVOKED` on authenticate. |
| Secret/badge in UI/logs | Issue endpoint one-shot; audit only 8-char ids; UI never stores secret after dismiss. |
| Attestation spoof | Expected measurement registered from `scripts/badge_agent.py` source at gateway boot for external roles. |
| LLM in allow/deny | MCP path calls only Gateway; no LLM. |
| Natural language between agents | Unchanged: only typed args/outputs cross. |

## Test list (`tests/ward/test_mcp.py`)

1. SDK client spawns `badge_agent` over stdio against in-process uvicorn: initialize, tools/list filtered, successful `get_allergies`.
2. `draft_order` denied until prerequisites ran in same session, then allowed; output typed only.
3. `scheduling_assistant` never lists `draft_order`; calling it → denied + identity revoked.
4. No credential → refused at initialize.
5. Copied badge without key → refused (+ victim revoked per policy).
6. Badge from before rotation → refused.
7. Operator revoke mid-session → next `tools/call` → `DENY_REVOKED`; badge agent cannot re-authenticate.
8. Transparent rotation during a long session (advance clock / force rotate_after).
9. Full existing suite still green (`env -u GROQ_API_KEY`).

## Risks / open decisions (need your OK)

1. **External roles "own" no tools** — they appear as callers in `callable_by` and have `tools_allowed`. Confirm this model vs giving them a fake tool list.
2. **MCP session = one long run** vs run-per-call — plan recommends one durable run so prerequisites accumulate (required for `draft_order` demo).
3. **Overreach revoke** — prompt says scheduling calling `draft_order` revokes; implement via `DENY_ROLE_FORBIDDEN` ∈ `REVOKE_NOW` (already).
4. **Display names** — use `CursorAgent` / `SchedulingBot` so console cards match the prompt's `CursorAgent1` example.
5. Do **not** port old trial `/mcp` into Ward; new `ward/mcp.py` only.
