# Ward MCP demo (Cursor + Claude Code)

Ward's MCP front door is the **gateway only**. External clients (Cursor, Claude Code)
authenticate as an identity and get exactly one tool: `ask_ward`. That hands the prompt
to **OrchestratorAgent**, which plans and consults badged specialists through
lease → delegation → sealed handshake → typed output.

Cursor cannot call `get_allergies`, `check_coverage`, etc. If it tries, Ward returns
`DENY_ROLE_FORBIDDEN` and revokes that MCP identity.

## 1. Start Ward

```bash
cd a10hack
uv run python -m scripts.ward
```

Open http://127.0.0.1:8000/ and sign in (`alice` / `ward-demo-Qx7m`).
<!-- DEMO_HARDCODE: shared hackathon console password; override via WARD_OPERATORS. -->

## 2. Issue an MCP credential (operator only)

In **Demo controls** → **Issue MCP credential**:

- `CursorAgent` (`clinician_assistant`) — gateway channel for Cursor
- `SchedulingBot` (`scheduling_assistant`) — same channel (branded credential)

Ward mints the secret and writes it to **`data/mcp-credentials.env`** (gitignored,
mode `0600`). Do **not** let Cursor invent or paste secrets into `mcp.json`.

## 3. Cursor (`.cursor/mcp.json`)

Point at the operator-issued file — no secret in the JSON:

```json
{
  "mcpServers": {
    "ward": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/ABS/PATH/TO/a10hack",
        "python",
        "scripts/badge_agent.py"
      ],
      "env": {
        "WARD_URL": "http://127.0.0.1:8000",
        "WARD_CREDENTIALS_FILE": "/ABS/PATH/TO/a10hack/data/mcp-credentials.env"
      }
    }
  }
}
```

Reload Cursor MCP. Ask Cursor something like: *Check P001's medications and coverage.*
Cursor should call **`ask_ward` only**. In the Ward console you should see
**OrchestratorAgent** declare plans and specialists (MedHistory, Insurance, …) with
badges — not CursorAgent consulting them directly.

**Revoke mid-task:** click **Revoke** on the CursorAgent card, then ask again —
`ask_ward` fails with `DENY_REVOKED`.

## 4. Claude Code

```bash
export WARD_URL=http://127.0.0.1:8000
export WARD_CREDENTIALS_FILE=/ABS/PATH/TO/a10hack/data/mcp-credentials.env

claude mcp add --transport stdio ward -- uv run --directory /ABS/PATH/TO/a10hack python scripts/badge_agent.py
```

Without credentials, `badge_agent.py` exits and MCP initialize never succeeds.

## 5. What you should see

| Layer | Who |
|-------|-----|
| MCP tool | `ask_ward` only |
| Planner | OrchestratorAgent1 (master badge) |
| Tool owners | MedHistoryAgent1, InsuranceAgent1, … (per-consult badges) |
| CursorAgent1 | Authenticated channel; revoked → no more asks |
