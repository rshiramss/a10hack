# Ward MCP demo (Cursor + Claude Code)

Ward serves specialist tools over real MCP. An external client authenticates as a
role, sees only that role's tools, and every `tools/call` goes through lease →
delegation → sealed handshake → typed output. Revoke the agent in the console and
the next call is blocked.

## 1. Start Ward

```bash
cd a10hack
uv run python -m scripts.ward
```

Open http://127.0.0.1:8000/ and sign in (`alice` / `ward-demo-Qx7m`).

## 2. Issue an MCP credential

In **Demo controls** → **Issue MCP credential**:

- `CursorAgent` (`clinician_assistant`) — all specialist tools
- `SchedulingBot` (`scheduling_assistant`) — `find_appointment_slots`, `book_appointment`, `get_patient_profile` only

Copy `client_id` and `secret` once. They are not shown again.

## 3. Cursor (`.cursor/mcp.json`)

Put this in the project (or your user MCP config). Replace the secret values, or export
them in your shell and use `${env:...}` interpolation:

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
        "WARD_CLIENT_ID": "${env:WARD_CLIENT_ID}",
        "WARD_CLIENT_SECRET": "${env:WARD_CLIENT_SECRET}"
      }
    }
  }
}
```

Then in your shell:

```bash
export WARD_CLIENT_ID='CursorAgent1'
export WARD_CLIENT_SECRET='…paste once…'
```

Restart Cursor MCP (or reload the window). Ask Cursor to call `get_allergies` for
`P001`. In the Ward console you should see the external agent card, the plan steps,
and the handshake.

**Revoke mid-task:** click **Revoke** on the CursorAgent card, then ask Cursor to call
another tool — it should fail with `DENY_REVOKED` and cannot re-authenticate.

## 4. Claude Code

### With a credential (clinician or scheduling)

```bash
export WARD_URL=http://127.0.0.1:8000
export WARD_CLIENT_ID='SchedulingBot1'
export WARD_CLIENT_SECRET='…'

claude mcp add --transport stdio ward -- uv run --directory /ABS/PATH/TO/a10hack python scripts/badge_agent.py
```

Or a project `.mcp.json`:

```json
{
  "mcpServers": {
    "ward": {
      "command": "uv",
      "args": ["run", "--directory", "/ABS/PATH/TO/a10hack", "python", "scripts/badge_agent.py"],
      "env": {
        "WARD_URL": "http://127.0.0.1:8000",
        "WARD_CLIENT_ID": "${WARD_CLIENT_ID}",
        "WARD_CLIENT_SECRET": "${WARD_CLIENT_SECRET}"
      }
    }
  }
}
```

### Without a credential

If `WARD_CLIENT_ID` / `WARD_CLIENT_SECRET` are missing, `badge_agent.py` exits and
MCP initialize never succeeds — Claude Code will not see Ward tools. That is the
fail-closed demo: no identity, no tools.

### Scheduling overreach

With a `scheduling_assistant` credential, `draft_order` is absent from `tools/list`.
If something calls it anyway, Ward returns `DENY_ROLE_FORBIDDEN` and **revokes** that
identity.

## 5. What the LLM never sees

`scripts/badge_agent.py` holds the client secret, Ed25519 key, and badge. Stdio MCP
only exposes tool schemas and typed results. Secrets never appear in tool output.
