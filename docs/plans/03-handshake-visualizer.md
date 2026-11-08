# Feature 3: Handshake visualizer

> **Historical plan** (pre-implementation notes). Live UI: `server/ward_ui/handshake.js`.

## Goal

For the selected plan step, an animated sequence diagram (Orchestrator / external agent |
Gateway | Specialist) shows the real consult path. Failures stop in red at the failing hop.
Click → inspector with non-secret fields. Toggle "What the master actually saw". Pure
DOM/CSS/SVG; paper/ink style; `prefers-reduced-motion`.

## Current baseline

- UI shows small handshake **chips** per step (`signed call`, `lease`, `delegation signed`,
  `sealed AES-GCM`, `handshake`, `typed output`) driven by audit kinds — not a sequence
  diagram, no animation, no inspector payloads beyond raw audit JSON.
- Audit `DELEGATED` detail has args/inputs; `HANDSHAKE` has lease + proof label;
  `DELIVERED` has full typed result. No ciphertext prefix, no delegation claim subset,
  no proof hash prefix dedicated for UI.
- No Playwright in deps today.

## Files to add

| Path | Purpose |
|------|---------|
| `server/ward_ui/handshake.js` | Sequence diagram renderer + animation state machine (or keep in `app.js` if small enough — prefer separate file for clarity). |
| `tests/ward/test_handshake_ui_data.py` | Assert snapshot/audit inspector fields present and secret-free. |

## Files to change

| Path | Change |
|------|--------|
| `ward/gateway.py` | Enrich audit details (non-secret only): delegation claims subset (`sub`, `aud`, `lease`, `tool`, `exp` — **no** signatures/keys); `ciphertext_prefix16` (hex of first 16 bytes of sealed box); `proof_hash_prefix` (8–16 hex of challenge/proof material); keep typed `result`. On failure hops, ensure reason lands on the right audit kind so UI can map hop → fail. |
| `ward/gateway.py` `snapshot` | Per-step `handshake` object for the UI: ordered hops with status `pending`/`ok`/`fail`, labels, inspector payloads, `master_saw` typed result or null. |
| `server/ward_ui/index.html` | Container for diagram + inspector + toggle. |
| `server/ward_ui/styles.css` | Lanes, arrows, motion (and `@media (prefers-reduced-motion: reduce)` → jump to final state). Projector-readable sizes; match existing paper/ink. |
| `server/ward_ui/app.js` | Wire step click → visualizer; drive animation from snapshot; no `innerHTML` with data. |

## Data model / hop sequence

Fixed ordered hops (labels = real mechanisms):

1. **Signed call** — badge + PoP (`verify`)
2. **Badge / key / lease checks** — `check_badge`, lease active, order, inputs
3. **Ed25519 delegation** — gateway → specialist
4. **AES-GCM sealed envelope** — args + typed inputs
5. **Challenge** — gateway nonce
6. **Signed proof back** — HMAC + key signature
7. **Approval wait** (optional hop when Feature 2 applies) — pending/approved/denied/timeout
8. **Typed fields only** — output schema check + deliver

Failure mapping (examples from prompt):

| Scenario | Stop hop (red) |
|----------|----------------|
| Revoked badge mid-call | Badge / key / lease checks (or RESULT_DISCARDED after handshake → mark deliver hop) |
| P007 injected text / bad output | Typed fields only (`OUTPUT_REJECTED`) |
| Forged / bad handshake | Signed proof back |
| Approval denied / timeout | Approval wait |
| Stolen badge PoP fail | Signed call |

## Snapshot shape (UI contract)

```json
{
  "lease_id": "L-…",
  "lanes": ["caller", "gateway", "specialist"],
  "hops": [
    {
      "id": "signed_call",
      "label": "signed call (badge + PoP)",
      "status": "ok",
      "from": "caller",
      "to": "gateway",
      "inspector": { "op": "consult", "jkt_prefix": "a1b2c3d4" }
    }
  ],
  "master_saw": { "status": "drafted", "order_id": "ORD-…", "block_reasons": [] },
  "approval": null
}
```

Secrets never appear: no PEMs, no full JWTs, no seal/proof keys, no full ciphertext.

## Animation

- On step select: animate arrows 1…N with short delays; pause briefly on each.
- `prefers-reduced-motion`: show final hop states immediately, no timed sequence.
- Re-select or live audit update: re-sync from snapshot (don't invent hops client-side).

## Security analysis

| Risk | Mitigation |
|------|------------|
| Ciphertext leak | Only first 16 bytes hex in audit/UI. |
| Delegation token leak | Claims subset only; never raw JWT. |
| Proof leak | Hash prefix only. |
| XSS | `textContent` / `el()` only; no `innerHTML` with data. |

## Test list

1. After successful consult, snapshot step includes inspector fields; grep-style asserts no
   `BEGIN PRIVATE`, seal_key, full token patterns in snapshot JSON.
2. OUTPUT_REJECTED path: hop `typed_output` status `fail`; earlier hops `ok`.
3. Revoke mid-call: failing hop red; master_saw null.
4. Approval pending: approval hop `pending`.
5. Optional: if Playwright easy to add as dev dep, one smoke that diagram root exists after
   fake state inject; otherwise data tests only (prompt allows this).

## Risks / open decisions

1. **Animate from live audit stream vs precomputed snapshot hops** — recommend gateway
   builds `handshake` in snapshot so the UI stays dumb and testable.
2. **Caller lane label** — "Orchestrator" for master runs, external agent display name for
   MCP runs (from run/lease actor).
3. Adding Playwright — default **no** unless you want browser smoke; data tests first.
