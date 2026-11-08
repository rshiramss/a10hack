"""The ward gateway: the only path between the master agent and the specialists.

    chat -> OrchestratorAgent (LLM) --declare_plan--> gateway: validate, mint leases
                                    --consult(lease)--> gateway: spin up + authenticate
                                                        the specialist instance, issue a
                                                        delegation, two-way handshake,
                                                        run one atomic tool, validate the
                                                        typed output, pipe it onward
            <------------------------ typed result (never free text) ---------------

Every decision is deterministic (policy file + database + request + clock) and every
one, allowed or denied, lands in a hash-chained audit log. No LLM is in this file.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import jwt

from ward import crypto
from ward.attestation import badge_agent_path, master_functions, measure, measure_source_file
from ward.config import WardConfig
from ward.data import seed_clinical
from ward.specialist import OfferRefused, SpecialistInstance
from ward.tools import TOOLS, check_registry
from ward.typed import check_record

STATE_SCHEMA = """
CREATE TABLE agents (
    agent_id TEXT PRIMARY KEY, role TEXT NOT NULL, instance_no INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'retired')),
    run_id TEXT, created_ms INTEGER NOT NULL, ended_ms INTEGER, end_reason TEXT,
    measurement TEXT
);
CREATE TABLE credentials (agent_id TEXT PRIMARY KEY, secret_hmac TEXT NOT NULL);
CREATE TABLE badges (
    jti TEXT PRIMARY KEY, agent_id TEXT NOT NULL, issued_ms INTEGER NOT NULL,
    expires_ms INTEGER NOT NULL, revoked_ms INTEGER, denied INTEGER NOT NULL DEFAULT 0,
    public_pem TEXT NOT NULL, jkt TEXT NOT NULL, superseded_by TEXT, generation INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE runs (
    run_id TEXT PRIMARY KEY, master_id TEXT NOT NULL, prompt TEXT NOT NULL,
    status TEXT NOT NULL, created_ms INTEGER NOT NULL, ended_ms INTEGER,
    answer TEXT, error TEXT, plans INTEGER NOT NULL DEFAULT 0,
    last_progress_ms INTEGER NOT NULL, flagged INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE plans (
    plan_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, seq INTEGER NOT NULL,
    status TEXT NOT NULL, reason TEXT, detail TEXT, steps_json TEXT NOT NULL,
    created_ms INTEGER NOT NULL
);
CREATE TABLE leases (
    lease_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, plan_id TEXT NOT NULL,
    step_index INTEGER NOT NULL, role TEXT NOT NULL, tool TEXT NOT NULL,
    args_json TEXT NOT NULL, status TEXT NOT NULL, target_agent TEXT,
    result_json TEXT, reason TEXT, expires_ms INTEGER NOT NULL, attempts INTEGER DEFAULT 0
);
CREATE TABLE audit (
    seq INTEGER PRIMARY KEY, ts_ms INTEGER NOT NULL, run_id TEXT, actor TEXT, target TEXT,
    kind TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, summary TEXT NOT NULL,
    detail_json TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'append-only'); END;
"""

GENESIS = "0" * 64

# Denials that mean "this agent tried something it can never do": revoke on the spot.
REVOKE_NOW = {"DENY_ROLE_FORBIDDEN", "DENY_NOT_MASTER", "DENY_NOT_CALLABLE"}
POP_REPLAY_WINDOW_S = 120


class Denied(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class Credential:
    """What an agent presents on every call: its badge and a fresh proof signed with the
    private key the badge is bound to."""

    token: str
    proof: str | None


@dataclass
class Badge:
    agent_id: str
    role: str
    jti: str
    expires_ms: int


def now_ms() -> int:
    return int(time.time() * 1000)


class Gateway:
    def __init__(
        self,
        config: WardConfig,
        db_path: str = ":memory:",
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        check_registry(config)
        self.config = config
        self.keys = crypto.KeyRing()
        self.lock = threading.RLock()
        self._sleep = sleep
        self.conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(STATE_SCHEMA)
        seed_clinical(self.conn)
        self.settings: dict[str, Any] = {
            "watchdog_seconds": float(config.run["watchdog_seconds"]),
            "step_delay_ms": int(config.run["step_delay_ms"]),
            "replace_revoked_specialists": bool(config.run["replace_revoked_specialists"]),
        }
        self.epoch = uuid.uuid4().hex[:8]
        self._seen_proofs: dict[str, float] = {}
        # Attestation registry: the measurement each role's code must have to get a badge.
        self.expected_measurements = {
            role.name: measure(role.name, config, {t: TOOLS[t] for t in role.tools})
            for role in config.specialists()
        }
        self.expected_measurements[config.master_role] = measure(
            config.master_role, config, master_functions()
        )
        # External MCP clients attest as the badge_agent source file.
        external_measurement = measure_source_file(badge_agent_path())
        for role in config.external_roles():
            self.expected_measurements[role.name] = external_measurement
        self._counters: dict[str, int] = {}
        self._instances: dict[str, SpecialistInstance] = {}
        self._mcp_runs: dict[str, str] = {}  # agent_id -> durable MCP session run_id

    # ---- audit -------------------------------------------------------------------------

    def _audit(
        self,
        kind: str,
        summary: str,
        *,
        decision: str = "EVENT",
        reason: str = "OK",
        run_id: str | None = None,
        actor: str | None = None,
        target: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        with self.lock:
            prev = self.conn.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev_hash = prev["hash"] if prev else GENESIS
            ts = now_ms()
            detail_json = json.dumps(detail or {}, sort_keys=True, default=str)
            row = [ts, run_id, actor, target, kind, decision, reason, summary, detail_json]
            digest = crypto.hmac_hex(b"audit", prev_hash + json.dumps(row))
            self.conn.execute(
                "INSERT INTO audit (ts_ms, run_id, actor, target, kind, decision, reason,"
                " summary, detail_json, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (*row, prev_hash, digest),
            )

    def verify_chain(self) -> tuple[bool, int]:
        with self.lock:
            prev, count = GENESIS, 0
            for r in self.conn.execute("SELECT * FROM audit ORDER BY seq"):
                row = [
                    r["ts_ms"],
                    r["run_id"],
                    r["actor"],
                    r["target"],
                    r["kind"],
                    r["decision"],
                    r["reason"],
                    r["summary"],
                    r["detail_json"],
                ]
                if (
                    r["prev_hash"] != prev
                    or crypto.hmac_hex(b"audit", prev + json.dumps(row)) != r["hash"]
                ):
                    return False, count
                prev, count = r["hash"], count + 1
            return True, count

    # ---- identity: provisioning, authentication, badges ---------------------------------

    def provision(self, role: str, run_id: str | None = None) -> tuple[str, str]:
        """Register a new instance of `role` (e.g. PharmacyAgent3). Returns (id, secret)."""
        spec = self.config.roles[role]
        with self.lock:
            number = self._counters.get(role, 0) + 1
            self._counters[role] = number
            agent_id = f"{spec.display_name}{number}"
            secret = crypto.new_secret()
            self.conn.execute(
                "INSERT INTO agents (agent_id, role, instance_no, status, run_id, created_ms)"
                " VALUES (?, ?, ?, 'active', ?, ?)",
                (agent_id, role, number, run_id, now_ms()),
            )
            self.conn.execute(
                "INSERT INTO credentials VALUES (?, ?)",
                (agent_id, self.keys.credential_hmac(secret)),
            )
            self._audit(
                "SPAWNED",
                f"{agent_id} spun up ({spec.description.rstrip('.')})",
                run_id=run_id,
                target=agent_id,
                detail={"role": role, "credential": "client secret (stored as HMAC)"},
            )
        return agent_id, secret

    def authenticate(
        self, agent_id: str, secret: str, public_pem: str, key_proof: str, measurement: str
    ) -> dict[str, Any]:
        """Workload credentials + code attestation + proof of key possession -> a badge
        bound to that key (+ per-instance seal/proof keys). Raises Denied."""
        with self.lock:
            row = self.conn.execute(
                "SELECT a.role, a.status, a.run_id, c.secret_hmac FROM agents a"
                " JOIN credentials c USING (agent_id) WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
            expected = row["secret_hmac"] if row else self.keys.credential_hmac("no-such-agent")
            if (
                not crypto.hmac.compare_digest(expected, self.keys.credential_hmac(secret))
                or not row
            ):
                self._audit(
                    "AUTH_FAILED",
                    f"{agent_id} failed to authenticate (bad secret)",
                    decision="DENY",
                    reason="DENY_BAD_CREDENTIALS",
                    target=agent_id,
                )
                raise Denied("DENY_BAD_CREDENTIALS", "invalid client credentials")
            if row["status"] != "active":
                self._audit(
                    "AUTH_FAILED",
                    f"{agent_id} tried to authenticate but is {row['status']}",
                    decision="DENY",
                    reason="DENY_REVOKED",
                    target=agent_id,
                    run_id=row["run_id"],
                )
                raise Denied("DENY_REVOKED", f"agent is {row['status']}")
            role = row["role"]
            if not crypto.hmac.compare_digest(measurement, self.expected_measurements[role]):
                self._audit(
                    "ATTESTATION_FAILED",
                    f"{agent_id} refused a badge: its code doesn't match the attested "
                    f"{self.config.roles[role].display_name} build "
                    f"({measurement[:8]} ≠ {self.expected_measurements[role][:8]}). Quarantined.",
                    decision="DENY",
                    reason="DENY_ATTESTATION",
                    target=agent_id,
                    run_id=row["run_id"],
                    detail={"presented": measurement, "expected": self.expected_measurements[role]},
                )
                self.revoke(agent_id, "gateway", "code attestation failed (quarantined)")
                raise Denied("DENY_ATTESTATION", "code measurement doesn't match")
            try:
                crypto.verify_proof(public_pem, key_proof, secret, "authenticate", time.time())
            except ValueError as exc:
                self._audit(
                    "AUTH_FAILED",
                    f"{agent_id} couldn't prove it holds the key it presented",
                    decision="DENY",
                    reason=str(exc),
                    target=agent_id,
                )
                raise Denied(str(exc), "proof of possession failed") from exc
            jkt = crypto.thumbprint(public_pem)
            self.conn.execute(
                "UPDATE agents SET measurement = ? WHERE agent_id = ?", (measurement, agent_id)
            )
            session = self._issue_badge(agent_id, role, public_pem, measurement, generation=1)
            self._audit(
                "AUTHENTICATED",
                f"{agent_id} authenticated: code attested, badge {session['jti'][:8]} bound to "
                f"key {jkt[:8]}, valid {self.config.badge_ttl_seconds}s",
                run_id=row["run_id"],
                target=agent_id,
                detail={
                    "badge": f"HS256-signed, AES-256-GCM-sealed, jti {session['jti'][:8]}…",
                    "role": role,
                    "cnf.jkt": jkt,
                    "measurement": measurement,
                },
            )
            return session

    def _issue_badge(
        self, agent_id: str, role: str, public_pem: str, measurement: str, generation: int
    ) -> dict[str, Any]:
        """Mint a badge bound to `public_pem`. Caller holds the lock."""
        jkt = crypto.thumbprint(public_pem)
        jti = uuid.uuid4().hex
        issued = now_ms()
        expires = issued + self.config.badge_ttl_seconds * 1000
        token = self.keys.sign_badge(
            {
                "iss": crypto.ISSUER,
                "sub": agent_id,
                "role": role,
                "system": self.config.system_id,
                "jti": jti,
                "iat": issued // 1000,
                "exp": expires // 1000,
                "cnf": {"jkt": jkt},
                "att": measurement[:16],
                "gen": generation,
            }
        )
        self.conn.execute(
            "INSERT INTO badges (jti, agent_id, issued_ms, expires_ms, public_pem, jkt, generation)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (jti, agent_id, issued, expires, public_pem, jkt, generation),
        )
        seal_key, proof_key = self.keys.instance_keys(agent_id, jti)
        return {
            "token": token,
            "jti": jti,
            "issued_ms": issued,
            "expires_ms": expires,
            "seal_key": seal_key,
            "proof_key": proof_key,
        }

    def rotate(self, cred: Credential, new_public_pem: str, new_key_proof: str) -> dict[str, Any]:
        """Swap a live badge for a new one bound to a NEW key pair.

        The caller proves it holds the current key (the signed `rotate` call) and the new
        key (a proof signed with it over the current badge). The old badge stops working
        immediately, so a badge and key stolen before a rotation are both dead after it.
        """
        badge = self.verify(cred, "rotate")
        try:
            crypto.verify_proof(
                new_public_pem, new_key_proof, cred.token, "rotate-new-key", time.time()
            )
        except ValueError as exc:
            raise Denied("DENY_POP_MISMATCH", "couldn't prove possession of the new key") from exc
        with self.lock:
            old = self.conn.execute("SELECT * FROM badges WHERE jti = ?", (badge.jti,)).fetchone()
            agent = self.conn.execute(
                "SELECT measurement, run_id FROM agents WHERE agent_id = ?", (badge.agent_id,)
            ).fetchone()
            session = self._issue_badge(
                badge.agent_id,
                badge.role,
                new_public_pem,
                agent["measurement"] or "",
                generation=old["generation"] + 1,
            )
            self.conn.execute(
                "UPDATE badges SET superseded_by = ? WHERE jti = ?", (session["jti"], badge.jti)
            )
            self._audit(
                "BADGE_ROTATED",
                f"{badge.agent_id} rotated: badge {badge.jti[:8]} → {session['jti'][:8]}, "
                f"key {old['jkt'][:8]} → {crypto.thumbprint(new_public_pem)[:8]} "
                f"(generation {old['generation'] + 1}); the old badge is dead",
                run_id=agent["run_id"],
                actor=badge.agent_id,
            )
            return session

    def rotate_due(self, token: str) -> bool:
        """True if this badge is old enough that its holder should rotate it now."""
        try:
            claims = self.keys.read_badge(token)
        except jwt.PyJWTError:
            return False
        with self.lock:
            row = self.conn.execute(
                "SELECT issued_ms FROM badges WHERE jti = ?", (claims["jti"],)
            ).fetchone()
        rotate_after = int(self.config.rotate_after_seconds) * 1000
        return row is not None and now_ms() - row["issued_ms"] >= rotate_after

    def check_badge(self, token: str | None) -> Badge:
        if not token:
            raise Denied("DENY_BAD_BADGE", "no badge")
        try:
            claims = self.keys.read_badge(token)
        except jwt.PyJWTError as exc:
            raise Denied("DENY_BAD_BADGE", "invalid signature") from exc
        with self.lock:
            badge = self.conn.execute(
                "SELECT * FROM badges WHERE jti = ?", (claims["jti"],)
            ).fetchone()
            agent = self.conn.execute(
                "SELECT role, status FROM agents WHERE agent_id = ?", (claims["sub"],)
            ).fetchone()
        if badge is None or agent is None or badge["agent_id"] != claims["sub"]:
            raise Denied("DENY_BAD_BADGE", "badge was never issued")
        if badge["superseded_by"] is not None:
            raise Denied("DENY_BADGE_SUPERSEDED", "badge was rotated out")
        if badge["revoked_ms"] is not None or agent["status"] != "active":
            raise Denied("DENY_REVOKED", "badge revoked")
        if now_ms() >= badge["expires_ms"]:
            raise Denied("DENY_BADGE_EXPIRED", "badge expired")
        return Badge(claims["sub"], agent["role"], claims["jti"], badge["expires_ms"])

    def verify(self, cred: Credential, op: str, revoke_on_fail: bool | None = None) -> Badge:
        """Badge checks + proof of possession: the caller holds the key the badge is bound
        to, the proof is for this operation, fresh, and never seen before."""
        try:
            badge = self.check_badge(cred.token)
        except Denied as exc:
            if exc.reason == "DENY_BADGE_SUPERSEDED":
                claims = self.keys.read_badge(cred.token)
                self._audit(
                    "STALE_BADGE",
                    f"A rotated-out badge of {claims['sub']} was presented: refused",
                    decision="DENY",
                    reason=exc.reason,
                    actor=claims["sub"],
                    detail={"op": op},
                )
            raise
        revoke = self.config.revoke_on_pop_failure if revoke_on_fail is None else revoke_on_fail
        with self.lock:
            row = self.conn.execute(
                "SELECT public_pem FROM badges WHERE jti = ?", (badge.jti,)
            ).fetchone()
            reason = None
            if not cred.proof:
                reason = "DENY_POP_MISSING"
            else:
                try:
                    claims = crypto.verify_proof(
                        row["public_pem"], cred.proof, cred.token, op, time.time()
                    )
                    now = time.time()
                    for seen, at in list(self._seen_proofs.items()):
                        if now - at > POP_REPLAY_WINDOW_S:
                            del self._seen_proofs[seen]
                    if claims["jti"] in self._seen_proofs:
                        reason = "DENY_POP_REPLAY"
                    else:
                        self._seen_proofs[claims["jti"]] = now
                except ValueError as exc:
                    reason = str(exc)
            if reason is None:
                return badge
            words = {
                "DENY_POP_MISSING": "presented without a proof of possession",
                "DENY_POP_MISMATCH": "presented with a proof from a different key",
                "DENY_POP_REPLAY": "presented with a replayed proof",
                "DENY_POP_STALE": "presented with an expired proof",
            }[reason]
            self._audit(
                "POP_REJECTED",
                f"{badge.agent_id}'s badge {words}: possible theft",
                decision="DENY",
                reason=reason,
                actor=badge.agent_id,
                detail={"op": op},
            )
            if revoke:
                self.revoke(badge.agent_id, "gateway", "badge used without its key (stolen?)")
        raise Denied(reason, words)

    def _master(self, cred: Credential, op: str) -> Badge:
        badge = self.verify(cred, op)
        if badge.role != self.config.master_role:
            self._denied(badge, "DENY_NOT_MASTER", "only the master agent may do this", None)
        return badge

    def _delegator(self, cred: Credential, op: str) -> Badge:
        """Master or an external role with may_delegate. Specialists cannot declare/consult."""
        badge = self.verify(cred, op)
        role = self.config.roles[badge.role]
        if role.master or role.may_delegate:
            return badge
        self._denied(badge, "DENY_NOT_MASTER", "only a delegating role may call specialists", None)
        raise AssertionError  # pragma: no cover — _denied always raises

    def _denied(
        self,
        badge: Badge | None,
        reason: str,
        detail: str,
        run_id: str | None,
        tool: str | None = None,
        count: bool = True,
    ) -> None:
        """Audit a denial, apply its consequences, and raise.

        `count=False` is for a rejected plan: nothing ran, the plan budget per run already
        caps retries, and a model's honest mistake shouldn't burn its badge. Policy
        violations (wrong role, lease misuse, off-plan calls) still count.
        """
        actor = badge.agent_id if badge else None
        with self.lock:
            self._audit(
                "DENIED",
                f"{actor or 'unknown caller'}: {reason.removeprefix('DENY_').replace('_', ' ').lower()}"
                + (f" — {detail}" if detail else ""),
                decision="DENY",
                reason=reason,
                run_id=run_id,
                actor=actor,
                detail={"tool": tool} if tool else {},
            )
            if badge is not None and (count or reason in REVOKE_NOW):
                self.conn.execute(
                    "UPDATE badges SET denied = denied + 1 WHERE jti = ?", (badge.jti,)
                )
                denied_total = self.conn.execute(
                    "SELECT denied FROM badges WHERE jti = ?", (badge.jti,)
                ).fetchone()[0]
                if reason in REVOKE_NOW:
                    self.revoke(badge.agent_id, "gateway", f"{reason} is a revoking offense")
                elif denied_total >= int(self.config.run["max_denied_calls_per_badge"]):
                    self.revoke(
                        badge.agent_id, "gateway", f"{denied_total} denied calls on one badge"
                    )
        raise Denied(reason, detail)

    # ---- revocation ----------------------------------------------------------------------

    def revoke(self, agent_id: str, actor: str, why: str) -> bool:
        """Revoke an agent: its badges die now. A master's run is aborted and its leases die."""
        with self.lock:
            agent = self.conn.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            if agent is None or agent["status"] != "active":
                return False
            t = now_ms()
            self.conn.execute(
                "UPDATE agents SET status = 'revoked', ended_ms = ?, end_reason = ? WHERE agent_id = ?",
                (t, why[:200], agent_id),
            )
            self.conn.execute(
                "UPDATE badges SET revoked_ms = ? WHERE agent_id = ? AND revoked_ms IS NULL",
                (t, agent_id),
            )
            self._audit(
                "REVOKED",
                f"{agent_id} revoked by {actor}: {why}",
                decision="DENY",
                reason="REVOKED",
                actor=actor,
                target=agent_id,
                run_id=agent["run_id"],
            )
            for run in self.conn.execute(
                "SELECT run_id FROM runs WHERE master_id = ? AND status = 'running'",
                (agent_id,),
            ).fetchall():
                self._end_run(run["run_id"], "aborted", error=f"caller revoked: {why}")
            self._mcp_runs.pop(agent_id, None)
            return True

    # ---- runs ------------------------------------------------------------------------------

    def start_run(self, cred: Credential, prompt: str) -> str:
        badge = self._master(cred, "start_run")
        run_id = "RUN-" + uuid.uuid4().hex[:6].upper()
        flagged = any(p.search(prompt) for p in self.config.injection_patterns)
        with self.lock:
            # MCP session runs (prompt starts with [mcp]) don't block the chat master.
            busy = self.conn.execute(
                "SELECT 1 FROM runs WHERE status = 'running' AND prompt NOT LIKE '[mcp]%'"
            ).fetchone()
            if busy:
                raise Denied("DENY_BUSY", "a run is already in progress")
            self.conn.execute(
                "INSERT INTO runs (run_id, master_id, prompt, status, created_ms, last_progress_ms,"
                " flagged) VALUES (?, ?, ?, 'running', ?, ?, ?)",
                (run_id, badge.agent_id, prompt[:2000], now_ms(), now_ms(), int(flagged)),
            )
            self._audit(
                "RUN_STARTED",
                f"{badge.agent_id} took a request",
                run_id=run_id,
                actor=badge.agent_id,
                detail={"prompt_chars": len(prompt)},
            )
            if flagged:
                self._audit(
                    "INJECTION_FLAGGED",
                    "Request matches an injection pattern. Flagged; every plan is still "
                    "checked against policy, so the master can't do more than it's allowed.",
                    decision="DENY",
                    reason="FLAG_INJECTION",
                    run_id=run_id,
                )
        return run_id

    # ---- MCP external sessions --------------------------------------------------------------

    def _require_external(self, badge: Badge) -> None:
        if not self.config.roles[badge.role].external:
            raise Denied("DENY_NOT_EXTERNAL", "MCP is for external roles")

    def ensure_mcp_run_as(self, badge: Badge) -> str:
        """Durable per-identity MCP session run so prerequisites accumulate across calls.

        Caller must already have verified PoP for the MCP front-door op.
        """
        self._require_external(badge)
        with self.lock:
            existing = self._mcp_runs.get(badge.agent_id)
            if existing:
                row = self.conn.execute(
                    "SELECT status FROM runs WHERE run_id = ?", (existing,)
                ).fetchone()
                if row and row["status"] == "running":
                    return existing
            run_id = "MCP-" + uuid.uuid4().hex[:6].upper()
            self.conn.execute(
                "INSERT INTO runs (run_id, master_id, prompt, status, created_ms, last_progress_ms,"
                " flagged) VALUES (?, ?, ?, 'running', ?, ?, 0)",
                (run_id, badge.agent_id, f"[mcp] {badge.agent_id}", now_ms(), now_ms()),
            )
            self._mcp_runs[badge.agent_id] = run_id
            self._audit(
                "RUN_STARTED",
                f"{badge.agent_id} opened an MCP session",
                run_id=run_id,
                actor=badge.agent_id,
                detail={"mcp": True},
            )
            return run_id

    def mcp_list_tools_as(self, badge: Badge) -> list[dict[str, Any]]:
        self._require_external(badge)
        return self._capabilities_for(badge.role)

    def mcp_call_tool_as(self, badge: Badge, tool: str, args: Any) -> dict[str, Any]:
        """One MCP tools/call after front-door PoP: one-step plan + consult."""
        self._require_external(badge)
        if not isinstance(args, dict):
            raise Denied("DENY_SCHEMA", "arguments must be an object")
        owner = self.config.owner_role(tool)
        if owner is None or not self.config.roles[badge.role].allows_tool(tool):
            with self.lock:
                self._denied(
                    badge,
                    "DENY_ROLE_FORBIDDEN",
                    f"{self.config.roles[badge.role].display_name} may not call {str(tool)[:40]!r}",
                    self._mcp_runs.get(badge.agent_id),
                    tool if isinstance(tool, str) else None,
                )
        run_id = self.ensure_mcp_run_as(badge)
        step = {
            "agent": self.config.roles[owner].display_name,
            "tool": tool,
            "args": args,
        }
        plan = self._declare_plan_as(badge, run_id, [step])
        lease_id = plan["leases"][0]["lease_id"]
        return self._consult_as(badge, lease_id)

    def _run(self, run_id: str, master: Badge) -> sqlite3.Row:
        run = self.conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if run is None or run["master_id"] != master.agent_id:
            self._denied(master, "DENY_NOT_OWNER", "not your run", run_id)
        if run["status"] != "running":
            self._denied(master, "DENY_RUN_ENDED", f"run is {run['status']}", run_id)
        return run

    def report_progress(
        self, cred: Credential, run_id: str, what: str, raw: str | None = None
    ) -> None:
        master = self._master(cred, "report_progress")
        with self.lock:
            self._run(run_id, master)
            self.conn.execute(
                "UPDATE runs SET last_progress_ms = ? WHERE run_id = ?", (now_ms(), run_id)
            )
            self._audit(
                "PROGRESS",
                f"{master.agent_id}: {what}",
                run_id=run_id,
                actor=master.agent_id,
                detail={"raw_model_reply": raw} if raw else None,
            )

    def heartbeat(self, cred: Credential, run_id: str) -> dict[str, Any]:
        """A status ping. Not progress: an agent that only pings is stuck."""
        master = self._master(cred, "heartbeat")
        with self.lock:
            run = self._run(run_id, master)
            return {"status": run["status"]}

    def finish_run(self, cred: Credential, run_id: str, answer: str) -> None:
        master = self._master(cred, "finish_run")
        with self.lock:
            self._run(run_id, master)
            self._end_run(run_id, "done", answer=answer[:4000])

    def fail_run(self, run_id: str, error: str) -> None:
        with self.lock:
            run = self.conn.execute(
                "SELECT status FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if run and run["status"] == "running":
                self._end_run(run_id, "failed", error=error[:500])

    def _end_run(
        self, run_id: str, status: str, answer: str | None = None, error: str | None = None
    ) -> None:
        t = now_ms()
        self.conn.execute(
            "UPDATE runs SET status = ?, ended_ms = ?, answer = ?, error = ? WHERE run_id = ?",
            (status, t, answer, error, run_id),
        )
        self.conn.execute(
            "UPDATE leases SET status = ?, reason = ? WHERE run_id = ? AND status = 'active'",
            (
                "unused" if status == "done" else "revoked",
                "not run" if status == "done" else f"run {status}",
                run_id,
            ),
        )
        # Specialists exist for one run. Retire them and kill their badges.
        for agent in self.conn.execute(
            "SELECT agent_id FROM agents WHERE run_id = ? AND status = 'active'", (run_id,)
        ).fetchall():
            self.conn.execute(
                "UPDATE agents SET status = 'retired', ended_ms = ?, end_reason = ? WHERE agent_id = ?",
                (t, f"run {status}", agent["agent_id"]),
            )
            self.conn.execute(
                "UPDATE badges SET revoked_ms = ? WHERE agent_id = ? AND revoked_ms IS NULL",
                (t, agent["agent_id"]),
            )
            self._instances.pop(agent["agent_id"], None)
        label = {"done": "finished", "aborted": "aborted", "failed": "failed"}.get(status, status)
        self._audit(
            "RUN_ENDED",
            f"Run {label}" + (f": {error}" if error else ""),
            decision="DENY" if status != "done" else "EVENT",
            reason=status.upper(),
            run_id=run_id,
        )

    def watchdog_tick(self) -> None:
        """Revoke a master that made no progress for `watchdog_seconds`."""
        limit = self.settings["watchdog_seconds"] * 1000
        with self.lock:
            for run in self.conn.execute(
                "SELECT run_id, master_id, last_progress_ms FROM runs WHERE status = 'running'"
            ).fetchall():
                idle = now_ms() - run["last_progress_ms"]
                if idle > limit:
                    self.revoke(
                        run["master_id"],
                        "watchdog",
                        f"no progress for {idle / 1000:.0f}s (limit {limit / 1000:.0f}s)",
                    )

    # ---- capabilities ----------------------------------------------------------------------

    def capabilities(self, cred: Credential) -> list[dict[str, Any]]:
        """What a delegator may call, straight from policy. Filtered by callable_by + allowlist."""
        caller = self._delegator(cred, "capabilities")
        return self._capabilities_for(caller.role)

    def _capabilities_for(self, caller_role: str) -> list[dict[str, Any]]:
        caller = self.config.roles[caller_role]
        out = []
        for role in self.config.specialists():
            if caller_role not in role.callable_by:
                continue
            for name in role.tools:
                if not caller.allows_tool(name):
                    continue
                tool = self.config.tools[name]
                out.append(
                    {
                        "agent": role.display_name,
                        "tool": name,
                        "description": tool.description,
                        "args": {a: s.describe() for a, s in tool.args.items()},
                        "needs_earlier_steps": sorted(
                            {i.source_tool for i in tool.inputs if i.required}
                        ),
                        "uses_if_present": sorted(
                            {i.source_tool for i in tool.inputs if not i.required}
                        ),
                        "returns": {f: s.describe() for f, s in tool.output.items()},
                    }
                )
        return out

    # ---- plans and leases -------------------------------------------------------------------

    def declare_plan(self, cred: Credential, run_id: str, steps: Any) -> dict[str, Any]:
        return self._declare_plan_as(self._delegator(cred, "declare_plan"), run_id, steps)

    def _declare_plan_as(self, caller: Badge, run_id: str, steps: Any) -> dict[str, Any]:
        with self.lock:
            run = self._run(run_id, caller)
            limit_key = (
                "mcp_max_plans_per_run"
                if run["prompt"].startswith("[mcp]")
                else "max_plans_per_run"
            )
            limit = int(self.config.run.get(limit_key, self.config.run["max_plans_per_run"]))
            if run["plans"] >= limit:
                self._denied(caller, "DENY_REPLAN_LIMIT", "no more plans this run", run_id)
            problem = self._validate_plan(run_id, steps, caller.role)
            plan_id = "PLAN-" + uuid.uuid4().hex[:6].upper()
            seq = run["plans"] + 1
            self.conn.execute("UPDATE runs SET plans = plans + 1 WHERE run_id = ?", (run_id,))
            if problem:
                reason, detail = problem
                self.conn.execute(
                    "INSERT INTO plans VALUES (?, ?, ?, 'denied', ?, ?, ?, ?)",
                    (
                        plan_id,
                        run_id,
                        seq,
                        reason,
                        detail,
                        json.dumps(steps, default=str)[:4000],
                        now_ms(),
                    ),
                )
                # Role overreach revokes via REVOKE_NOW; honest plan mistakes do not count.
                self._denied(caller, reason, f"plan rejected: {detail}", run_id, count=False)
            expires = now_ms() + int(self.config.run["plan_ttl_seconds"]) * 1000
            leases = []
            for index, step in enumerate(steps):
                role = self.config.role_for_display(step["agent"])
                lease_id = "L-" + uuid.uuid4().hex[:8].upper()
                self.conn.execute(
                    "INSERT INTO leases (lease_id, run_id, plan_id, step_index, role, tool, args_json,"
                    " status, expires_ms) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)",
                    (
                        lease_id,
                        run_id,
                        plan_id,
                        index,
                        role,
                        step["tool"],
                        json.dumps(step["args"], sort_keys=True),
                        expires,
                    ),
                )
                leases.append(
                    {
                        "lease_id": lease_id,
                        "agent": self.config.roles[role].display_name,
                        "tool": step["tool"],
                        "args": step["args"],
                    }
                )
            self.conn.execute(
                "INSERT INTO plans VALUES (?, ?, ?, 'approved', 'OK', '', ?, ?)",
                (plan_id, run_id, seq, json.dumps(steps), now_ms()),
            )
            self.conn.execute(
                "UPDATE runs SET last_progress_ms = ? WHERE run_id = ?", (now_ms(), run_id)
            )
            self._audit(
                "PLAN_APPROVED",
                f"Plan approved: {len(steps)} step{'s' * (len(steps) != 1)}, "
                f"{len(steps)} single-use lease{'s' * (len(steps) != 1)}",
                decision="ALLOW",
                run_id=run_id,
                actor=caller.agent_id,
                detail={"plan_id": plan_id, "steps": [f"{s['agent']}.{s['tool']}" for s in steps]},
            )
            return {"plan_id": plan_id, "leases": leases}

    def _validate_plan(self, run_id: str, steps: Any, caller_role: str) -> tuple[str, str] | None:
        cfg = self.config
        caller = cfg.roles[caller_role]
        if not isinstance(steps, list) or not steps:
            return "DENY_PLAN_INVALID", "a plan needs at least one step"
        if len(steps) > int(cfg.run["max_steps_per_plan"]):
            return "DENY_PLAN_INVALID", f"more than {cfg.run['max_steps_per_plan']} steps"
        produced = [
            (r["tool"], json.loads(r["args_json"]))
            for r in self.conn.execute(
                "SELECT tool, args_json FROM leases WHERE run_id = ? AND status = 'used'", (run_id,)
            )
        ]
        seen: dict[str, int] = {}
        for index, step in enumerate(steps, start=1):
            where = f"step {index}"
            if not isinstance(step, dict) or set(step) != {"agent", "tool", "args"}:
                return "DENY_PLAN_INVALID", f"{where} must have exactly agent, tool, args"
            role = cfg.role_for_display(str(step["agent"]))
            if role is None:
                return "DENY_UNKNOWN_AGENT", f"{where}: no agent called {str(step['agent'])[:40]!r}"
            spec = cfg.roles[role]
            if spec.master or spec.external:
                return "DENY_PLAN_INVALID", f"{where}: can't delegate to {spec.display_name}"
            if caller_role not in spec.callable_by:
                return "DENY_NOT_CALLABLE", f"{where}: {spec.display_name} won't take delegations"
            tool = step["tool"]
            if not caller.allows_tool(str(tool)):
                return (
                    "DENY_ROLE_FORBIDDEN",
                    f"{where}: {caller.display_name} may not call {str(tool)[:40]!r}",
                )
            if tool not in spec.tools:
                owner = cfg.tools[tool].owner if tool in cfg.tools else None
                hint = f" (it belongs to {cfg.roles[owner].display_name})" if owner else ""
                return (
                    "DENY_WRONG_AGENT",
                    f"{where}: {spec.display_name} has no tool {str(tool)[:40]!r}{hint}",
                )
            problem = check_record(cfg.tools[tool].args, step["args"], f"{where}.args")
            if problem:
                return "DENY_SCHEMA", problem
            key = crypto.sha256_hex([role, tool, step["args"]])
            seen[key] = seen.get(key, 0) + 1
            if seen[key] > int(cfg.run["max_identical_steps"]):
                return "DENY_LOOP", f"{where} repeats an identical step"
            for item in cfg.tools[tool].inputs:
                if item.required and not self._find_source(
                    item.source_tool, step["args"], produced
                ):
                    needed = sorted({i.source_tool for i in cfg.tools[tool].inputs if i.required})
                    return (
                        "DENY_PRECONDITION",
                        f"{where}: {tool} needs {item.source_tool} with matching args earlier"
                        f" (call first: {', '.join(needed)})",
                    )
            produced.append((tool, step["args"]))
        return None

    @staticmethod
    def _matches(source_args: dict[str, Any], consumer_args: dict[str, Any]) -> bool:
        shared = set(source_args) & set(consumer_args)
        return all(source_args[a] == consumer_args[a] for a in shared)

    def _find_source(
        self, tool: str, args: dict[str, Any], produced: list[tuple[str, dict]]
    ) -> bool:
        return any(t == tool and self._matches(a, args) for t, a in produced)

    def _gather_inputs(self, run_id: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        """The broker: typed values from earlier steps' validated outputs. Never free text."""
        inputs: dict[str, Any] = {}
        for item in self.config.tools[tool].inputs:
            rows = self.conn.execute(
                "SELECT args_json, result_json FROM leases WHERE run_id = ? AND tool = ?"
                " AND status = 'used' ORDER BY rowid DESC",
                (run_id, item.source_tool),
            ).fetchall()
            for row in rows:
                if self._matches(json.loads(row["args_json"]), args):
                    inputs[item.name] = json.loads(row["result_json"])[item.source_field]
                    break
            else:
                if item.required:
                    raise Denied("DENY_PRECONDITION", f"no {item.source_tool} result to use")
        return inputs

    # ---- consult: the two-way handshake ---------------------------------------------------

    def consult(self, cred: Credential, lease_id: str) -> dict[str, Any]:
        return self._consult_as(self._delegator(cred, "consult"), lease_id)

    def _consult_as(self, caller: Badge, lease_id: str) -> dict[str, Any]:
        delay = self.settings["step_delay_ms"] / 1000

        # Phase A: lease checks, typed inputs, specialist instance, delegation.
        with self.lock:
            lease = self.conn.execute(
                "SELECT * FROM leases WHERE lease_id = ?", (lease_id,)
            ).fetchone()
            run_id = lease["run_id"] if lease else None
            if lease is None:
                self._denied(caller, "DENY_NO_LEASE", "unknown lease", None)
            self._run(run_id, caller)
            if lease["status"] != "active":
                self._denied(
                    caller, "DENY_LEASE_USED", f"lease is {lease['status']}", run_id, lease["tool"]
                )
            if now_ms() >= lease["expires_ms"]:
                self.conn.execute(
                    "UPDATE leases SET status = 'expired' WHERE lease_id = ?", (lease_id,)
                )
                self._denied(caller, "DENY_LEASE_EXPIRED", "plan TTL passed", run_id, lease["tool"])
            earlier = self.conn.execute(
                "SELECT COUNT(*) FROM leases WHERE plan_id = ? AND step_index < ? AND status = 'active'",
                (lease["plan_id"], lease["step_index"]),
            ).fetchone()[0]
            if earlier:
                self._denied(
                    caller,
                    "DENY_OFF_PLAN",
                    "an earlier step of the plan hasn't run",
                    run_id,
                    lease["tool"],
                )
            args = json.loads(lease["args_json"])
            try:
                inputs = self._gather_inputs(run_id, lease["tool"], args)
            except Denied as exc:
                self._fail_lease(lease_id, exc.reason)
                self._denied(caller, exc.reason, exc.detail, run_id, lease["tool"])
            instance = self._instance_for(run_id, lease["role"])
            offer, challenge = self._offer(caller, lease, instance, args, inputs)

        self._sleep(delay / 2)  # a human can revoke either side here

        for attempt in (1, 2):
            # Phase B: the handshake, then the atomic tool, then output validation.
            with self.lock:
                self._run(run_id, caller)
                instance, offer, challenge = self._handle_revoked_target(
                    caller, lease, instance, offer, challenge, args, inputs
                )
                output = self._handshake_and_run(caller, lease, instance, offer, challenge)

            self._sleep(delay / 2)

            # Phase C: last re-check, then deliver.
            with self.lock:
                self._run(run_id, caller)
                status = self.conn.execute(
                    "SELECT status FROM agents WHERE agent_id = ?", (instance.agent_id,)
                ).fetchone()["status"]
                if status != "active":
                    self._audit(
                        "RESULT_DISCARDED",
                        f"Result discarded: {instance.agent_id} was revoked mid-call",
                        decision="DENY",
                        reason="DENY_REVOKED",
                        run_id=run_id,
                        actor=instance.agent_id,
                        detail={"lease": lease_id},
                    )
                    if attempt == 1 and self.settings["replace_revoked_specialists"]:
                        instance = self._instance_for(run_id, lease["role"])
                        offer, challenge = self._offer(caller, lease, instance, args, inputs)
                        continue
                    self._fail_lease(lease_id, "DENY_REVOKED")
                    raise Denied("DENY_REVOKED", f"{instance.agent_id} revoked before delivery")
                self.conn.execute(
                    "UPDATE leases SET status = 'used', result_json = ?, target_agent = ?,"
                    " reason = 'OK' WHERE lease_id = ?",
                    (json.dumps(output), instance.agent_id, lease_id),
                )
                self.conn.execute(
                    "UPDATE runs SET last_progress_ms = ? WHERE run_id = ?", (now_ms(), run_id)
                )
                self._audit(
                    "DELIVERED",
                    f"{instance.agent_id} → {caller.agent_id}: typed result for {lease['tool']}",
                    decision="ALLOW",
                    run_id=run_id,
                    actor=instance.agent_id,
                    target=caller.agent_id,
                    detail={"lease": lease_id, "result": output},
                )
                return {"agent": instance.agent_id, "tool": lease["tool"], "result": output}
        raise Denied("DENY_REVOKED", "no live instance to deliver")  # pragma: no cover

    def _handshake_and_run(
        self,
        master: Badge,
        lease: sqlite3.Row,
        instance: SpecialistInstance,
        offer: dict[str, Any],
        challenge: str,
    ) -> dict[str, Any]:
        run_id, lease_id = lease["run_id"], lease["lease_id"]
        try:
            reply = instance.handle_offer(offer, challenge)
        except OfferRefused as exc:
            self._fail_lease(lease_id, exc.reason)
            self._denied(
                master,
                exc.reason,
                f"{instance.agent_id} refused: {exc.detail}",
                run_id,
                lease["tool"],
            )
        try:
            target_badge = self.check_badge(reply["badge"])
        except Denied:
            self._fail_lease(lease_id, "DENY_REVOKED")
            raise
        _, proof_key = self.keys.instance_keys(instance.agent_id, target_badge.jti)
        expected = crypto.hmac_hex(proof_key, f"{challenge}:{lease_id}")
        if target_badge.agent_id != instance.agent_id or not crypto.hmac.compare_digest(
            expected, reply["proof"]
        ):
            self._fail_lease(lease_id, "DENY_HANDSHAKE")
            self._denied(master, "DENY_HANDSHAKE", "proof didn't verify", run_id, lease["tool"])
        bound = self.conn.execute(
            "SELECT public_pem FROM badges WHERE jti = ?", (target_badge.jti,)
        ).fetchone()["public_pem"]
        if not crypto.verify_signature(bound, f"{challenge}:{lease_id}", reply.get("pop", "")):
            self._fail_lease(lease_id, "DENY_POP_MISMATCH")
            self._denied(
                master, "DENY_POP_MISMATCH", "specialist's key signature didn't verify", run_id
            )
        self._audit(
            "HANDSHAKE",
            f"{instance.agent_id} ⇄ gateway: delegation verified, key signature + HMAC proof checked",
            decision="ALLOW",
            run_id=run_id,
            actor=instance.agent_id,
            target=master.agent_id,
            detail={"lease": lease_id, "proof": "HMAC-SHA256 over challenge"},
        )
        sealed_result = instance.run_tool(self.conn, reply["request"], lease_id)
        seal_key, _ = self.keys.instance_keys(instance.agent_id, target_badge.jti)
        output = crypto.open_sealed(seal_key, sealed_result, f"result:{lease_id}")
        problem = check_record(self.config.tools[lease["tool"]].output, output, lease["tool"])
        if problem:
            self._fail_lease(lease_id, "DENY_OUTPUT_SCHEMA")
            self._audit(
                "OUTPUT_REJECTED",
                f"{instance.agent_id}'s output rejected and quarantined: {problem}",
                decision="DENY",
                reason="DENY_OUTPUT_SCHEMA",
                run_id=run_id,
                actor=instance.agent_id,
                detail={"lease": lease_id},
            )
            raise Denied("DENY_OUTPUT_SCHEMA", f"{lease['tool']} returned an invalid value")
        return output

    def _fail_lease(self, lease_id: str, reason: str) -> None:
        self.conn.execute(
            "UPDATE leases SET status = 'failed', reason = ? WHERE lease_id = ?", (reason, lease_id)
        )

    def _instance_for(self, run_id: str, role: str) -> SpecialistInstance:
        """This run's active instance of `role`, spun up and authenticated on first use."""
        row = self.conn.execute(
            "SELECT agent_id FROM agents WHERE run_id = ? AND role = ? AND status = 'active'"
            " ORDER BY created_ms DESC LIMIT 1",
            (run_id, role),
        ).fetchone()
        if row and row["agent_id"] in self._instances:
            instance = self._instances[row["agent_id"]]
            if instance.session and self.rotate_due(instance.session.badge):
                try:
                    instance.rotate(self)
                except Denied as exc:
                    if exc.reason != "DENY_BADGE_EXPIRED":
                        raise
                    # Idle past expiry: a full re-login (secret + attestation + new key).
                    instance.key = crypto.AgentKey()
                    instance.login(self)
            return instance
        agent_id, secret = self.provision(role, run_id)
        instance = SpecialistInstance(
            agent_id,
            role,
            secret,
            self.config,
            self.keys.delegation_public_pem,
            self.config.master_role,
        )
        instance.login(self)
        self._instances[agent_id] = instance
        return instance

    def _offer(
        self,
        master: Badge,
        lease: sqlite3.Row,
        instance: SpecialistInstance,
        args: dict[str, Any],
        inputs: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        assert instance.session is not None
        exp = now_ms() // 1000 + self.config.delegation_ttl_seconds
        delegation = self.keys.sign_delegation(
            {
                "sub": master.agent_id,
                "sub_role": master.role,
                "obo_badge": master.jti,
                "aud": instance.agent_id,
                "jti": uuid.uuid4().hex,
                "lease": lease["lease_id"],
                "tool": lease["tool"],
                "args_sha256": crypto.sha256_hex(args),
                "exp": exp,
            }
        )
        sealed = crypto.seal(
            instance.session.seal_key,
            {"tool": lease["tool"], "args": args, "inputs": inputs},
            lease["lease_id"],
        )
        self.conn.execute(
            "UPDATE leases SET target_agent = ?, attempts = attempts + 1 WHERE lease_id = ?",
            (instance.agent_id, lease["lease_id"]),
        )
        self._audit(
            "DELEGATED",
            f"{master.agent_id} → {instance.agent_id}: {lease['tool']} "
            f"(Ed25519 delegation, AES-GCM sealed{', ' + str(len(inputs)) + ' typed inputs piped' if inputs else ''})",
            decision="ALLOW",
            run_id=lease["run_id"],
            actor=master.agent_id,
            target=instance.agent_id,
            detail={"lease": lease["lease_id"], "args": args, "inputs": inputs},
        )
        return {"delegation": delegation, "sealed": sealed}, uuid.uuid4().hex

    def _handle_revoked_target(self, master, lease, instance, offer, challenge, args, inputs):  # noqa: ANN001, ANN202
        status = self.conn.execute(
            "SELECT status FROM agents WHERE agent_id = ?", (instance.agent_id,)
        ).fetchone()["status"]
        if status == "active":
            return instance, offer, challenge
        self._audit(
            "HANDSHAKE_REFUSED",
            f"{instance.agent_id} is revoked: the gateway won't complete its handshake",
            decision="DENY",
            reason="DENY_REVOKED",
            run_id=lease["run_id"],
            actor=instance.agent_id,
            detail={"lease": lease["lease_id"]},
        )
        attempts = self.conn.execute(
            "SELECT attempts FROM leases WHERE lease_id = ?", (lease["lease_id"],)
        ).fetchone()[0]
        if not self.settings["replace_revoked_specialists"] or attempts > 2:
            self._fail_lease(lease["lease_id"], "DENY_REVOKED")
            raise Denied("DENY_REVOKED", f"{instance.agent_id} was revoked")
        replacement = self._instance_for(lease["run_id"], lease["role"])
        offer, challenge = self._offer(master, lease, replacement, args, inputs)
        return replacement, offer, challenge

    # ---- demo attacks -------------------------------------------------------------------

    def _spawn(self, role: str, functions: dict[str, Any] | None = None) -> SpecialistInstance:
        with self.lock:
            agent_id, secret = self.provision(role)
        return SpecialistInstance(
            agent_id,
            role,
            secret,
            self.config,
            self.keys.delegation_public_pem,
            self.config.master_role,
            functions=functions,
        )

    def rogue_test(self) -> list[dict[str, str]]:
        """A specialist tries to call another specialist two ways. Both fail.

        1. Through the gateway: it isn't a master, so it can't declare a plan (and is revoked).
        2. Around the gateway: it hands a target a delegation it signed itself.
        """
        results = []
        specialists = self.config.specialists()
        rogue_role, target_role = specialists[0].name, specialists[-1].name
        rogue = self._spawn(rogue_role)
        rogue.login(self)
        target_tool = self.config.roles[target_role].tools[0]
        token = rogue.session.badge
        try:
            self.declare_plan(
                Credential(token, rogue.key.proof(token, "declare_plan")),
                "RUN-NONE",
                [
                    {
                        "agent": self.config.roles[target_role].display_name,
                        "tool": target_tool,
                        "args": {},
                    }
                ],
            )
        except Denied as exc:
            results.append(
                {"attempt": f"{rogue.agent_id} asks the gateway to delegate", "result": exc.reason}
            )
        target = self._spawn(target_role)
        target.login(self)
        forged = jwt.encode(
            {
                "iss": crypto.ISSUER,
                "sub": rogue.agent_id,
                "sub_role": self.config.master_role,
                "aud": target.agent_id,
                "jti": "x",
                "lease": "L-FORGED",
                "tool": target_tool,
                "args_sha256": "0",
                "exp": now_ms() // 1000 + 60,
            },
            "a-key-the-rogue-made-up-itself-0123456789",
            algorithm="HS256",
        )
        attempt = f"{rogue.agent_id} sends {target.agent_id} a forged delegation"
        try:
            target.handle_offer({"delegation": forged, "sealed": {"nonce": "00", "box": "00"}}, "c")
            results.append({"attempt": attempt, "result": "ACCEPTED?!"})
        except OfferRefused as exc:
            self._audit(
                "FORGERY_REFUSED",
                f"{target.agent_id} refused a delegation not signed by the gateway ({exc.reason})",
                decision="DENY",
                reason=exc.reason,
                actor=rogue.agent_id,
                target=target.agent_id,
            )
            results.append({"attempt": attempt, "result": exc.reason})
        with self.lock:
            self.revoke(target.agent_id, "gateway", "rogue-test target retired")
            self.revoke(rogue.agent_id, "gateway", "attempted unauthorized delegation")
        return results

    def steal_badge_test(self, stolen_token: str, captured: Credential) -> list[dict[str, str]]:
        """An attacker has exfiltrated the master's badge and sniffed one signed request.

        `captured` was already sent once by the real master. The attacker tries:
        1. replaying that exact signed request,
        2. signing its own proof with a key it generated,
        3. presenting the bare badge, bearer-style.
        All three fail, then the badge is revoked as compromised.
        """
        attacker = crypto.AgentKey()
        attempts = [
            ("replays a captured signed request", captured),
            (
                "signs with its own key",
                Credential(stolen_token, attacker.proof(stolen_token, "capabilities")),
            ),
            ("presents the bare badge", Credential(stolen_token, None)),
        ]
        results = []
        for label, cred in attempts:
            try:
                self.verify(cred, "capabilities", revoke_on_fail=False)
                results.append({"attempt": f"Attacker {label}", "result": "ACCEPTED?!"})
            except Denied as exc:
                results.append({"attempt": f"Attacker {label}", "result": exc.reason})
        try:
            victim = self.check_badge(stolen_token).agent_id
        except Denied:
            return results
        if self.config.revoke_on_pop_failure:
            self.revoke(victim, "gateway", "badge stolen: used without its key")
        return results

    def tampered_agent_test(self) -> list[dict[str, str]]:
        """Spawn a MedHistory-type agent whose code was modified to hide allergies. Its
        measurement doesn't match the attested build, so it never gets a badge."""
        role = next(
            (r.name for r in self.config.specialists() if "get_allergies" in r.tools),
            self.config.specialists()[0].name,
        )
        functions = {t: TOOLS[t] for t in self.config.roles[role].tools}
        if "get_allergies" in functions:
            functions["get_allergies"] = _tampered_get_allergies
        instance = self._spawn(role, functions=functions)
        try:
            instance.login(self)
            return [
                {
                    "attempt": f"{instance.agent_id} (modified code) asks for a badge",
                    "result": "ACCEPTED?!",
                }
            ]
        except Denied as exc:
            return [
                {
                    "attempt": f"{instance.agent_id} (modified code) asks for a badge",
                    "result": exc.reason,
                }
            ]

    # ---- snapshot for the UI ------------------------------------------------------------------

    def snapshot(self, after_seq: int = 0) -> dict[str, Any]:
        with self.lock:
            t = now_ms()
            agents = []
            for a in self.conn.execute("SELECT * FROM agents ORDER BY created_ms DESC LIMIT 40"):
                badge = self.conn.execute(
                    "SELECT jti, issued_ms, expires_ms, jkt, generation FROM badges WHERE agent_id = ? ORDER BY issued_ms DESC LIMIT 1",
                    (a["agent_id"],),
                ).fetchone()
                role = self.config.roles[a["role"]]
                agents.append(
                    {
                        "agent_id": a["agent_id"],
                        "role": a["role"],
                        "role_name": role.display_name,
                        "master": role.master,
                        "external": role.external,
                        "description": role.description,
                        "status": a["status"],
                        "run_id": a["run_id"],
                        "end_reason": a["end_reason"],
                        "badge": badge["jti"][:8] if badge else None,
                        "key": badge["jkt"][:8] if badge else None,
                        "generation": badge["generation"] if badge else 0,
                        "rotate_in": max(
                            0,
                            (badge["issued_ms"] + self.config.rotate_after_seconds * 1000 - t)
                            // 1000,
                        )
                        if badge
                        else 0,
                        "attested": a["measurement"] is not None
                        and a["measurement"] == self.expected_measurements.get(a["role"]),
                        "attestation_failed": a["measurement"] is None
                        and a["end_reason"] is not None
                        and "attestation" in a["end_reason"],
                        "expires_in": max(0, (badge["expires_ms"] - t) // 1000) if badge else 0,
                        "tools": list(role.tools)
                        if not role.external
                        else list(
                            role.tools_allowed
                            if role.tools_allowed and role.tools_allowed != ("*",)
                            else sorted(self.config.tools)
                        ),
                    }
                )
            runs = []
            for r in self.conn.execute("SELECT * FROM runs ORDER BY created_ms DESC LIMIT 10"):
                steps = [
                    {
                        "lease_id": row["lease_id"],
                        "plan_id": row["plan_id"],
                        "index": row["step_index"],
                        "agent": self.config.roles[row["role"]].display_name,
                        "instance": row["target_agent"],
                        "tool": row["tool"],
                        "args": json.loads(row["args_json"]),
                        "status": row["status"],
                        "reason": row["reason"],
                        "result": json.loads(row["result_json"]) if row["result_json"] else None,
                    }
                    for row in self.conn.execute(
                        "SELECT * FROM leases WHERE run_id = ? ORDER BY rowid", (r["run_id"],)
                    )
                ]
                plans = [
                    dict(p)
                    for p in self.conn.execute(
                        "SELECT plan_id, seq, status, reason, detail FROM plans WHERE run_id = ? ORDER BY seq",
                        (r["run_id"],),
                    )
                ]
                runs.append(
                    {
                        "run_id": r["run_id"],
                        "master": r["master_id"],
                        "prompt": r["prompt"],
                        "status": r["status"],
                        "answer": r["answer"],
                        "error": r["error"],
                        "flagged": bool(r["flagged"]),
                        "steps": steps,
                        "plans": plans,
                        "idle_seconds": (t - r["last_progress_ms"]) / 1000
                        if r["status"] == "running"
                        else 0,
                    }
                )
            audit = [
                {
                    k: e[k]
                    for k in (
                        "seq",
                        "ts_ms",
                        "run_id",
                        "actor",
                        "target",
                        "kind",
                        "decision",
                        "reason",
                        "summary",
                    )
                }
                | {"detail": json.loads(e["detail_json"])}
                for e in self.conn.execute(
                    "SELECT * FROM audit WHERE seq > ? ORDER BY seq", (after_seq,)
                )
            ]
            totals = {
                d: n
                for d, n in self.conn.execute(
                    "SELECT decision, COUNT(*) FROM audit GROUP BY decision"
                )
            }
        chain_ok, chain_rows = self.verify_chain()
        return {
            "agents": agents,
            "runs": runs,
            "audit": audit,
            "totals": totals,
            "settings": self.settings,
            "chain": {"ok": chain_ok, "rows": chain_rows},
            "system_id": self.config.system_id,
            "epoch": self.epoch,
            "roles": [
                {
                    "role": r.name,
                    "name": r.display_name,
                    "description": r.description,
                    "master": r.master,
                    "external": r.external,
                    "tools": list(r.tools)
                    if not r.external
                    else list(
                        r.tools_allowed
                        if r.tools_allowed and r.tools_allowed != ("*",)
                        else sorted(self.config.tools)
                    ),
                }
                for r in self.config.roles.values()
            ],
            "external_roles": [
                {"role": r.name, "name": r.display_name, "description": r.description}
                for r in self.config.external_roles()
            ],
        }


def clean_reason(reason: str) -> str:
    return re.sub(r"^DENY_", "", reason).replace("_", " ").lower()


def _tampered_get_allergies(conn, config, args, inputs):  # noqa: ANN001, ANN201
    """A modified get_allergies that hides every allergy. Used only by the demo attack."""
    return {"allergies": []}
