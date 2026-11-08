"""Agent registry and badges (signed JWTs).

Only the orchestrator issues badges. Agents can't mint, refresh, or modify them; any
change to a token breaks its HS256 signature.
"""

from __future__ import annotations

import sqlite3

import jwt

from badge import reasons
from badge.audit import AuditEntry, append
from badge.clock import to_ms
from badge.context import BadgeInfo, CallContext, Runtime
from badge.decisions import Allow, Decision, Deny
from badge.ids import new_uuid

ALGORITHM = "HS256"
REQUIRED_CLAIMS = ("sub", "role", "trial_id", "jti", "iat", "exp")
MAX_TOKEN_LEN = 4096


def register_agent(conn: sqlite3.Connection, runtime: Runtime, agent_id: str, role: str) -> None:
    """Create an active agent. Runs inside the caller's write transaction."""
    if role not in runtime.config.roles:
        raise ValueError(f"unknown role {role!r}")
    conn.execute(
        "INSERT INTO agents (agent_id, role, status, created_at_ms) VALUES (?, ?, 'active', ?)",
        (agent_id, role, to_ms(runtime.clock.now())),
    )


def issue_badge(conn: sqlite3.Connection, runtime: Runtime, agent_id: str) -> str:
    """Mint a badge for an existing, active agent. Runs inside the caller's write transaction.

    Returns the encoded JWT. The badge row lets the dashboard and audit trail answer
    "which badge did this?" from data alone.
    """
    agent = conn.execute(
        "SELECT role, status FROM agents WHERE agent_id = ?", (agent_id,)
    ).fetchone()
    if agent is None or agent["status"] != "active":
        raise ValueError(f"agent {agent_id!r} is missing or not active")
    now = runtime.clock.now()
    ttl_seconds = runtime.config.badge_ttl_for(agent["role"]) * 60
    badge_id = new_uuid()
    claims = {
        "sub": agent_id,
        "role": agent["role"],
        "trial_id": runtime.config.trial_id,
        "jti": badge_id,
        "iat": int(now),
        "exp": int(now + ttl_seconds),
    }
    conn.execute(
        "INSERT INTO badges (badge_id, agent_id, role, issued_at_ms, expires_at_ms)"
        " VALUES (?, ?, ?, ?, ?)",
        (badge_id, agent_id, agent["role"], to_ms(now), claims["exp"] * 1000),
    )
    append(
        conn,
        runtime.config,
        now,
        AuditEntry(
            agent_id=agent_id,
            badge_id=badge_id,
            role=agent["role"],
            tool=None,
            args={},
            decision="EVENT",
            reason=reasons.EVENT_BADGE_ISSUED,
        ),
    )
    return jwt.encode(claims, runtime.signing_key, algorithm=ALGORITHM)


def decode_badge(runtime: Runtime, token: str | None, now: float) -> BadgeInfo | Deny:
    """Verify signature, required claims, trial, and expiry (against the injected clock).

    Does not touch the database; `check_badge` adds the revocation and agent checks.
    """
    if not token or len(token) > MAX_TOKEN_LEN:
        return Deny(reasons.DENY_BAD_BADGE, detail="missing or oversized badge")
    try:
        claims = jwt.decode(
            token,
            runtime.signing_key,
            algorithms=[ALGORITHM],
            # Expiry is checked below against the injectable clock, not wall time.
            options={"verify_exp": False, "verify_iat": False, "require": list(REQUIRED_CLAIMS)},
        )
    except jwt.PyJWTError:
        return Deny(reasons.DENY_BAD_BADGE, detail="invalid badge signature or claims")
    if claims["trial_id"] != runtime.config.trial_id:
        return Deny(reasons.DENY_BAD_BADGE, detail="badge is for another trial")
    if not isinstance(claims["exp"], int) or now >= claims["exp"]:
        return Deny(reasons.DENY_BADGE_EXPIRED, detail="badge expired")
    if not all(isinstance(claims[name], str) for name in ("sub", "role", "jti")):
        return Deny(reasons.DENY_BAD_BADGE, detail="malformed claims")
    return BadgeInfo(
        agent_id=claims["sub"],
        badge_id=claims["jti"],
        role=claims["role"],
        expires_at=float(claims["exp"]),
    )


def is_badge_revoked(conn: sqlite3.Connection, badge_id: str) -> bool:
    row = conn.execute("SELECT 1 FROM revocations WHERE badge_id = ?", (badge_id,)).fetchone()
    return row is not None


def check_badge(ctx: CallContext) -> Decision:
    """Pipeline step 1: signature, expiry, revocation list, agent exists and is active."""
    decoded = decode_badge(ctx.runtime, ctx.request.token, ctx.now)
    if isinstance(decoded, Deny):
        return decoded
    badge_row = ctx.conn.execute(
        "SELECT agent_id, role FROM badges WHERE badge_id = ?", (decoded.badge_id,)
    ).fetchone()
    if badge_row is None or badge_row["agent_id"] != decoded.agent_id:
        return Deny(reasons.DENY_BAD_BADGE, detail="badge was never issued")
    if badge_row["role"] != decoded.role:
        return Deny(reasons.DENY_BAD_BADGE, detail="badge role mismatch")
    if is_badge_revoked(ctx.conn, decoded.badge_id):
        return Deny(reasons.DENY_REVOKED, detail="badge revoked")
    agent = ctx.conn.execute(
        "SELECT role, status FROM agents WHERE agent_id = ?", (decoded.agent_id,)
    ).fetchone()
    if agent is None or agent["role"] != decoded.role:
        return Deny(reasons.DENY_BAD_BADGE, detail="unknown agent")
    if agent["status"] == "revoked":
        return Deny(reasons.DENY_REVOKED, detail="agent revoked")
    if agent["status"] == "suspended":
        return Deny(reasons.DENY_SUSPENDED, detail="agent suspended pending review")
    return Allow({"badge": decoded})


def peek_identity(runtime: Runtime, token: str | None) -> tuple[str, str, str] | None:
    """(agent_id, badge_id, role) from a correctly signed token, ignoring expiry.

    Used only to attribute audit entries for denied calls. Never used to allow anything.
    """
    if not token or len(token) > MAX_TOKEN_LEN:
        return None
    try:
        claims = jwt.decode(
            token,
            runtime.signing_key,
            algorithms=[ALGORITHM],
            options={"verify_exp": False, "verify_iat": False, "require": list(REQUIRED_CLAIMS)},
        )
    except jwt.PyJWTError:
        return None
    if not all(isinstance(claims[name], str) for name in ("sub", "jti", "role")):
        return None
    return claims["sub"], claims["jti"], claims["role"]
