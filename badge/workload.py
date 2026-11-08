"""Workload identity: agents authenticate themselves to get a badge.

OAuth2 client_credentials, demo-grade. The orchestrator provisions an agent once and gets a
client secret back (shown once, stored only as an HMAC). From then on the agent's own
process proves who it is at POST /auth/agent/token and receives a short-lived badge.

A revoked or suspended agent can't trade its credentials for a new badge, so revocation
sticks: re-authenticating is not a way around it.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3

from badge import identity, reasons
from badge.audit import AuditEntry, append
from badge.clock import to_ms
from badge.context import Runtime
from badge.decisions import Deny

MAX_CLIENT_ID_LEN = 64
MAX_SECRET_LEN = 128


def _secret_hmac(runtime: Runtime, client_secret: str) -> str:
    return hmac.new(
        runtime.signing_key.encode(), client_secret.encode(), hashlib.sha256
    ).hexdigest()


def provision_credentials(conn: sqlite3.Connection, runtime: Runtime, agent_id: str) -> str:
    """Create (or rotate) the agent's client secret. Runs inside the caller's write
    transaction. Returns the plaintext secret; it is never stored."""
    client_secret = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO agent_credentials (agent_id, secret_hmac, created_at_ms) VALUES (?, ?, ?)"
        " ON CONFLICT(agent_id) DO UPDATE SET secret_hmac = excluded.secret_hmac,"
        " created_at_ms = excluded.created_at_ms",
        (agent_id, _secret_hmac(runtime, client_secret), to_ms(runtime.clock.now())),
    )
    return client_secret


def _audit_failure(
    conn: sqlite3.Connection, runtime: Runtime, agent_id: str | None, role: str | None, why: str
) -> None:
    append(
        conn,
        runtime.config,
        runtime.clock.now(),
        AuditEntry(
            agent_id=agent_id,
            badge_id=None,
            role=role,
            tool=None,
            args={},
            decision="EVENT",
            reason=reasons.EVENT_AUTH_FAILED,
            severity="high",
            detail=why,
        ),
    )


def exchange_credentials(
    conn: sqlite3.Connection, runtime: Runtime, client_id: str, client_secret: str
) -> str | Deny:
    """Verify client credentials and mint a badge. Runs inside the caller's write
    transaction. Every failure is audited; the caller learns only a generic reason."""
    client_id = client_id[:MAX_CLIENT_ID_LEN]
    client_secret = client_secret[:MAX_SECRET_LEN]
    row = conn.execute(
        "SELECT a.role, a.status, c.secret_hmac FROM agents a"
        " JOIN agent_credentials c ON c.agent_id = a.agent_id WHERE a.agent_id = ?",
        (client_id,),
    ).fetchone()
    # Compare against a dummy when the client is unknown, so timing doesn't reveal which
    # agent ids exist.
    expected = row["secret_hmac"] if row else _secret_hmac(runtime, "unknown-client")
    secret_ok = hmac.compare_digest(expected, _secret_hmac(runtime, client_secret))
    if row is None or not secret_ok:
        known = row is not None
        _audit_failure(
            conn,
            runtime,
            client_id if known else None,
            row["role"] if known else None,
            "bad client secret" if known else "unknown client",
        )
        return Deny(reasons.DENY_BAD_CREDENTIALS, detail="invalid client credentials")
    if row["status"] != "active":
        _audit_failure(conn, runtime, client_id, row["role"], f"agent is {row['status']}")
        reason = reasons.DENY_REVOKED if row["status"] == "revoked" else reasons.DENY_SUSPENDED
        return Deny(reason, detail=f"agent is {row['status']}")
    return identity.issue_badge(conn, runtime, client_id)
